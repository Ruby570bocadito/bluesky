"""
Tests de exportación CSV de dispositivos — bluesky.utils.csv_export
y el flag `bluesky scan --export`.
"""
import csv
import io
import json
import os
import sys
from unittest.mock import patch


sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from bluesky.utils.csv_export import (
    CSV_COLUMNS, devices_to_csv, devices_from_scan_result,
)

FAKE_DEVICES = [
    {
        "mac": "B8:27:EB:12:34:56",
        "name": "raspberrypi",
        "type": "classic",
        "vendor": "Raspberry Pi Trading",
        "rssi": -52,
        "info": {"rssi": -52, "paired": False, "services": []},
    },
    {
        "mac": "00:1A:7D:99:88:77",
        "name": "CSR dongle",
        "type": "ble",
        "vendor": "Cambridge Silicon Radio (CSR)",
        "rssi": 0,
        "info": {"rssi": -40, "paired": True},
    },
]


def _parse_csv(text: str):
    rows = list(csv.reader(io.StringIO(text)))
    return rows[0], rows[1:]


class TestDevicesToCsv:
    """Generación de CSV a partir de dispositivos de un scan."""

    def test_cabecera(self):
        header, _ = _parse_csv(devices_to_csv([]))
        assert header == CSV_COLUMNS

    def test_lista_vacia_solo_cabecera(self):
        assert devices_to_csv([]) == ",".join(CSV_COLUMNS) + "\n"

    def test_fila_completa(self):
        _, rows = _parse_csv(devices_to_csv([FAKE_DEVICES[0]]))
        assert rows[0] == [
            "B8:27:EB:12:34:56", "raspberrypi", "classic",
            "Raspberry Pi Trading", "-52", "no",
        ]

    def test_rssi_y_paired_desde_info(self):
        # Sin rssi/paired en el nivel superior: se toman de info
        dev = {"mac": "AA:BB:CC:DD:EE:FF", "name": "X", "type": "ble",
               "info": {"rssi": -60, "paired": True}}
        _, rows = _parse_csv(devices_to_csv([dev]))
        assert rows[0][4] == "-60"
        assert rows[0][5] == "yes"

    def test_campos_ausentes_como_vacios(self):
        dev = {"mac": "AA:BB:CC:DD:EE:FF"}
        _, rows = _parse_csv(devices_to_csv([dev]))
        assert rows[0] == ["AA:BB:CC:DD:EE:FF", "", "", "", "", ""]

    def test_none_como_vacio(self):
        dev = {"mac": "AA:BB:CC:DD:EE:FF", "name": None, "rssi": None}
        _, rows = _parse_csv(devices_to_csv([dev]))
        assert rows[0][1] == ""
        assert rows[0][4] == ""

    def test_nombre_con_coma_quedado(self):
        dev = {"mac": "AA:BB:CC:DD:EE:FF", "name": 'Auriculares, "Pro" 2'}
        text = devices_to_csv([dev])
        _, rows = _parse_csv(text)
        assert rows[0][1] == 'Auriculares, "Pro" 2'

    def test_nombre_unicode(self):
        dev = {"mac": "AA:BB:CC:DD:EE:FF", "name": "Auriculares ñ-í"}
        _, rows = _parse_csv(devices_to_csv([dev]))
        assert rows[0][1] == "Auriculares ñ-í"

    def test_entrada_no_dict_tolerada(self):
        text = devices_to_csv(["solo-un-string", FAKE_DEVICES[0]])
        header, rows = _parse_csv(text)
        assert rows[0][0] == "solo-un-string"
        assert len(rows) == 2

    def test_none_como_lista(self):
        header, rows = _parse_csv(devices_to_csv(None))
        assert header == CSV_COLUMNS
        assert rows == []

    def test_multiples_filas_orden_preservado(self):
        _, rows = _parse_csv(devices_to_csv(FAKE_DEVICES))
        assert len(rows) == 2
        assert rows[0][0] == FAKE_DEVICES[0]["mac"]
        assert rows[1][0] == FAKE_DEVICES[1]["mac"]


class TestDevicesFromScanResult:
    """Extracción de dispositivos desde el resultado de un módulo."""

    def test_resultado_normal(self):
        result = {"success": True, "data": {"devices": FAKE_DEVICES}, "error": None}
        assert devices_from_scan_result(result) == FAKE_DEVICES

    def test_resultado_fallido(self):
        result = {"success": False, "data": {}, "error": "boom"}
        assert devices_from_scan_result(result) == []

    def test_sin_data(self):
        assert devices_from_scan_result({"success": True}) == []

    def test_entrada_basura(self):
        assert devices_from_scan_result(None) == []
        assert devices_from_scan_result("no-dict") == []
        assert devices_from_scan_result({"data": "no-dict"}) == []
        assert devices_from_scan_result({"data": {"devices": "no-lista"}}) == []


class _FakeScanner:
    """Sustituto de DeviceScanner con resultados deterministas."""

    def __init__(self, options=None):
        self.options = options or {}

    def run(self):
        return {"success": True, "data": {"devices": FAKE_DEVICES}, "error": None}


class TestCliExport:
    """`bluesky scan --export` escribe CSV/JSON con los dispositivos."""

    def test_export_csv(self, tmp_path, capsys):
        from bluesky.cli import cmd_scan
        out = tmp_path / "devices.csv"
        with patch("bluesky.modules.scanners.device_scanner.DeviceScanner",
                   _FakeScanner):
            rc = cmd_scan(["--export", str(out)])
        assert rc == 0
        text = out.read_text(encoding="utf-8")
        # BOM utf-8-sig para Excel + cabecera + 2 filas
        assert text.startswith("\ufeff")
        _, rows = _parse_csv(text)
        assert len(rows) == 2
        assert rows[0][0] == "B8:27:EB:12:34:56"
        assert rows[0][3] == "Raspberry Pi Trading"
        assert "exportados" in capsys.readouterr().out

    def test_export_json(self, tmp_path):
        from bluesky.cli import cmd_scan
        out = tmp_path / "devices.json"
        with patch("bluesky.modules.scanners.device_scanner.DeviceScanner",
                   _FakeScanner):
            rc = cmd_scan(["--export", str(out)])
        assert rc == 0
        data = json.loads(out.read_text(encoding="utf-8"))
        assert data["count"] == 2
        assert data["devices"][0]["mac"] == "B8:27:EB:12:34:56"

    def test_export_json_mode_sigue_funcionando(self, tmp_path, capsys):
        from bluesky.cli import cmd_scan
        out = tmp_path / "devices.csv"
        with patch("bluesky.modules.scanners.device_scanner.DeviceScanner",
                   _FakeScanner):
            rc = cmd_scan(["--json", "--export", str(out)])
        assert rc == 0
        # La salida stdout sigue siendo JSON limpio (sin el mensaje de export)
        stdout = capsys.readouterr().out
        assert json.loads(stdout)["count"] == 2
        assert out.exists()

    def test_export_ruta_inaccesible(self, tmp_path, capsys):
        from bluesky.cli import cmd_scan
        bad = tmp_path / "no_existe_dir" / "x.csv"
        with patch("bluesky.modules.scanners.device_scanner.DeviceScanner",
                   _FakeScanner):
            rc = cmd_scan(["--export", str(bad)])
        # Error de escritura -> exit code 1 y mensaje de ERROR
        assert rc == 1
        assert "ERROR" in capsys.readouterr().out
