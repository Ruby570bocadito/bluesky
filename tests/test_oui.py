"""
Tests del lookup OUI (fabricante por MAC) — bluesky.utils.oui.
"""
import os
import sys


sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from bluesky.utils.oui import (
    OUI_DATABASE, normalize_mac, lookup_vendor, annotate_devices,
)


class TestNormalizeMac:
    """Normalización de MACs en distintos formatos."""

    def test_formato_dos_puntos(self):
        assert normalize_mac("B8:27:EB:12:34:56") == "B827EB123456"

    def test_formato_guiones(self):
        assert normalize_mac("b8-27-eb-12-34-56") == "B827EB123456"

    def test_formato_mezclado(self):
        assert normalize_mac("b8:27-eB.12 34:56") == "B827EB123456"

    def test_sin_separadores(self):
        assert normalize_mac("b827eb123456") == "B827EB123456"

    def test_minusculas_a_mayusculas(self):
        assert normalize_mac("aa:bb:cc:dd:ee:ff") == "AABBCCDDEEFF"

    def test_mac_invalida_letras_no_hex(self):
        assert normalize_mac("ZZ:27:EB:12:34:56") is None

    def test_mac_corta(self):
        assert normalize_mac("B8:27:EB:12:34") is None

    def test_mac_larga(self):
        assert normalize_mac("B8:27:EB:12:34:56:78") is None

    def test_mac_vacia_y_none(self):
        assert normalize_mac("") is None
        assert normalize_mac(None) is None

    def test_mac_no_string(self):
        assert normalize_mac(12345) is None
        assert normalize_mac(["B8", "27"]) is None


class TestLookupVendor:
    """Búsqueda de fabricante por prefijo OUI."""

    def test_raspberry_pi(self):
        assert lookup_vendor("B8:27:EB:12:34:56") == "Raspberry Pi Trading"

    def test_apple(self):
        assert lookup_vendor("00:1B:63:AA:BB:CC") == "Apple"

    def test_csr_dongle(self):
        # El clásico dongle CSR8510 usado en auditoría Bluetooth
        assert lookup_vendor("00:1A:7D:AA:BB:CC") == "Cambridge Silicon Radio (CSR)"

    def test_case_insensitive(self):
        assert lookup_vendor("f0:18:98:11:22:33") == "Apple"

    def test_desconocido_devuelve_default(self):
        assert lookup_vendor("99:99:99:11:22:33") == ""
        assert lookup_vendor("99:99:99:11:22:33", default="Unknown") == "Unknown"

    def test_mac_invalida_devuelve_default(self):
        assert lookup_vendor("no-es-una-mac") == ""
        assert lookup_vendor("", default="Unknown") == "Unknown"
        assert lookup_vendor(None) == ""

    def test_todos_los_prefijos_tienen_formato_valido(self):
        # La DB compartida debe mantener prefijos 'AA:BB:CC' normalizados
        for prefix in OUI_DATABASE:
            assert len(prefix) == 8
            assert prefix[2] == ":" and prefix[5] == ":"
            assert prefix == prefix.upper()
            assert OUI_DATABASE[prefix]  # valor no vacío

    def test_db_comparte_familia_termux(self):
        # Entradas que antes vivían solo en el backend Termux
        assert lookup_vendor("00:23:76:00:00:00") == "Samsung"
        assert lookup_vendor("FC:61:3D:00:00:00") == "Xiaomi"


class TestAnnotateDevices:
    """Anotación de vendor sobre listas de dispositivos de un scan."""

    def test_anota_vendor(self):
        devices = [{"mac": "B8:27:EB:12:34:56", "name": "raspberrypi"}]
        annotate_devices(devices)
        assert devices[0]["vendor"] == "Raspberry Pi Trading"

    def test_desconocido_no_inserta_vendor(self):
        devices = [{"mac": "99:99:99:11:22:33", "name": "??"}]
        annotate_devices(devices)
        assert "vendor" not in devices[0]

    def test_respeta_vendor_existente(self):
        devices = [{"mac": "B8:27:EB:12:34:56", "vendor": "Mi alias"}]
        annotate_devices(devices)
        assert devices[0]["vendor"] == "Mi alias"

    def test_sin_mac_no_explota(self):
        devices = [{"name": "anónimo"}]
        annotate_devices(devices)
        assert "vendor" not in devices[0]

    def test_entradas_no_dict_intactas(self):
        devices = ["AA:BB:CC:DD:EE:FF"]
        out = annotate_devices(devices)
        assert out == ["AA:BB:CC:DD:EE:FF"]

    def test_devuelve_la_misma_lista(self):
        devices = []
        assert annotate_devices(devices) is devices


class TestScannerIntegration:
    """DeviceScanner anota 'vendor' en cada dispositivo descubierto."""

    def test_run_anota_vendor(self, monkeypatch):
        from bluesky.modules.scanners.device_scanner import DeviceScanner

        scanner = DeviceScanner(options={"type": "all", "timeout": "1"})
        fake = [
            {"mac": "B8:27:EB:12:34:56", "name": "pi", "type": "classic", "rssi": 0},
            {"mac": "00:1A:7D:99:88:77", "name": "csr-dongle", "type": "ble", "rssi": -60},
        ]
        monkeypatch.setattr(scanner, "_scan_classic", lambda timeout: fake)
        monkeypatch.setattr(scanner, "_scan_ble", lambda timeout: [])
        monkeypatch.setattr(scanner, "_get_device_info", lambda mac: {"services": []})
        monkeypatch.setattr("bluesky.modules.scanners.device_scanner.is_windows",
                            lambda: False)

        result = scanner.run()
        devices = result["data"]["devices"]
        assert result["success"] is True
        assert devices[0]["vendor"] == "Raspberry Pi Trading"
        assert devices[1]["vendor"] == "Cambridge Silicon Radio (CSR)"
