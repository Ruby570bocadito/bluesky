"""
Tests unitarios para Termux Bluetooth Backend (utils/termux_backend.py)
"""

import sys
import unittest
from unittest.mock import patch, MagicMock
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from bluesky.utils import termux_backend as tb


class TestTermuxBackend(unittest.TestCase):
    """Pruebas para el módulo termux_backend."""

    def test_01_is_termux_api_available(self):
        """Verificar detección de Termux:API (debe ser False en testing)."""
        # En entorno de test sin Termux, debe retornar False
        available = tb.is_termux_api_available()
        self.assertIsInstance(available, bool)

    def test_02_is_termux_bluetooth_enabled(self):
        """Verificar detección de Bluetooth (debe ser False sin Termux:API)."""
        enabled = tb.is_termux_bluetooth_enabled()
        self.assertIsInstance(enabled, bool)

    def test_03_list_adapters_returns_list(self):
        """list_adapters debe retornar lista (posiblemente vacía)."""
        adapters = tb.list_adapters()
        self.assertIsInstance(adapters, list)
        # Sin Termux, debe ser lista vacía
        if not tb.is_termux_api_available():
            self.assertEqual(len(adapters), 0)

    def test_04_scan_devices_returns_list(self):
        """scan_devices debe retornar lista."""
        devices = tb.scan_devices(timeout=2)
        self.assertIsInstance(devices, list)

    def test_05_get_device_info_nonexistent(self):
        """get_device_info con MAC inválida debe retornar None sin Termux:API."""
        info = tb.get_device_info("00:00:00:00:00:00")
        if not tb.is_termux_api_available():
            self.assertIsNone(info)

    def test_06_enable_disable_bluetooth(self):
        """enable/disable Bluetooth debe retornar bool."""
        if tb.is_termux_api_available():
            enabled = tb.enable_bluetooth()
            self.assertIsInstance(enabled, bool)
            disabled = tb.disable_bluetooth()
            self.assertIsInstance(disabled, bool)
        else:
            # Sin API, debe retornar False
            self.assertFalse(tb.enable_bluetooth())
            self.assertFalse(tb.disable_bluetooth())

    def test_07_pair_unpair_device(self):
        """pair/unpair debe retornar bool."""
        if tb.is_termux_api_available():
            paired = tb.pair_device("00:00:00:00:00:00")
            self.assertIsInstance(paired, bool)
            unpaired = tb.unpair_device("00:00:00:00:00:00")
            self.assertIsInstance(unpaired, bool)
        else:
            self.assertFalse(tb.pair_device("00:00:00:00:00:00"))
            self.assertFalse(tb.unpair_device("00:00:00:00:00:00"))

    def test_08_connect_disconnect_device(self):
        """connect/disconnect debe retornar bool."""
        if tb.is_termux_api_available():
            connected = tb.connect_device("00:00:00:00:00:00")
            self.assertIsInstance(connected, bool)
            disconnected = tb.disconnect_device("00:00:00:00:00:00")
            self.assertIsInstance(disconnected, bool)
        else:
            self.assertFalse(tb.connect_device("00:00:00:00:00:00"))
            self.assertFalse(tb.disconnect_device("00:00:00:00:00:00"))

    def test_09_get_status(self):
        """get_status debe retornar dict con campos esperados."""
        status = tb.get_status()
        self.assertIsInstance(status, dict)
        self.assertIn("platform", status)
        self.assertEqual(status["platform"], "termux")
        self.assertIn("api_available", status)
        self.assertIn("bluetooth_enabled", status)
        self.assertIn("ble_available", status)
        self.assertIn("adapter", status)
        self.assertIn("adapter_mac", status)
        self.assertIn("paired_count", status)
        self.assertIn("backend", status)

    def test_10_scan_bluez_fallback(self):
        """El fallback a BlueZ debe retornar lista."""
        devices = tb._scan_bluez_fallback(timeout=2)
        self.assertIsInstance(devices, list)

    def test_11_classify_device_type(self):
        """Clasificación de tipo BLE vs Classic."""
        # BLE keywords
        ble_device = {"name": "Smart Bulb BLE", "type": "ble"}
        classic_device = {"name": "Headphones", "type": "classic"}

        self.assertEqual(tb._classify_device_type(ble_device), "ble")
        self.assertEqual(tb._classify_device_type(classic_device), "classic")

        # Por nombre
        device_ble_name = {"name": "iBeacon-01234"}
        self.assertEqual(tb._classify_device_type(device_ble_name), "ble")

        # Default
        device_unknown = {"name": "Generic Device"}
        self.assertEqual(tb._classify_device_type(device_unknown), "classic")

    def test_12_guess_vendor_from_mac(self):
        """Adivinar fabricante por prefijo MAC."""
        tests = [
            ("5C:B9:01:12:34:56", "Xiaomi"),
            ("04:CB:1D:AB:CD:EF", "Huawei"),
            ("00:0A:AD:11:22:33", "HTC"),
            ("10:83:44:AA:BB:CC", "Google"),
            ("00:00:00:00:00:00", "Unknown"),
            ("FF:FF:FF:FF:FF:FF", "Unknown"),
        ]
        for mac, expected in tests:
            vendor = tb._guess_vendor_from_mac(mac)
            self.assertEqual(vendor, expected,
                             f"MAC {mac}: esperado {expected}, obtenido {vendor}")

    def test_13_getprop(self):
        """getprop debe funcionar sin fallar."""
        prop = tb._getprop("ro.build.version.sdk")
        # En Termux real retornaría SDK version, en test puede ser None
        self.assertIsNone(prop)  # getprop no disponible en Linux normal

    def test_14_run_termux_api(self):
        """_run_termux_api debe manejar comandos sin fallar."""
        result = tb._run_termux_api("scan", "--limit", "1", timeout=2)
        self.assertIsNone(result)  # Sin Termux:API retorna None

    def test_15_parse_json_output(self):
        """Parseo de JSON output."""
        # JSON válido
        parsed = tb._parse_json_output('[{"name":"Test","address":"00:11:22:33:44:55"}]')
        self.assertIsNotNone(parsed)
        self.assertEqual(len(parsed), 1)
        self.assertEqual(parsed[0]["name"], "Test")

        # JSON inválido
        parsed = tb._parse_json_output("not json")
        self.assertIsNone(parsed)

        # None
        parsed = tb._parse_json_output(None)
        self.assertIsNone(parsed)

        # Dict
        parsed = tb._parse_json_output('{"name":"single"}')
        self.assertIsNotNone(parsed)
        self.assertEqual(len(parsed), 1)


class TestTermuxBackendMocked(unittest.TestCase):
    """Pruebas con mocks para simular Termux:API."""

    @patch('bluesky.utils.termux_backend.is_termux_api_available')
    @patch('bluesky.utils.termux_backend._run_termux_api')
    def test_01_scan_with_mock(self, mock_run, mock_avail):
        """Simular escaneo de dispositivos."""
        import json
        mock_avail.return_value = True
        mock_run.return_value = json.dumps([
            {"address": "AA:BB:CC:DD:EE:FF", "name": "Test Phone",
             "rssi": -60, "type": "classic"},
            {"address": "11:22:33:44:55:66", "name": "Test BLE",
             "rssi": -75, "type": "ble"},
        ])

        devices = tb.scan_devices(timeout=2)

        self.assertEqual(len(devices), 2)
        self.assertEqual(devices[0]["name"], "Test Phone")
        self.assertEqual(devices[0]["address"], "AA:BB:CC:DD:EE:FF")
        self.assertEqual(devices[0]["type"], "classic")

    @patch('bluesky.utils.termux_backend.is_termux_api_available')
    @patch('bluesky.utils.termux_backend._run_termux_api')
    def test_02_get_status_with_mock(self, mock_run, mock_avail):
        """Simular estado Bluetooth."""
        mock_avail.return_value = True

        status = tb.get_status()

        self.assertEqual(status["platform"], "termux")
        self.assertTrue(status["api_available"])


if __name__ == "__main__":
    import json
    unittest.main(verbosity=2)
