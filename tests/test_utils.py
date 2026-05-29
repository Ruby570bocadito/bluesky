"""
Tests unitarios para utilidades (utils/*)
"""

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from bluesky.utils.format import (
    colorize, separator, severity_icon, target_type_icon,
    format_device_list, format_service_list,
    terminal_width
)
from bluesky.utils.network import mac_valid, mac_normalize
from bluesky.utils.termux import is_termux


class TestFormatUtils(unittest.TestCase):
    """Pruebas para formato."""

    def test_01_colorize(self):
        """Verificar que colorize agrega códigos ANSI."""
        result = colorize("test", "red")
        self.assertIn("\033[91m", result)
        self.assertIn("\033[0m", result)
        self.assertIn("test", result)

    def test_02_colorize_unknown_color(self):
        """Verificar color desconocido."""
        result = colorize("test", "unknown_color")
        self.assertEqual(result, "test")

    def test_03_separator_creates(self):
        """Verificar separador."""
        s = separator()
        self.assertGreater(len(s), 10)

    def test_04_separator_with_title(self):
        """Verificar separador con título."""
        s = separator(title="TEST")
        self.assertIn("TEST", s)

    def test_05_severity_icons(self):
        """Verificar iconos de severidad."""
        self.assertEqual(severity_icon("critical"), "🔴")
        self.assertEqual(severity_icon("high"), "🟠")
        self.assertEqual(severity_icon("medium"), "🟡")
        self.assertEqual(severity_icon("low"), "⚪")
        self.assertEqual(severity_icon("unknown"), "⚪")

    def test_06_target_type_icons(self):
        """Verificar iconos de tipo de target."""
        self.assertEqual(target_type_icon("classic"), "📡")
        self.assertEqual(target_type_icon("ble"), "🔵")
        self.assertEqual(target_type_icon("both"), "🔄")
        self.assertEqual(target_type_icon("unknown"), "📡")

    def test_07_device_list_empty(self):
        """Verificar lista vacía de dispositivos."""
        result = format_device_list([])
        self.assertIn("No se encontraron", result)

    def test_08_device_list_with_devices(self):
        """Verificar lista con dispositivos."""
        devices = [
            {"mac": "AA:BB:CC:DD:EE:FF", "name": "Phone", "type": "classic", "rssi": -65},
            {"mac": "11:22:33:44:55:66", "name": "Headset", "type": "ble"},
        ]
        result = format_device_list(devices)
        self.assertIn("Phone", result)
        self.assertIn("AA:BB:CC:DD:EE:FF", result)

    def test_09_service_list_empty(self):
        """Verificar lista vacía de servicios."""
        result = format_service_list([])
        self.assertIn("No se encontraron", result)

    def test_10_terminal_width(self):
        """Verificar ancho de terminal."""
        width = terminal_width()
        self.assertGreater(width, 10)

    def test_11_service_list_with_services(self):
        """Verificar lista con servicios."""
        services = [
            {"name": "A2DP Source", "channel": 1, "risk": "low"},
            {"name": "PBAP", "channel": 3, "risk": "high"},
        ]
        result = format_service_list(services)
        self.assertIn("A2DP Source", result)
        self.assertIn("PBAP", result)


class TestNetworkUtils(unittest.TestCase):
    """Pruebas para utilidades de red."""

    def test_01_mac_valid_valid(self):
        """Verificar MAC válida."""
        self.assertTrue(mac_valid("AA:BB:CC:DD:EE:FF"))
        self.assertTrue(mac_valid("aa:bb:cc:dd:ee:ff"))
        self.assertTrue(mac_valid("AA-BB-CC-DD-EE-FF"))

    def test_02_mac_valid_invalid(self):
        """Verificar MAC inválida."""
        self.assertFalse(mac_valid(""))
        self.assertFalse(mac_valid("not-a-mac"))
        self.assertFalse(mac_valid("AA:BB:CC:DD:EE"))
        self.assertFalse(mac_valid("AA:BB:CC:DD:EE:FF:GG"))

    def test_03_mac_normalize(self):
        """Verificar normalización de MAC."""
        self.assertEqual(mac_normalize("aa:bb:cc:dd:ee:ff"), "AA:BB:CC:DD:EE:FF")
        self.assertEqual(mac_normalize("AA-BB-CC-DD-EE-FF"), "AA:BB:CC:DD:EE:FF")


class TestTermuxUtils(unittest.TestCase):
    """Pruebas para utilidades Termux."""

    def test_01_is_termux(self):
        """Verificar detección de Termux (debe ser False en Linux)."""
        # En Linux normal debe ser False
        result = is_termux()
        self.assertFalse(result, "Este test debe correr en Linux, no en Termux")


if __name__ == "__main__":
    unittest.main(verbosity=2)
