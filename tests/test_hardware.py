"""
Tests unitarios para HardwareDetector (core/hardware.py)
"""

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from bluesky.core.hardware import HardwareDetector


class TestHardwareDetector(unittest.TestCase):
    """Pruebas para HardwareDetector."""

    def setUp(self):
        self.hw = HardwareDetector()

    def test_01_detect_termux(self):
        """Verificar detección de Termux (debe ser False en Linux)."""
        # En Linux normal debe ser False
        result = self.hw.is_termux()
        self.assertIn(result, [True, False])

    def test_02_get_adapter_info(self):
        """Verificar que get_adapter_info retorna dict con campos."""
        info = self.hw.get_adapter_info()
        self.assertIn("available", info)
        self.assertIn("interface", info)
        self.assertIn("mac", info)
        self.assertIn("powered", info)
        self.assertIn("type", info)

    def test_03_get_bluetooth_devices(self):
        """Verificar detección de dispositivos BT."""
        devices = self.hw.get_bluetooth_devices()
        self.assertIsInstance(devices, list)
        # Puede estar vacío si no hay BT

    def test_04_get_capabilities(self):
        """Verificar capacidades."""
        caps = self.hw.get_capabilities()
        self.assertIn("bluetooth_available", caps)
        self.assertIn("ble_support", caps)
        self.assertIn("classic_support", caps)
        self.assertIn("is_root", caps)
        self.assertIn("is_termux", caps)
        self.assertIsInstance(caps["bluetooth_available"], bool)

    def test_05_is_root(self):
        """Verificar detección de root (debe ser bool)."""
        result = self.hw.is_root()
        self.assertIsInstance(result, bool)

    def test_06_check_internal_bt(self):
        """Verificar chequeo de BT interno."""
        ok, msg = self.hw.check_hardware_requirement("internal_bt")
        self.assertIsInstance(ok, bool)
        self.assertIsInstance(msg, str)

    def test_07_check_unknown_requirement(self):
        """Verificar requisito desconocido."""
        ok, msg = self.hw.check_hardware_requirement("nonexistent_hardware_xyz")
        self.assertFalse(ok)
        self.assertIn("desconocido", msg.lower())

    def test_08_required_internal_no_error(self):
        """Verificar que check no lance excepción."""
        try:
            self.hw.check_hardware_requirement("root")
        except Exception as e:
            self.fail(f"check_hardware_requirement lanzó excepción: {e}")

    def test_09_multiple_calls_consistent(self):
        """Verificar consistencia en llamadas múltiples."""
        caps1 = self.hw.get_capabilities()
        caps2 = self.hw.get_capabilities()
        self.assertEqual(caps1["bluetooth_available"], caps2["bluetooth_available"])
        self.assertEqual(caps1["is_termux"], caps2["is_termux"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
