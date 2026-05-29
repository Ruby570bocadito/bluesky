"""
Tests unitarios para Reporter (core/reporter.py)
"""

import sys
import json
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from bluesky.core.reporter import Reporter


class TestReporter(unittest.TestCase):
    """Pruebas para Reporter."""

    def setUp(self):
        """Configurar datos de prueba."""
        self.test_data = {
            "session": {
                "name": "Test Audit",
                "date": "2026-05-28",
                "environment": "Linux",
                "duration": "10m",
            },
            "targets": [
                {
                    "name": "Test Phone",
                    "mac": "AA:BB:CC:DD:EE:FF",
                    "rssi": -65,
                    "first_seen": "2026-05-28T10:00:00",
                    "services": [{"name": "A2DP Source", "uuid": "0x110A"}],
                    "vulnerabilities": [{"name": "KNOB", "severity": "critical"}],
                },
                {
                    "name": "Test Headset",
                    "mac": "11:22:33:44:55:66",
                    "rssi": -80,
                    "first_seen": "2026-05-28T10:05:00",
                    "services": [],
                    "vulnerabilities": [],
                },
            ],
            "results": [
                {
                    "module": "bluejacking",
                    "target": "AA:BB:CC:DD:EE:FF",
                    "timestamp": "2026-05-28T10:01:00",
                    "success": True,
                    "data": {"message": "Test sent"},
                },
                {
                    "module": "knob",
                    "target": "AA:BB:CC:DD:EE:FF",
                    "timestamp": "2026-05-28T10:02:00",
                    "success": False,
                    "data": {},
                    "error": "No compatible hardware",
                },
            ],
        }
        self.reporter = Reporter(self.test_data)

    def test_01_create_reporter(self):
        """Verificar creación del reporter."""
        self.assertIsNotNone(self.reporter)

    def test_02_set_data(self):
        """Verificar cambio de datos."""
        new_data = {"test": "data"}
        self.reporter.set_data(new_data)
        self.assertEqual(self.reporter.data, new_data)

    def test_03_json_output(self):
        """Verificar generación de JSON."""
        output = self.reporter.to_json()
        parsed = json.loads(output)
        self.assertEqual(parsed["session"]["name"], "Test Audit")
        self.assertEqual(len(parsed["targets"]), 2)
        self.assertEqual(len(parsed["results"]), 2)

    def test_04_json_to_file(self):
        """Verificar JSON a archivo."""
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
            self.reporter.to_json(f.name)
            with open(f.name, encoding="utf-8") as fh:
                data = json.load(fh)
            self.assertEqual(data["session"]["name"], "Test Audit")

    def test_05_txt_output(self):
        """Verificar generación de TXT."""
        output = self.reporter.to_txt()
        self.assertIn("BLUESKY - BLUETOOTH AUDIT REPORT", output)
        self.assertIn("Test Phone", output)
        self.assertIn("AA:BB:CC:DD:EE:FF", output)
        self.assertIn("bluejacking", output)

    def test_06_txt_to_file(self):
        """Verificar TXT a archivo."""
        with tempfile.NamedTemporaryFile(suffix=".txt", delete=False) as f:
            self.reporter.to_txt(f.name)
            with open(f.name, encoding="utf-8") as fh:
                content = fh.read()
            self.assertIn("BLUESKY", content)

    def test_07_html_output(self):
        """Verificar generación de HTML."""
        output = self.reporter.to_html()
        self.assertIn("<html", output)
        self.assertIn("Bluesky Audit Report", output)
        self.assertIn("Test Phone", output)
        self.assertIn("KNOB", output)

    def test_08_html_to_file(self):
        """Verificar HTML a archivo."""
        with tempfile.NamedTemporaryFile(suffix=".html", delete=False) as f:
            self.reporter.to_html(f.name)
            with open(f.name, encoding="utf-8") as fh:
                content = fh.read()
            self.assertIn("Bluesky Audit Report", content)

    def test_09_empty_data(self):
        """Verificar reporte con datos vacíos."""
        empty = Reporter()
        txt = empty.to_txt()
        self.assertIn("BLUESKY", txt)

    def test_10_html_vulnerability_classes(self):
        """Verificar clases CSS para vulnerabilidades."""
        html = self.reporter.to_html()
        self.assertIn("critical", html)
        self.assertIn("KNOB", html)


if __name__ == "__main__":
    unittest.main(verbosity=2)
