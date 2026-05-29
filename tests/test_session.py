"""
Tests unitarios para Session (core/session.py)
"""

import sys
import os
import json
import tempfile
import unittest
from pathlib import Path

# Asegurar que podemos importar bluesky
sys.path.insert(0, str(Path(__file__).parent.parent))

from bluesky.core.session import Session


class TestSession(unittest.TestCase):
    """Pruebas para la clase Session."""

    def setUp(self):
        """Configurar sesión temporal para pruebas."""
        self.temp_dir = tempfile.mkdtemp()
        self.session = Session("test_session", base_dir=self.temp_dir)

    def test_01_create_session(self):
        """Verificar creación de sesión."""
        self.assertEqual(self.session.name, "test_session")
        self.assertEqual(len(self.session.targets), 0)
        self.assertEqual(len(self.session.results), 0)
        self.assertTrue(self.session.base_dir.exists())

    def test_02_add_target(self):
        """Verificar agregar targets."""
        target = self.session.add_target("AA:BB:CC:DD:EE:FF", "Test Phone", -65)
        self.assertEqual(target["mac"], "AA:BB:CC:DD:EE:FF")
        self.assertEqual(target["name"], "Test Phone")
        self.assertEqual(target["rssi"], -65)
        self.assertEqual(len(self.session.targets), 1)

    def test_03_add_duplicate_target(self):
        """Verificar que no se duplican targets por MAC."""
        self.session.add_target("AA:BB:CC:DD:EE:FF", "Test Phone", -65)
        self.session.add_target("AA:BB:CC:DD:EE:FF", "Test Phone", -70)
        self.assertEqual(len(self.session.targets), 1)
        self.assertEqual(self.session.targets[0]["rssi"], -70)

    def test_04_add_result(self):
        """Verificar agregar resultados."""
        result = self.session.add_result(
            "bluejacking", "AA:BB:CC:DD:EE:FF", True,
            {"message": "Sent"}, None
        )
        self.assertEqual(result["module"], "bluejacking")
        self.assertTrue(result["success"])
        self.assertEqual(len(self.session.results), 1)

    def test_05_save_and_load(self):
        """Verificar guardar y cargar sesión."""
        self.session.add_target("AA:BB:CC:DD:EE:FF", "Test Phone", -65)
        self.session.add_result("scan", "AA:BB:CC:DD:EE:FF", True, {}, None)
        self.session._save()

        # Crear nueva sesión y cargar
        new_session = Session("test_session", base_dir=self.temp_dir)
        loaded = new_session.load()
        self.assertTrue(loaded)
        self.assertEqual(len(new_session.targets), 1)
        self.assertEqual(len(new_session.results), 1)
        self.assertEqual(new_session.targets[0]["mac"], "AA:BB:CC:DD:EE:FF")

    def test_06_list_sessions(self):
        """Verificar listado de sesiones."""
        self.session._save()
        sessions = Session.list_sessions(base_dir=self.temp_dir)
        self.assertIn("test_session", sessions)

    def test_07_summary(self):
        """Verificar resumen de sesión."""
        self.session.add_target("AA:BB:CC:DD:EE:FF", "Test Phone", -65)
        self.session.add_result("bluejacking", "AA:BB:CC:DD:EE:FF", True, {}, None)
        self.session.add_result("knob", "AA:BB:CC:DD:EE:FF", False, {}, "No HW")

        summary = self.session.summary()
        self.assertEqual(summary["total_targets"], 1)
        self.assertEqual(summary["total_results"], 2)
        self.assertEqual(summary["successful_attacks"], 1)
        self.assertEqual(summary["failed_attacks"], 1)

    def test_08_load_nonexistent(self):
        """Verificar carga de sesión inexistente."""
        fake_session = Session("nonexistent", base_dir=self.temp_dir)
        loaded = fake_session.load()
        self.assertFalse(loaded)

    def test_09_notes(self):
        """Verificar notas de sesión."""
        self.session.notes = "Auditoría de prueba"
        self.session._save()

        loaded = Session("test_session", base_dir=self.temp_dir)
        loaded.load()
        self.assertEqual(loaded.notes, "Auditoría de prueba")

    def test_10_serializable(self):
        """Verificar que los datos sean serializables a JSON."""
        self.session.add_target("AA:BB:CC:DD:EE:FF", "Test Phone", -65)
        self.session.add_result("scan", "AA:BB:CC:DD:EE:FF", True, {}, None)
        summary = self.session.summary()
        try:
            json.dumps(summary, default=str)
            serializable = True
        except (TypeError, ValueError):
            serializable = False
        self.assertTrue(serializable)


if __name__ == "__main__":
    unittest.main(verbosity=2)
