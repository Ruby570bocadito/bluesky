"""
Tests unitarios para ModuleEngine (core/engine.py)
"""

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from bluesky.core.engine import ModuleEngine, BaseModule


class TestModuleEngine(unittest.TestCase):
    """Pruebas para ModuleEngine."""

    @classmethod
    def setUpClass(cls):
        cls.engine = ModuleEngine()

    def test_01_engine_creates(self):
        """Verificar que el motor se crea."""
        self.assertIsNotNone(self.engine)

    def test_02_all_modules_loaded(self):
        """Verificar que se cargaron módulos."""
        modules = self.engine.list_modules()
        self.assertGreater(len(modules), 5, "Deben cargarse al menos 5 módulos")

    def test_03_required_modules_exist(self):
        """Verificar que los módulos clave existen."""
        modules = self.engine.list_modules()
        names = [m.get("name", "") for m in modules]

        required = ["bluejacking", "blueborne", "whisperpair", "knob"]
        for req in required:
            self.assertIn(req, names, f"Módulo '{req}' no encontrado")

    def test_04_module_info_format(self):
        """Verificar que la info del módulo nativo tiene los campos esperados."""
        for mod in self.engine.list_modules():
            # Los plugins externos pueden no tener todos los campos BaseModule
            if mod.get("type") and "scanner" in mod.get("type", ""):
                continue
            self.assertIn("name", mod)
            self.assertIn("description", mod)
            self.assertIn("severity", mod)
            self.assertIn("target_type", mod)
            self.assertIn("requires_hardware", mod)
            self.assertIn("cve", mod)
            self.assertIn("version", mod)

    def test_05_get_module_by_name(self):
        """Verificar obtener módulo por nombre."""
        cls = self.engine.get_module("bluejacking")
        self.assertIsNotNone(cls)
        self.assertTrue(issubclass(cls, BaseModule))

    def test_06_module_creates_instance(self):
        """Verificar que el módulo puede instanciarse."""
        cls = self.engine.get_module("bluejacking")
        instance = cls()
        self.assertIsInstance(instance, BaseModule)

    def test_07_get_nonexistent_module(self):
        """Verificar que módulo inexistente retorna None."""
        cls = self.engine.get_module("nonexistent_module_xyz")
        self.assertIsNone(cls)

    def test_08_run_nonexistent_module(self):
        """Verificar ejecución de módulo inexistente."""
        result = self.engine.run_module("nonexistent_module_xyz")
        self.assertFalse(result.get("success"))
        self.assertIsNotNone(result.get("error"))

    def test_09_module_run_method(self):
        """Verificar que el módulo tiene método run."""
        cls = self.engine.get_module("whisperpair")
        instance = cls(target="00:11:22:33:44:55")
        self.assertTrue(hasattr(instance, "run"))
        self.assertTrue(callable(instance.run))

    def test_10_module_get_info(self):
        """Verificar get_info del módulo."""
        cls = self.engine.get_module("blueborne")
        instance = cls()
        info = instance.get_info()
        self.assertEqual(info.get("name"), "blueborne")
        self.assertIn("CVE-2017", info.get("cve", ""))

    def test_11_severity_values(self):
        """Verificar valores de severidad válidos en módulos nativos."""
        valid = {"critical", "high", "medium", "low"}
        for mod in self.engine.list_modules():
            sev = mod.get("severity", "")
            if not sev:
                continue  # Plugins pueden no tener severity
            self.assertIn(sev, valid, f"Severidad inválida '{sev}' en {mod.get('name')}")

    def test_12_target_type_values(self):
        """Verificar valores de target_type válidos en módulos nativos."""
        valid = {"classic", "ble", "both", "android"}
        for mod in self.engine.list_modules():
            ttype = mod.get("target_type", "")
            if not ttype:
                continue  # Plugins pueden no tener target_type
            self.assertIn(ttype, valid, f"Tipo inválido '{ttype}' en {mod.get('name')}")


class TestBaseModule(unittest.TestCase):
    """Pruebas para BaseModule."""

    def test_01_base_cannot_run(self):
        """Verificar que BaseModule.run() lanza NotImplementedError."""
        base = BaseModule()
        with self.assertRaises(NotImplementedError):
            base.run()

    def test_02_base_has_defaults(self):
        """Verificar valores por defecto de BaseModule."""
        base = BaseModule()
        info = base.get_info()
        self.assertEqual(info["name"], "")
        self.assertEqual(info["version"], "0.2.0")
        self.assertEqual(info["severity"], "medium")

    def test_03_base_check_prerequisites(self):
        """Verificar prerequisitos base - falla sin target."""
        base = BaseModule()
        ok, msg = base.check_prerequisites()
        self.assertFalse(ok)
        self.assertIn("target", msg.lower())

    def test_03b_base_check_prerequisites_with_target(self):
        """Verificar prerequisitos base con target."""
        base = BaseModule(target="AA:BB:CC:DD:EE:FF")
        ok, msg = base.check_prerequisites()
        self.assertTrue(ok)

    def test_04_custom_module(self):
        """Verificar módulo personalizado."""
        class TestMod(BaseModule):
            name = "testmod"
            description = "Test module"
            severity = "high"

        mod = TestMod(target="AA:BB:CC:DD:EE:FF", options={"opt1": "val1"})
        self.assertEqual(mod.target, "AA:BB:CC:DD:EE:FF")
        self.assertEqual(mod.options["opt1"], "val1")
        self.assertEqual(mod.name, "testmod")


if __name__ == "__main__":
    unittest.main(verbosity=2)
