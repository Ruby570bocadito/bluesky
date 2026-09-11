"""
Tests de regresión QA ronda 2 (BS-QA2) — bugs confirmados con repro.

Cada test reproduce un bug real verificado antes del fix:
  - engine.run_module: crash de run() devolvía dict SIN clave "data"
    (contrato {"success", "data", "error"} roto → KeyError aguas abajo)
  - hardware._check_usb_product: se llamaba con lista (hardware.py:419
    `ubluetooth_dongle`) pero la firma era str → AttributeError silencioso
  - reporter.to_html: nombres de dispositivos/MACs/errores interpolados sin
    html.escape → XSS almacenado al abrir el reporte (nombre de dispositivo
    controlado por el host escaneado)
  - reporter: versión obsoleta "v0.1.0" en los pies de reporte
  - session.load: JSON corrupto en disco → JSONDecodeError crasheaba la consola
  - session.load: JSON válido pero targets/results/config no-lista/no-dict
"""

import sys
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).parent.parent))

from bluesky.core.engine import ModuleEngine, BaseModule
from bluesky.core.reporter import Reporter
from bluesky.core.session import Session
from bluesky.core import hardware as hw


class TestEngineResultContract(unittest.TestCase):
    """Contrato de resultados del engine: SIEMPRE con clave 'data'."""

    @classmethod
    def setUpClass(cls):
        cls.engine = ModuleEngine()

    def test_01_crash_in_run_returns_data_key(self):
        """run() que lanza excepción → {"success", "data", "error"} completo."""
        result = self.engine.run_module(
            "bluejacking", target="00:11:22:33:44:55",
            options={"MESSAGE": "__qa_probe__"},
        )
        # El módulo puede tener éxito o no, pero el shape debe ser completo
        self.assertIn("success", result)
        self.assertIn("data", result)
        self.assertIn("error", result)
        self.assertIsInstance(result["data"], dict)

    def test_02_failing_module_result_has_data(self):
        """Módulo inexistente y prerequisitos fallidos también respetan shape."""
        r1 = self.engine.run_module("__no_existe__")
        self.assertEqual(r1, {"success": False, "data": {},
                              "error": r1.get("error")})
        r2 = self.engine.run_module("rfcomm_shell", target="00:11:22:33:44:55")
        self.assertIn("data", r2)
        self.assertIsInstance(r2.get("data"), dict)

    def test_03_base_module_run_contract_via_engine(self):
        """Un módulo cuyo run() explota dentro del engine no pierde 'data'."""

        class _Boom(BaseModule):
            name = "__qa_boom__"
            description = "módulo de prueba"
            module_options = {"TARGET": "t"}

            def run(self):
                raise RuntimeError("kaboom")

        self.engine._modules["__qa_boom__"] = _Boom
        try:
            r = self.engine.run_module("__qa_boom__",
                                       target="00:11:22:33:44:55")
        finally:
            self.engine._modules.pop("__qa_boom__", None)
        self.assertFalse(r["success"])
        self.assertEqual(r["data"], {})
        self.assertIn("kaboom", r["error"])


class TestUsbProductCheck(unittest.TestCase):
    """_check_usb_product debe aceptar str Y lista (bug de hardware.py:419)."""

    def test_04_check_usb_product_accepts_list(self):
        """Antes: _check_usb_product(['rtl8761']) → AttributeError .lower."""
        with mock.patch.object(hw, "_check_usb_product_single",
                               return_value=True) as m:
            self.assertTrue(hw._check_usb_product(["rtl8761"]))
            m.assert_called_once_with("rtl8761")

    def test_05_check_usb_product_accepts_str(self):
        with mock.patch.object(hw, "_check_usb_product_single",
                               return_value=False) as m:
            self.assertFalse(hw._check_usb_product("rtl8761"))
            m.assert_called_once_with("rtl8761")

    def test_06_check_usb_product_empty_and_garbage(self):
        self.assertFalse(hw._check_usb_product([]))
        self.assertFalse(hw._check_usb_product(["", None]))
        self.assertFalse(hw._check_usb_product(None))

    def test_07_ubluetooth_dongle_requirement_does_not_error(self):
        """El check 'ubluetooth_dongle' no debe terminar en 'Error al verificar'."""
        ok, msg = hw.HardwareDetector.check_hardware_requirement(
            "ubluetooth_dongle")
        self.assertIn("No disponible", msg)  # sin dongle en CI/entorno de test
        self.assertNotIn("Error al verificar", msg)


class TestReporterHtmlEscaping(unittest.TestCase):
    """El reporte HTML debe escapar TODOS los datos del escaneo."""

    def setUp(self):
        self.hostile = {
            "session": {
                "name": '<script>alert("s")</script>',
                "date": "2026-01-01",
                "environment": '<img src=x onerror=alert(1)>',
            },
            "targets": [{
                "name": '<script>alert("t")</script>',
                "mac": 'AA:BB:CC:DD:EE:FF"><b>inj</b>',
                "rssi": -60,
                "vulnerabilities": [
                    {"name": "<svg onload=alert(2)>",
                     "severity": '"><script>x</script>'},
                ],
            }],
            "results": [{
                "module": "<b>knob</b>",
                "target": '00:11:22:33:44:55" onmouseover="alert(3)',
                "success": False,
                "error": "<script>alert(4)</script>",
            }, {
                "module": "knob",
                "target": "00:11:22:33:44:55",
                "success": True,
                "data": {},
            }],
        }
        self.html = Reporter(self.hostile).to_html()

    def test_08_no_raw_script_tag_from_device_data(self):
        # No hay etiquetas raw generadas por datos del escaneo
        self.assertNotIn("<script>alert", self.html)
        self.assertNotIn("<img", self.html)
        self.assertNotIn("<svg onload", self.html)
        self.assertNotIn("<b>inj</b>", self.html)
        self.assertNotIn("onmouseover=\"alert", self.html)
        # Y los payloads escapados SÍ aparecen como texto inofensivo
        self.assertIn("&lt;script&gt;", self.html)
        self.assertIn("&lt;img", self.html)

    def test_09_severity_class_is_whitelisted(self):
        self.assertNotIn('class="vuln ">', self.html)
        self.assertNotIn('"><script>x</script>', self.html)
        self.assertIn('class="vuln medium"', self.html)
        self.assertIn('class="failed"', self.html)
        self.assertIn('class="success"', self.html)

    def test_10_report_footer_uses_package_version(self):
        from bluesky import __version__
        self.assertNotIn("v0.1.0", self.html)
        self.assertIn(f"v{__version__}", self.html)
        txt = Reporter(self.hostile).to_txt()
        self.assertNotIn("v0.1.0", txt)
        self.assertIn(f"v{__version__}", txt)

    def test_11_reporter_tolerates_non_dict_session(self):
        r = Reporter({"session": "garbage", "targets": None, "results": None})
        html = r.to_html()
        self.assertIn("bluesky Audit Report", html)


class TestSessionCorruptLoad(unittest.TestCase):
    """session.load con fichero corrupto no debe lanzar excepción."""

    def test_12_load_corrupted_json_returns_false(self):
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            s = Session("corrupt", base_dir=tmp)
            s.session_file.write_text("{not valid json!!")
            self.assertFalse(s.load())
            # targets en memoria intactos tras el fallo de carga
            self.assertEqual(s.targets, [])

    def test_13_load_non_dict_json_returns_false(self):
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            s = Session("nondict", base_dir=tmp)
            s.session_file.write_text('["a", "list"]')
            self.assertFalse(s.load())

    def test_14_load_valid_json_with_wrong_field_types(self):
        import tempfile, json as _json
        with tempfile.TemporaryDirectory() as tmp:
            s = Session("wrongtypes", base_dir=tmp)
            s.session_file.write_text(_json.dumps({
                "name": "x",
                "targets": "no-soy-lista",
                "results": 42,
                "config": ["no-soy-dict"],
            }))
            self.assertTrue(s.load())
            self.assertEqual(s.targets, [])
            self.assertEqual(s.results, [])
            self.assertEqual(s.config, {})


if __name__ == "__main__":
    unittest.main(verbosity=2)
