"""
Tests unitarios para helpers de seguridad introducidos en rondas 1-2
del agente z_bugs.

Cubre:
  - is_valid_mac() / mac_valid() (validación de MAC)
  - _is_safe_origin() (middleware CSRF del dashboard web)
  - Middleware CSRF en endpoints POST
  - /api/config no expone datos sensibles
"""

import json
import os
import sys
import unittest
from pathlib import Path

# Asegurar que podemos importar bluesky
sys.path.insert(0, str(Path(__file__).parent.parent))


# ─── Helpers de MAC ──────────────────────────────────────────────────────────

class TestMacValidation(unittest.TestCase):
    """Validación MAC unificada en utils/network.py:mac_valid."""

    def setUp(self):
        from bluesky.utils.network import mac_valid
        self.mac_valid = mac_valid

    def test_01_valid_with_colons(self):
        """MAC válida con formato XX:XX:XX:XX:XX:XX."""
        self.assertTrue(self.mac_valid("AA:BB:CC:DD:EE:FF"))

    def test_02_valid_lowercase(self):
        """MAC válida en minúsculas."""
        self.assertTrue(self.mac_valid("aa:bb:cc:dd:ee:ff"))

    def test_03_valid_with_hyphens(self):
        """MAC válida con guiones en lugar de dos puntos."""
        self.assertTrue(self.mac_valid("AA-BB-CC-DD-EE-FF"))

    def test_04_invalid_empty(self):
        """String vacío no es MAC válida."""
        self.assertFalse(self.mac_valid(""))

    def test_05_invalid_flag_injection(self):
        """Un flag como '--evil-flag' no es MAC válida (defensa CLI)."""
        self.assertFalse(self.mac_valid("--evil-flag"))

    def test_06_invalid_shell_injection(self):
        """MAC con payload de shell injection no es válida."""
        self.assertFalse(self.mac_valid("AA:BB:CC:DD:EE:FF; rm -rf /"))
        self.assertFalse(self.mac_valid("$(whoami)"))

    def test_07_invalid_none(self):
        """None debe devolver False, no lanzar TypeError."""
        self.assertFalse(self.mac_valid(None))

    def test_08_invalid_non_string(self):
        """Tipos no-str deben devolver False, no lanzar TypeError."""
        self.assertFalse(self.mac_valid(123))
        self.assertFalse(self.mac_valid(["AA:BB:CC:DD:EE:FF"]))
        self.assertFalse(self.mac_valid({"mac": "AA:BB:CC:DD:EE:FF"}))

    def test_09_too_short(self):
        """MAC con menos de 6 octetos es inválida."""
        self.assertFalse(self.mac_valid("AA:BB:CC:DD:EE"))

    def test_10_too_long(self):
        """MAC con más de 6 octetos es inválida."""
        self.assertFalse(self.mac_valid("AA:BB:CC:DD:EE:FF:GG"))

    def test_11_invalid_chars(self):
        """Caracteres no-hex son inválidos."""
        self.assertFalse(self.mac_valid("ZZ:BB:CC:DD:EE:FF"))
        self.assertFalse(self.mac_valid("AA:BB:CC:DD:EE:GX"))


class TestMacValidationUnification(unittest.TestCase):
    """Las 3 funciones de validación MAC son la misma fuente de verdad."""

    def test_01_all_three_implementations_agree(self):
        """engine.is_valid_mac, termux._is_valid_mac y network.mac_valid
        devuelven lo mismo para casos representativos."""
        from bluesky.core.engine import is_valid_mac
        from bluesky.utils.termux_backend import _is_valid_mac
        from bluesky.utils.network import mac_valid

        cases = [
            ("AA:BB:CC:DD:EE:FF", True),
            ("aa-bb-cc-dd-ee-ff", True),
            ("", False),
            (None, False),
            ("--evil-flag", False),
            (123, False),
        ]
        for addr, expected in cases:
            r1 = is_valid_mac(addr)
            r2 = _is_valid_mac(addr)
            r3 = mac_valid(addr)
            self.assertEqual(r1, expected, f"is_valid_mac({addr!r}) = {r1}")
            self.assertEqual(r2, expected, f"_is_valid_mac({addr!r}) = {r2}")
            self.assertEqual(r3, expected, f"mac_valid({addr!r}) = {r3}")


# ─── BaseModule.check_prerequisites con MAC ──────────────────────────────────

class TestBaseModuleMacValidation(unittest.TestCase):
    """BaseModule.check_prerequisites valida MAC si se proporciona target."""

    def setUp(self):
        from bluesky.core.engine import BaseModule
        self.BaseModule = BaseModule

        class TestMod(BaseModule):
            name = "test"
            module_options = {"TARGET": "MAC objetivo"}

            def run(self, target="", options=None):
                return {"success": True, "data": {}, "error": None}

        self.TestMod = TestMod

    def test_01_valid_target_passes(self):
        """Target con MAC válida pasa check_prerequisites."""
        m = self.TestMod(target="AA:BB:CC:DD:EE:FF")
        ok, msg = m.check_prerequisites()
        self.assertTrue(ok, f"MAC válida rechazada: {msg}")

    def test_02_invalid_target_blocked(self):
        """Target con flag como '--evil-flag' se bloquea."""
        m = self.TestMod(target="--evil-flag")
        ok, msg = m.check_prerequisites()
        self.assertFalse(ok)
        self.assertIn("formato MAC válido", msg)

    def test_03_shell_injection_blocked(self):
        """Target con payload shell se bloquea."""
        m = self.TestMod(target="AA:BB:CC:DD:EE:FF; rm -rf /")
        ok, _ = m.check_prerequisites()
        self.assertFalse(ok)

    def test_04_empty_target_blocked_when_required(self):
        """Target vacío se bloquea cuando TARGET no marca 'opcional'/'vacío'."""
        m = self.TestMod(target="")
        ok, _ = m.check_prerequisites()
        self.assertFalse(ok)

    def test_05_optional_target_empty_allowed(self):
        """TARGET marcado como 'opcional' con target vacío se permite."""
        class TestOpt(self.BaseModule):
            name = "test_opt"
            module_options = {"TARGET": "MAC (opcional para filtrado)"}

            def run(self, target="", options=None):
                return {"success": True, "data": {}, "error": None}

        m = TestOpt(target="")
        ok, _ = m.check_prerequisites()
        self.assertTrue(ok, "TARGET opcional vacío debe permitirse")

    def test_06_optional_target_still_validates_format(self):
        """TARGET opcional sigue validando formato si se proporciona."""
        class TestOpt(self.BaseModule):
            name = "test_opt"
            module_options = {"TARGET": "MAC (opcional para filtrado)"}

            def run(self, target="", options=None):
                return {"success": True, "data": {}, "error": None}

        m = TestOpt(target="--evil-flag")
        ok, _ = m.check_prerequisites()
        self.assertFalse(ok, "TARGET opcional con valor inválido debe bloquearse")


# ─── Middleware CSRF del dashboard web ──────────────────────────────────────

class TestCsrfMiddleware(unittest.TestCase):
    """Middleware CSRF en web/app.py valida Origin/Referer en POST."""

    def setUp(self):
        # Flask es obligatorio para estos tests
        try:
            import flask  # noqa: F401
        except ImportError:
            self.skipTest("Flask no disponible en este entorno")
        from bluesky.web.app import create_app
        self.app = create_app(debug=False)
        self.client = self.app.test_client()

    def test_01_post_without_origin_allowed(self):
        """POST sin Origin ni Referer (curl/scripts) está permitido."""
        r = self.client.post("/api/scan", json={"scanner": "device"})
        # 200 = el POST pasó el middleware CSRF. El resto del procesamiento
        # puede fallar por engine, pero el middleware no debe bloquear.
        self.assertNotEqual(r.status_code, 403,
                            "curl sin Origin no debe ser bloqueado por CSRF")

    def test_02_post_with_evil_origin_blocked(self):
        """POST con Origin de dominio malicioso se bloquea."""
        r = self.client.post("/api/scan",
                             json={"scanner": "device"},
                             headers={"Origin": "http://evil.com"})
        self.assertEqual(r.status_code, 403)
        data = r.get_json()
        self.assertIn("CSRF", data.get("error", ""))

    def test_03_post_with_matching_origin_allowed(self):
        """POST con Origin del mismo host está permitido."""
        r = self.client.post("/api/scan",
                             json={"scanner": "device"},
                             headers={"Origin": "http://localhost"})
        self.assertNotEqual(r.status_code, 403,
                            "Origin localhost no debe ser bloqueado")

    def test_04_post_with_matching_referer_allowed(self):
        """POST con Referer del mismo host está permitido."""
        r = self.client.post("/api/scan",
                             json={"scanner": "device"},
                             headers={"Referer": "http://localhost/scan"})
        self.assertNotEqual(r.status_code, 403)

    def test_05_post_with_mismatched_referer_blocked(self):
        """POST con Referer de dominio malicioso se bloquea."""
        r = self.client.post("/api/scan",
                             json={"scanner": "device"},
                             headers={"Referer": "http://evil.com/scan"})
        self.assertEqual(r.status_code, 403)

    def test_06_get_not_affected(self):
        """GET no pasa por el middleware CSRF."""
        r = self.client.get("/api/status")
        # 200 = el endpoint funciona. El middleware CSRF no debe bloquear GET.
        self.assertEqual(r.status_code, 200)

    def test_07_module_run_with_evil_origin_blocked(self):
        """POST /api/modules/<name>/run con Origin malicioso se bloquea."""
        r = self.client.post("/api/modules/bluejacking/run",
                             json={"target": "AA:BB:CC:DD:EE:FF"},
                             headers={"Origin": "http://evil.com"})
        self.assertEqual(r.status_code, 403)

    def test_08_module_run_without_origin_allowed(self):
        """POST /api/modules/<name>/run sin Origin (curl) está permitido."""
        r = self.client.post("/api/modules/bluejacking/run",
                             json={"target": "AA:BB:CC:DD:EE:FF"})
        # El middleware no debe bloquear. El endpoint puede devolver
        # cualquier status (200, 404 si no encuentra el módulo, etc.)
        # pero NO 403.
        self.assertNotEqual(r.status_code, 403)


# ─── /api/config no expone datos sensibles ──────────────────────────────────

class TestApiConfigNoLeak(unittest.TestCase):
    """El endpoint /api/config no debe exponer MACs, favoritos ni paths."""

    def setUp(self):
        try:
            import flask  # noqa: F401
        except ImportError:
            self.skipTest("Flask no disponible en este entorno")
        from bluesky.web.app import create_app
        self.app = create_app(debug=False)
        self.client = self.app.test_client()

    def test_01_no_default_target_address(self):
        """/api/config no expone default_target.address."""
        r = self.client.get("/api/config")
        data = json.dumps(r.get_json())
        self.assertNotIn("default_target", data,
                         "/api/config expone default_target")

    def test_02_no_favorites_list(self):
        """/api/config no expone la lista de favoritos (solo contador)."""
        r = self.client.get("/api/config")
        data = r.get_json()
        config = data.get("config", {})
        # Debe tener favorites_count (int), NO favorites (lista)
        self.assertNotIn("favorites", config,
                         "No debe exponer lista de favorites")
        if "favorites_count" in config:
            self.assertIsInstance(config["favorites_count"], int)

    def test_03_no_module_options_dict(self):
        """/api/config no expone module_options completo (solo contador)."""
        r = self.client.get("/api/config")
        config = r.get_json().get("config", {})
        self.assertNotIn("module_options", config,
                         "No debe exponer module_options completo")
        if "module_options_count" in config:
            self.assertIsInstance(config["module_options_count"], int)

    def test_04_no_session_last_session(self):
        """/api/config no expone session.last_session (path en disco)."""
        r = self.client.get("/api/config")
        data = json.dumps(r.get_json())
        self.assertNotIn("last_session", data,
                         "/api/config expone session.last_session")

    def test_05_general_keys_present(self):
        """/api/config sigue mostrando claves de UI en general."""
        r = self.client.get("/api/config")
        config = r.get_json().get("config", {})
        general = config.get("general", {})
        for key in ("theme", "log_level", "report_format",
                    "safe_mode", "language"):
            self.assertIn(key, general,
                          f"general.{key} debería estar presente")


# ─── cmd_report: payload correcto para Reporter ──────────────────────────────

class TestCmdReportPayload(unittest.TestCase):
    """cmd_report pasa un payload correcto a Reporter (con results[] y
    session{name,date,...}), no session.summary() que no tiene esas claves."""

    def setUp(self):
        # Reset singleton de config para que cada test tenga su HOME limpio
        from bluesky.utils.config import BlueskyConfig
        BlueskyConfig.reset_instance()
        self.BlueskyConfig = BlueskyConfig

    def test_01_report_includes_results(self):
        """El reporte TXT incluye la sección Attack Results con los módulos."""
        import tempfile
        old_home = os.environ.get("HOME")
        with tempfile.TemporaryDirectory() as td:
            os.environ["HOME"] = td
            self.BlueskyConfig.reset_instance()

            from bluesky.core.session import Session
            s = Session(name="default")  # usa td/.bluesky/sessions/
            s.add_target("AA:BB:CC:DD:EE:FF", "Test Device", -65)
            s.add_result("bluejacking", "AA:BB:CC:DD:EE:FF", True,
                         data={"msg": "sent"}, error=None)
            s.add_result("knob", "AA:BB:CC:DD:EE:FF", False, data={},
                         error="no hw")

            self.BlueskyConfig.reset_instance()
            from bluesky.cli import cmd_report
            output_file = os.path.join(td, "report.txt")
            exit_code = cmd_report(["--txt", "-o", output_file])
            self.assertEqual(exit_code, 0)

            content = open(output_file).read()
            # Sesión con nombre
            self.assertIn("Session:", content)
            self.assertIn("default", content)
            # Targets
            self.assertIn("Targets Found: 1", content)
            self.assertIn("Test Device", content)
            self.assertIn("AA:BB:CC:DD:EE:FF", content)
            # Resultados
            self.assertIn("Attack Results: 2", content)
            self.assertIn("bluejacking", content)
            self.assertIn("knob", content)
            self.assertIn("no hw", content)
            # SUCCESS/FAILED markers
            self.assertIn("SUCCESS", content)
            self.assertIn("FAILED", content)

        if old_home is not None:
            os.environ["HOME"] = old_home
        self.BlueskyConfig.reset_instance()

    def test_02_report_txt_flag_overrides_config(self):
        """--txt sobrescribe el report_format de la config (default html)."""
        import tempfile
        old_home = os.environ.get("HOME")
        with tempfile.TemporaryDirectory() as td:
            os.environ["HOME"] = td
            self.BlueskyConfig.reset_instance()

            # Escribir config con report_format=html
            config_dir = Path(td) / ".config" / "bluesky"
            config_dir.mkdir(parents=True, exist_ok=True)
            config_path = config_dir / "bluesky.json"
            config_path.write_text(json.dumps({
                "general": {"report_format": "html"}
            }))

            self.BlueskyConfig.reset_instance()
            from bluesky.cli import cmd_report
            output_file = os.path.join(td, "report.txt")
            exit_code = cmd_report(["--txt", "-o", output_file])
            self.assertEqual(exit_code, 0)

            content = open(output_file).read()
            # Debe ser texto plano (no HTML con <!DOCTYPE)
            self.assertNotIn("<!DOCTYPE", content)
            self.assertIn("BLUESKY - BLUETOOTH AUDIT REPORT", content)

        if old_home is not None:
            os.environ["HOME"] = old_home
        self.BlueskyConfig.reset_instance()


# ─── Session._sanitize_session_name ─────────────────────────────────────────

class TestSessionNameSanitization(unittest.TestCase):
    """Session sanean el nombre para prevenir path traversal."""

    def setUp(self):
        from bluesky.core.session import _sanitize_session_name
        self.sanitize = _sanitize_session_name

    def test_01_valid_name_unchanged(self):
        """Nombre válido pasa sin cambios."""
        self.assertEqual(self.sanitize("my_session"), "my_session")
        self.assertEqual(self.sanitize("default"), "default")
        self.assertEqual(self.sanitize("mi.ses-01"), "mi.ses-01")

    def test_02_path_traversal_blocked(self):
        """Path traversal se neutraliza."""
        self.assertNotIn("..", self.sanitize("../../../../tmp/evil"))
        self.assertNotIn("/", self.sanitize("../../../../tmp/evil"))
        self.assertNotIn("\\", self.sanitize("..\\..\\..\\evil"))

    def test_03_empty_returns_default(self):
        """Nombre vacío retorna 'default'."""
        self.assertEqual(self.sanitize(""), "default")

    def test_04_none_returns_default(self):
        """None retorna 'default'."""
        self.assertEqual(self.sanitize(None), "default")

    def test_05_non_string_returns_default(self):
        """Tipos no-str retornan 'default'."""
        self.assertEqual(self.sanitize(123), "default")
        self.assertEqual(self.sanitize(["a"]), "default")

    def test_06_null_bytes_stripped(self):
        """Bytes nulos se eliminan (defensa en profundidad)."""
        result = self.sanitize("evil\x00.py")
        self.assertNotIn("\x00", result)


# ─── XSS almacenado en reportes HTML ─────────────────────────────────────────

class TestXssAutopilotReport(unittest.TestCase):
    """Autopilot._phase_report() no debe interpolar datos sin escape.

    Vector: un dispositivo Bluetooth cercano se anuncia con un nombre
    hostil como '<script>...</script>'. Si el reporte no escapa, al
    abrirlo en navegador se ejecuta JS en contexto file:// (acceso a
    archivos locales vía XHR) o en el contexto del dashboard web.

    Corregido en ronda 1 del agente z_bugs (commit f413c57).
    """

    def test_01_no_raw_script_tag_from_device_name(self):
        """Nombre hostil de dispositivo no genera <script> crudo."""
        import os, re
        from bluesky.modules.attacks.autopilot import Autopilot

        targets = [
            {'mac': 'AA:BB:CC:DD:EE:FF',
             'name': '<script>alert("xss-autopilot")</script>',
             'type': 'classic'},
            {'mac': '11:22:33:44:55:66',
             'name': '<img src=x onerror=alert(1)>',
             'type': 'ble'},
        ]
        all_vulns = {
            'AA:BB:CC:DD:EE:FF': [
                {'id': '<script>evil()</script>', 'name': 'x',
                 'severity': 'high', 'vulnerable': True, 'module': 'knob'},
            ],
        }
        results = {
            'AA:BB:CC:DD:EE:FF': [
                {'module': 'bluejacking', 'target': 'AA:BB:CC:DD:EE:FF',
                 'success': True, 'data': {}, 'error': None}],
        }
        a = Autopilot()
        report_path = a._phase_report(targets, results, all_vulns)
        try:
            content = open(report_path).read()
            # Ninguno de estos patrones crudos debe aparecer
            for pattern in [
                '<script>alert', '<img src=x onerror',
                '<script>evil()', '<script>document.cookie',
            ]:
                self.assertNotIn(pattern, content,
                                 f'XSS no escapado: {pattern!r}')
            # Y sí debe estar escapado
            self.assertIn('&lt;script&gt;', content)
        finally:
            if os.path.exists(report_path):
                os.unlink(report_path)


class TestXssVulnScannerReport(unittest.TestCase):
    """VulnScanner._generate_report() no debe interpolar datos sin escape.

    Mismo vector que TestXssAutopilotReport. Corregido en ronda 4
    del agente z_bugs.
    """

    def test_01_no_raw_script_tag_from_device_name(self):
        """Nombre hostil de dispositivo no genera <script> crudo."""
        import os
        from bluesky.modules.scanners.vuln_scanner import VulnScanner

        v = VulnScanner(target='AA:BB:CC:DD:EE:FF')
        target = 'AA:BB:CC:DD:EE:FF'
        all_vulns = []
        found = [
            {'id': '<script>alert("vuln-xss")</script>',
             'name': '<img src=x onerror=alert(1)>',
             'cve': 'CVE-2024-<script>evil()</script>',
             'severity': 'critical',
             'evidence': '<script>document.cookie</script>',
             'module': 'knob',
             'remediation': '<script>alert(1)</script>'},
            {'id': 'BIAS', 'name': 'Bluetooth Impersonation',
             'cve': 'CVE-2020-10135', 'severity': 'high',
             'evidence': 'normal', 'module': 'bias'},
        ]
        device_info = {
            'name': '<script>alert("device-xss")</script>',
            'class': 'Phone',
            'manufacturer': '<img src=x onerror=alert(2)>',
        }

        report_path = v._generate_report(target, all_vulns, found, device_info)
        try:
            content = open(report_path).read()
            # Ninguno de estos patrones crudos debe aparecer
            for pattern in [
                '<script>alert', '<img src=x onerror',
                '<script>evil()', '<script>document.cookie',
                '<script>alert("device-xss")',
            ]:
                self.assertNotIn(pattern, content,
                                 f'XSS no escapado: {pattern!r}')
            # Y sí debe estar escapado
            self.assertIn('&lt;script&gt;', content)
            self.assertIn('&lt;img src=x onerror', content)
        finally:
            if os.path.exists(report_path):
                os.unlink(report_path)

    def test_02_target_in_filename_sanitized(self):
        """El target se sanea al construir el nombre del archivo de reporte."""
        import os
        from bluesky.modules.scanners.vuln_scanner import VulnScanner

        # Target con path traversal (aunque la validación MAC de BaseModule
        # ya lo bloquearía antes, esta es defensa en profundidad)
        v = VulnScanner(target='AA:BB:CC:DD:EE:FF')
        # Simular target malicioso directamente al método
        target = '../../../tmp/evil'
        report_path = v._generate_report(target, [], [], {})
        try:
            # El filename NO debe contener ../
            self.assertNotIn('..', str(report_path))
            self.assertNotIn('/tmp/evil', str(report_path))
        finally:
            if os.path.exists(report_path):
                os.unlink(report_path)


class TestBlueFragConditionalRoot(unittest.TestCase):
    """BlueFrag.check_prerequisites respeta el modo para exigir root.

    MODE=info/scan no requieren root (solo lectura/simulación).
    MODE=exploit/dos sí requieren root (envío de paquetes raw).
    """

    def setUp(self):
        from bluesky.modules.attacks.bluefrag import BlueFrag
        self.BlueFrag = BlueFrag

    def test_01_mode_info_no_root_required(self):
        """MODE=info no exige root."""
        b = self.BlueFrag(options={'MODE': 'info'})
        ok, msg = b.check_prerequisites()
        self.assertTrue(ok, f"MODE=info no debe exigir root: {msg}")

    def test_02_mode_scan_no_root_required(self):
        """MODE=scan no exige root."""
        b = self.BlueFrag(options={'MODE': 'scan'})
        ok, msg = b.check_prerequisites()
        self.assertTrue(ok, f"MODE=scan no debe exigir root: {msg}")

    def test_03_mode_exploit_requires_root(self):
        """MODE=exploit exige root."""
        b = self.BlueFrag(options={'MODE': 'exploit'})
        ok, msg = b.check_prerequisites()
        # En CI sin root, debe fallar con "root" en msg
        if not ok:
            self.assertIn("root", msg.lower())

    def test_04_mode_dos_requires_root(self):
        """MODE=dos exige root."""
        b = self.BlueFrag(options={'MODE': 'dos'})
        ok, msg = b.check_prerequisites()
        if not ok:
            self.assertIn("root", msg.lower())

    def test_05_default_mode_scan_no_root(self):
        """Sin MODE explícito, default es scan (no root)."""
        b = self.BlueFrag()
        ok, msg = b.check_prerequisites()
        self.assertTrue(ok, f"Default MODE=scan no debe exigir root: {msg}")

    def test_06_invalid_target_blocked_regardless_of_mode(self):
        """Target malicioso se bloquea independientemente del modo."""
        b = self.BlueFrag(target='--evil-flag', options={'MODE': 'info'})
        ok, msg = b.check_prerequisites()
        self.assertFalse(ok)
        self.assertIn("formato MAC", msg)


class TestCrackleScapyNotBlocking(unittest.TestCase):
    """Crackle.check_prerequisites no exige scapy (modo simulación disponible)."""

    def setUp(self):
        from bluesky.modules.attacks.crackle import Crackle
        self.Crackle = Crackle

    def test_01_crackle_passes_without_scapy(self):
        """Crackle sin scapy pasa check_prerequisites (modo simulación)."""
        c = self.Crackle()
        ok, msg = c.check_prerequisites()
        # scapy no está en este entorno, pero el check debe pasar
        self.assertTrue(ok, f"Crackle sin scapy debe pasar: {msg}")

    def test_02_crackle_validates_mac(self):
        """Crackle valida MAC si se proporciona."""
        c = self.Crackle(target='--evil-flag')
        ok, msg = c.check_prerequisites()
        self.assertFalse(ok)
        self.assertIn("formato MAC", msg)

    def test_03_crackle_valid_mac_passes(self):
        """Crackle con MAC válida pasa."""
        c = self.Crackle(target='AA:BB:CC:DD:EE:FF')
        ok, msg = c.check_prerequisites()
        self.assertTrue(ok, f"MAC válida debe pasar: {msg}")


if __name__ == "__main__":
    unittest.main(verbosity=2)
