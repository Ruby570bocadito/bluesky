"""
Tests de regresión QA (ronda BS-QA).

Cada test reproduce un bug real confirmado con repro previo:
  - engine.run_module ejecutaba run() DOS veces ante un TypeError interno
  - check_prerequisites con AttributeError crasheaba el caller
  - device_scanner WinRT con NameError 'devices'
  - termux sin binario → UnboundLocalError json
  - reporter/format con items no-dict → AttributeError
  - config con shapes anidados malformados → AttributeError
  - btlejack/btspam con datos no serializables en result["data"]
  - rfcomm_shell con stderr en bytes
  - vuln_scanner con opciones None
  - platform.is_wsl con segunda lectura vacía de /proc/version
"""

import io
import json
import os
import sys
import types
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).parent.parent))

from bluesky.core.engine import BaseModule, ModuleEngine


MODULE_OPTIONS_NONE = {"SCAN_TYPE": None, "REPORT": None}


class TestEngineRunDispatch(unittest.TestCase):
    """engine.run_module: despacho de run() sin doble ejecución."""

    def _engine(self) -> ModuleEngine:
        return ModuleEngine(load_plugins=False)

    def test_01_no_double_execution_on_internal_typeerror(self):
        """Un TypeError DENTRO de run() no debe relanzar el módulo (doble ejecución)."""
        class Flaky(BaseModule):
            name = "flaky_qa"
            calls = 0

            def run(self, target=None, options=None):
                Flaky.calls += 1
                raise TypeError("error interno real de ejecución")

        eng = self._engine()
        eng._modules["flaky_qa"] = Flaky
        res = eng.run_module("flaky_qa", target="00:11:22:33:44:55")
        self.assertFalse(res["success"])
        self.assertEqual(Flaky.calls, 1, "run() se ejecutó más de una vez")

    def test_02_fallback_run_without_kwargs(self):
        """Plugins con run(self) sin kwargs siguen funcionando (fallback de binding)."""
        class Simple(BaseModule):
            name = "simple_qa"

            def run(self):
                return {"success": True, "data": {"ran": True}, "error": None}

        eng = self._engine()
        eng._modules["simple_qa"] = Simple
        res = eng.run_module("simple_qa", target="00:11:22:33:44:55")
        self.assertTrue(res["success"])
        self.assertTrue(res["data"]["ran"])

    def test_03_kwargs_passed_when_accepted(self):
        """target/options se pasan a run(target=..., options=...) cuando la firma los acepta."""
        class WithKwargs(BaseModule):
            name = "kwargs_qa"

            def run(self, target=None, options=None):
                return {"success": True, "data": {"target": target, "options": options},
                        "error": None}

        eng = self._engine()
        eng._modules["kwargs_qa"] = WithKwargs
        res = eng.run_module("kwargs_qa", target="00:11:22:33:44:55",
                             options={"K": "V"})
        self.assertTrue(res["success"])
        self.assertEqual(res["data"]["target"], "00:11:22:33:44:55")
        self.assertEqual(res["data"]["options"], {"K": "V"})

    def test_04_check_prerequisites_attributeerror_degrades_clean(self):
        """check_prerequisites con AttributeError (plataforma sin os.geteuid) no crashea."""
        class BrokenPrereq(BaseModule):
            name = "brokenprereq_qa"

            def check_prerequisites(self):
                raise AttributeError("module 'os' has no attribute 'geteuid'")

            def run(self, target=None, options=None):
                return {"success": True, "data": {}, "error": None}

        eng = self._engine()
        eng._modules["brokenprereq_qa"] = BrokenPrereq
        res = eng.run_module("brokenprereq_qa", target="00:11:22:33:44:55")
        self.assertTrue(res["success"])

    def test_05_l2cap_fuzz_prereq_on_windows_like_platform(self):
        """l2cap_fuzz.check_prerequisites no debe asumir os.geteuid en no-posix."""
        from bluesky.modules.exploits.l2cap_fuzz import L2CAPFuzz

        def no_euid(*a, **k):
            raise AttributeError("module 'os' has no attribute 'geteuid'")

        # Pasar target válido para que la validación MAC de BaseModule
        # no bloquee antes de llegar al check de root.
        with mock.patch.object(os, "name", "nt"), \
             mock.patch.object(os, "geteuid", no_euid):
            ok, msg = L2CAPFuzz(target="00:11:22:33:44:55").check_prerequisites()
        self.assertFalse(ok)
        self.assertIn("root", msg.lower())


class TestDeviceScannerWindows(unittest.TestCase):
    """device_scanner: ruta WinRT de Windows."""

    def test_06_winrt_scan_collects_classic_devices(self):
        """_scan_classic_windows_winrt debe definir 'devices' y recolectar (era NameError)."""
        from bluesky.modules.scanners.device_scanner import DeviceScanner

        scanner = DeviceScanner()
        fake = types.SimpleNamespace(
            returncode=0,
            stdout=json.dumps([{"Name": "BT Classic Dev", "Id": "XX_001122334455"}]),
            stderr="",
        )
        with mock.patch("subprocess.run", return_value=fake):
            out = scanner._scan_classic_windows_winrt(8)
        self.assertEqual(out, [{
            "mac": "00:11:22:33:44:55",
            "name": "BT Classic Dev",
            "type": "classic",
            "rssi": 0,
        }])


class TestTermuxPlatformUtils(unittest.TestCase):
    """utils/platform.py: detección unificada (termux.py legado eliminado)."""

    def test_07_is_termux_unified_detection(self):
        """La detección unificada de plataforma funciona sin crash."""
        from bluesky.utils.platform import is_termux, get_platform

        self.assertIsInstance(is_termux(), bool)
        self.assertIn(get_platform(), ("linux", "termux", "windows"))


class TestReporterShapes(unittest.TestCase):
    """reporter: items no-dict en targets/results de un JSON cargado a mano."""

    def test_08_to_txt_with_non_dict_targets(self):
        """to_txt tolera targets string/None (antes: AttributeError .get)."""
        from bluesky.core.reporter import Reporter

        r = Reporter({
            "session": {"name": "s"},
            "targets": ["AA:BB:CC:DD:EE:FF", None],
            "results": [{"module": "m", "target": "t", "success": True}],
        })
        out = r.to_txt()
        self.assertIn("AA:BB:CC:DD:EE:FF", out)
        self.assertIn("Attack Results", out)

    def test_09_to_html_with_non_dict_targets(self):
        """to_html tolera targets/results no-dict (antes: AttributeError)."""
        from bluesky.core.reporter import Reporter

        r = Reporter({
            "session": {"name": "s"},
            "targets": ["AA:BB:CC:DD:EE:FF"],
            "results": ["garbage", {"module": "m", "target": "t", "success": True}],
        })
        html = r.to_html()
        self.assertIn("bluesky Audit Report", html)
        self.assertIn("✅ Success", html)


class TestFormatShapes(unittest.TestCase):
    """utils/format.py: tolerancia a None y items no-dict."""

    def test_10_severity_icon_none_safe(self):
        """severity_icon(None) no revienta (antes: AttributeError .lower)."""
        from bluesky.utils.format import severity_icon, target_type_icon

        self.assertEqual(severity_icon(None), "⚪")
        self.assertEqual(severity_icon("high"), "🟠")
        self.assertEqual(target_type_icon(None), "📡")

    def test_11_format_device_list_non_dict(self):
        """format_device_list tolera items no-dict (antes: AttributeError)."""
        from bluesky.utils.format import format_device_list

        out = format_device_list(["AA:BB:CC:DD:EE:FF", {"name": "Dev", "mac": "00:11:22:33:44:55"}])
        self.assertIn("AA:BB:CC:DD:EE:FF", out)
        self.assertIn("Dev", out)


class TestConfigShapes(unittest.TestCase):
    """config: shapes anidados malformados."""

    def test_12_get_module_option_non_dict(self):
        """module_options con valor no-dict devuelve default (antes: AttributeError)."""
        from bluesky.utils.config import BlueskyConfig

        BlueskyConfig.reset_instance()
        try:
            cfg = BlueskyConfig()
            cfg.load()
            cfg._config["module_options"] = {"knob": 5}
            self.assertIsNone(cfg.get_module_option("knob", "timeout"))
            self.assertEqual(cfg.get_module_option("knob", "timeout", 30), 30)
        finally:
            BlueskyConfig.reset_instance()

    def test_13_add_favorite_with_non_dict_entries(self):
        """favorites con entradas no-dict no revienta add/remove_favorite."""
        from bluesky.utils.config import BlueskyConfig

        BlueskyConfig.reset_instance()
        try:
            cfg = BlueskyConfig()
            cfg.load()
            cfg._config["favorites"] = ["AA:BB:CC:DD:EE:FF", None]
            cfg.add_favorite("00:11:22:33:44:55", "lab")
            favs = cfg.get_favorites()
            # Las entradas malformadas se descartan al normalizar
            self.assertEqual(len(favs), 1)
            self.assertEqual(favs[0]["address"], "00:11:22:33:44:55")
            cfg.remove_favorite("00:11:22:33:44:55")
            self.assertEqual(len(cfg.get_favorites()), 0)
        finally:
            BlueskyConfig.reset_instance()


class TestModuleDataShapes(unittest.TestCase):
    """result["data"] de los módulos debe ser JSON-serializable."""

    def test_14_btlejack_sniff_data_serializable(self):
        """btlejack sniff: data del resultado es JSON-serializable."""
        import tempfile
        from bluesky.modules.attacks import btlejack as bj_mod

        out_dir = Path(tempfile.mkdtemp(prefix="bs_qa_btlejack_"))
        m = bj_mod.BTLEJack(options={
            "MODE": "sniff", "ACCESS_ADDRESS": "8E89BED6",
            "OUTPUT": str(out_dir)})

        # Simular (solo en test) la presencia y salida de la herramienta real
        with mock.patch.object(
                bj_mod.BTLEJack, "_btlejack_available", return_value=True), \
             mock.patch.object(
                m, "_run_tool",
                return_value={"returncode": 0, "stdout": "sniffed 12 packets\n", "stderr": ""}):
            res = m.run()
        try:
            self.assertTrue(res["success"])
            # data debe ser serializable (salida de herramienta = strings)
            json.dumps(res["data"])
            self.assertIn("capture_file", res["data"])
        finally:
            for f in ("btlejack_sniff.txt",):
                p = out_dir / f
                if p.exists():
                    p.unlink()
            out_dir.rmdir()

    def test_15_btspam_stats_serializable(self):
        """btspam: stats sin sets (antes: TypeError al serializar)."""
        from bluesky.modules.attacks.btspam import BTSpam

        m = BTSpam(target="00:11:22:33:44:55",
                   options={"COUNT": "1", "DURATION": "1", "DELAY": "0"})
        res = m.run()
        self.assertIn("stats", res["data"])
        # Antes: stats["targets_hit"] era un set → TypeError en json.dumps
        json.dumps(res["data"]["stats"])
        self.assertIsInstance(res["data"]["stats"]["targets_hit"], list)

    def test_16_btspam_prereq_without_subprocess(self):
        """btspam.check_prerequisites no debe lanzar 'which' vía subprocess."""
        from bluesky.modules.attacks.btspam import BTSpam

        def fail(*a, **k):
            raise AssertionError("check_prerequisites no debe usar subprocess")

        with mock.patch("subprocess.run", fail):
            ok, _msg = BTSpam().check_prerequisites()
        self.assertTrue(ok)

    def test_17_vuln_scanner_none_options(self):
        """vuln_scanner con opciones None (JSON null) no revienta."""
        from bluesky.modules.scanners.vuln_scanner import VulnScanner

        m = VulnScanner(target="00:11:22:33:44:55",
                        options={"SCAN_TYPE": None, "REPORT": None})
        res = m.run()
        self.assertTrue(res["success"])
        self.assertEqual(res["data"]["scan_type"], "full")


class TestMiscRegressions(unittest.TestCase):
    """Otros fixes de la ronda QA."""

    def test_18_is_wsl_reads_proc_version_once(self):
        """is_wsl lee /proc/version una sola vez (el 2º read vacío mataba el check 'wsl')."""
        import platform as platform_mod
        from bluesky.utils import platform as bs_platform

        real_open = io.open
        data = "Linux version 6.6.07-WSL2-custom (root@wsl) #1 SMP"

        class FakeFile(io.StringIO):
            def __enter__(self):
                return self

            def __exit__(self, *args):
                return False

        opened = []

        def fake_open(path, *a, **k):
            opened.append(str(path))
            if str(path) == "/proc/version":
                return FakeFile(data)
            return real_open(path, *a, **k)

        with mock.patch.object(bs_platform.platform, "system", return_value="Linux"), \
             mock.patch.object(bs_platform, "_is_termux", return_value=False), \
             mock.patch("builtins.open", fake_open):
            self.assertTrue(bs_platform.is_wsl())
        self.assertEqual(opened.count("/proc/version"), 1)
        del platform_mod

    def test_19_rfcomm_listen_error_is_str(self):
        """rfcomm_shell._listen_rfcomm decodifica stderr bytes a str."""
        from bluesky.modules.exploits.rfcomm_shell import RfcommShell

        fake_proc = types.SimpleNamespace(poll=lambda: 1)

        def fake_communicate(timeout=None):
            return (b"", b"rfcomm: Can't bind socket: Address already in use")

        fake_proc.communicate = fake_communicate
        m = RfcommShell()
        with mock.patch("subprocess.Popen", return_value=fake_proc):
            res = m._listen_rfcomm("00:11:22:33:44:55", 1)
        self.assertIsInstance(res.get("error"), str)
        self.assertIn("Address already in use", res["error"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
