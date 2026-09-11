"""
Tests de regresión QA ronda 1 (BS-QA) — bugs confirmados con repro.

Cada test reproduce un bug real verificado en /tmp/bs_qa_repros/:
  - int() de opciones en __init__ de módulos → ValueError escapaba run_module
  - BaseModule._opt_int: lectura numérica tolerante de opciones
  - Session con JSON malformado (targets/results no-dict)
  - Reporter.to_txt con services/vulnerabilities no-dict
  - config.set_module_option con module_options malformado
  - device_scanner: timeout malformado + inyección PowerShell vía MAC
  - keystroke_injection: falso positivo "Keystrokes injected" sin /dev/hidg0
  - bluejacking: fuga de .vcf temporales cuando el subprocess expira
  - btlejack: canal no numérico en hijack
  - crackle: PIN no numérico
  - windows_backend.enable_bluetooth_windows devolvía None en vez de bool
"""

import json
import os
import re
import subprocess
import sys
import tempfile
import threading
import types
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).parent.parent))

from bluesky.core.engine import BaseModule, ModuleEngine

LAB_MAC = "00:11:22:33:44:55"


class TestEngineConstruction(unittest.TestCase):
    """engine.run_module: __init__ de módulos con opciones malformadas."""

    def test_01_construction_valueerror_degrades_clean(self):
        """ValueError en __init__ no debe escapar run_module (crasheaba la CLI)."""
        class BadInit(BaseModule):
            name = "badinit_qa"

            def __init__(self, target: str = "", options: dict = None):
                super().__init__(target, options)
                int((options or {}).get("N", "0"))  # ValueError con N no numérico

            def run(self):
                return {"success": True, "data": {}, "error": None}

        eng = ModuleEngine(load_plugins=False)
        eng._modules["badinit_qa"] = BadInit
        # Antes: ValueError: invalid literal for int() with base 10: 'x'
        res = eng.run_module("badinit_qa", target=LAB_MAC, options={"N": "x"})
        self.assertFalse(res["success"])
        self.assertIn("Opciones inválidas", res.get("error", ""))

    def test_02_opt_int_helper(self):
        """BaseModule._opt_int tolera malformados y preserva 0 explícito."""
        m = BaseModule(target=LAB_MAC, options={
            "A": "abc", "B": None, "C": "", "D": "0", "E": "7", "F": 3,
        })
        self.assertEqual(m._opt_int("A", 10), 10)   # no numérico → default
        self.assertEqual(m._opt_int("B", 10), 10)   # None → default
        self.assertEqual(m._opt_int("C", 10), 10)   # vacío → default
        self.assertEqual(m._opt_int("D", 10), 0)    # 0 explícito se respeta
        self.assertEqual(m._opt_int("E", 10), 7)
        self.assertEqual(m._opt_int("F", 10), 3)    # int nativo
        self.assertEqual(m._opt_int("MISSING", 42), 42)


class TestModuleOptionParsing(unittest.TestCase):
    """Módulos con int() de opciones en __init__ (crash al construir)."""

    def test_03_knob_bad_force_key_size(self):
        """Knob(FORCE_KEY_SIZE='abc') no debe lanzar ValueError (default 1)."""
        from bluesky.modules.attacks.knob import Knob

        m = Knob(target=LAB_MAC, options={"FORCE_KEY_SIZE": "abc"})
        self.assertEqual(m._force_key_size, 1)
        # None también degrada al default
        self.assertEqual(Knob(target=LAB_MAC, options={"FORCE_KEY_SIZE": None})._force_key_size, 1)

    def test_04_sweyntooth_bad_scan_duration(self):
        """Sweyntooth(SCAN_DURATION='not-a-number') usa el default 10."""
        from bluesky.modules.attacks.sweyntooth import Sweyntooth

        m = Sweyntooth(target=LAB_MAC, options={"SCAN_DURATION": "not-a-number"})
        self.assertEqual(m._scan_duration, 10)

    def test_05_bluefrag_bad_counts(self):
        """BlueFrag con PACKET_COUNT/CHANNEL/TIMEOUT malformados usa defaults."""
        from bluesky.modules.attacks.bluefrag import BlueFrag

        m = BlueFrag(target=LAB_MAC, options={
            "PACKET_COUNT": "many", "CHANNEL": "x", "TIMEOUT": None,
        })
        self.assertEqual(m._packet_count, 100)
        self.assertEqual(m._channel, 38)
        self.assertEqual(m._timeout, 30)

    def test_06_btlejack_timeout_none_keeps_target(self):
        """btlejack(TIMEOUT=None) no debe descartar target/opciones (antes TypeError)."""
        from bluesky.modules.attacks.btlejack import BTLEJack

        m = BTLEJack(target=LAB_MAC, options={"TIMEOUT": None, "MODE": "scan"})
        self.assertEqual(m._timeout, 30)
        # El target se parseó correctamente (antes el fallback cls() lo perdía)
        self.assertEqual(m._master_addr, LAB_MAC)

    def test_07_crackle_bad_max_pin(self):
        """Crackle(MAX_PIN='') usa el default 999999 (antes ValueError)."""
        from bluesky.modules.attacks.crackle import Crackle

        m = Crackle(target=LAB_MAC, options={"MAX_PIN": ""})
        self.assertEqual(m._max_pin, 999999)

    def test_08_crackle_pin_non_numeric_message(self):
        """_bruteforce_ltk con PIN no numérico retorna mensaje, no ValueError."""
        from bluesky.modules.attacks.crackle import Crackle

        m = Crackle(options={"PCAP_FILE": "x.pcap", "PIN": "not-a-pin"})
        packets = [
            {"type": "confirm", "value": "a" * 32},
            {"type": "random", "value": "b" * 32},
            {"type": "confirm", "value": "c" * 32},
            {"type": "random", "value": "d" * 32},
        ]
        res = m._bruteforce_ltk(packets)  # Antes: ValueError: invalid literal
        self.assertFalse(res["success"])
        self.assertIn("PIN inválido", res["message"])

    def test_09_btlejack_hijack_bad_channel(self):
        """_simulate_hijack con canal no numérico degrada a canal aleatorio."""
        from bluesky.modules.attacks.btlejack import BTLEJack

        m = BTLEJack(target=LAB_MAC, options={"MODE": "hijack", "CHANNEL": "0x25"})
        sim = m._simulate_hijack()  # Antes: ValueError: invalid literal for int()
        self.assertIsInstance(sim["channel"], int)
        self.assertTrue(0 <= sim["channel"] <= 36)

    def test_10_btspam_method_none_and_bad_numbers(self):
        """btspam.run() con METHOD=None y números malformados no revienta."""
        from bluesky.modules.attacks.btspam import BTSpam

        m = BTSpam(target=LAB_MAC, options={
            "METHOD": None, "RATE": "abc", "COUNT": "1",
            "DURATION": "1", "DELAY": "0",
        })
        # Antes: AttributeError: 'NoneType' object has no attribute 'lower'
        res = m.run()
        self.assertTrue(res["success"])
        self.assertEqual(res["data"]["methods"],
                         ["pairing_flood", "obex_spam", "connection_flood"])
        json.dumps(res["data"]["stats"])

    def test_11_btspam_stats_lock_exact_totals(self):
        """Los contadores de _stats son exactos bajo concurrencia (lock)."""
        from bluesky.modules.attacks.btspam import BTSpam

        m = BTSpam(target=LAB_MAC, options={})
        old_interval = sys.getswitchinterval()
        sys.setswitchinterval(1e-6)
        try:
            def worker():
                for _ in range(2000):
                    m._stat_inc("pairing_sent")
                    m._stat_hit(LAB_MAC)

            threads = [threading.Thread(target=worker) for _ in range(8)]
            for t in threads:
                t.start()
            for t in threads:
                t.join()
        finally:
            sys.setswitchinterval(old_interval)
        self.assertEqual(m._stats["pairing_sent"], 8 * 2000)
        self.assertEqual(m._stats_snapshot()["targets_hit"], [LAB_MAC])


class TestSessionMalformed(unittest.TestCase):
    """Session con JSON cargado a mano (targets/results malformados)."""

    def test_12_add_target_and_summary_with_malformed_data(self):
        """targets string / sin 'mac' y results string no revientan."""
        from bluesky.core.session import Session

        with tempfile.TemporaryDirectory() as td:
            data = {
                "name": "broken",
                "targets": [
                    "AA:BB:CC:DD:EE:FF",               # string (antes KeyError)
                    {"name": "sin-mac"},               # dict sin 'mac'
                    {"mac": LAB_MAC, "rssi": -50},
                ],
                "results": ["garbage", {"module": "m", "success": True}],
            }
            (Path(td) / "broken.json").write_text(json.dumps(data))

            s = Session("broken", base_dir=td)
            self.assertTrue(s.load())
            # Antes: TypeError: string indices must be integers
            t = s.add_target(LAB_MAC, "recon")
            self.assertEqual(t["mac"], LAB_MAC)
            # Antes: AttributeError: 'str' object has no attribute 'get'
            summary = s.summary()
            self.assertEqual(summary["successful_attacks"], 1)
            self.assertEqual(summary["failed_attacks"], 0)


class TestReporterNestedShapes(unittest.TestCase):
    """reporter.to_txt: services/vulnerabilities no-dict dentro de un target."""

    def test_13_to_txt_with_nested_non_dict(self):
        """Servicios/vulns como strings no revientan to_txt (antes AttributeError)."""
        from bluesky.core.reporter import Reporter

        r = Reporter({
            "session": {"name": "s"},
            "targets": [{
                "name": "dev", "mac": LAB_MAC, "rssi": -50,
                "services": ["Obex FTP"],              # string, no dict
                "vulnerabilities": ["CVE-2020-0022"],  # string, no dict
            }],
            "results": [],
        })
        out = r.to_txt()
        self.assertIn("Obex FTP", out)
        self.assertIn("CVE-2020-0022", out)


class TestConfigSetModuleOption(unittest.TestCase):
    """config.set_module_option con module_options malformado."""

    def test_14_set_module_option_rebuilds_malformed_shapes(self):
        """"knob": "junk" y module_options=42 no lanzan TypeError."""
        from bluesky.utils.config import BlueskyConfig

        BlueskyConfig.reset_instance()
        try:
            cfg = BlueskyConfig()
            cfg._loaded = True  # evitamos que get() re-cargue defaults
            cfg._config = {"module_options": {"knob": "junk-no-dict"}}
            cfg.set_module_option("knob", "timeout", 60)
            self.assertEqual(cfg.get_module_option("knob", "timeout"), 60)

            cfg._config = {"module_options": 42}
            cfg.set_module_option("knob", "timeout", 61)
            self.assertEqual(cfg.get_module_option("knob", "timeout"), 61)
        finally:
            BlueskyConfig.reset_instance()


class TestDeviceScannerHardening(unittest.TestCase):
    """device_scanner: timeout malformado + sanitización de MAC en PowerShell."""

    def test_15_run_with_bad_timeout(self):
        """run() con timeout='abc' degrada a 8 (antes ValueError en run)."""
        from bluesky.modules.scanners.device_scanner import DeviceScanner

        s = DeviceScanner(target="", options={"timeout": "abc"})
        res = s.run()  # Antes: ValueError: invalid literal for int()
        self.assertIn("scan_time", res["data"])
        self.assertEqual(res["data"]["scan_time"], 8)

    def test_16_run_with_null_type(self):
        """run() con type=None usa 'all' en lugar de escanear nada."""
        from bluesky.modules.scanners.device_scanner import DeviceScanner

        s = DeviceScanner(target="", options={"type": None})
        res = s.run()
        self.assertEqual(res["data"]["scan_type"], "all")

    def test_17_windows_ps_script_sanitizes_mac(self):
        """La MAC se sanitiza a hex antes de interpolarse en el script PS."""
        from bluesky.modules.scanners.device_scanner import DeviceScanner

        captured = {}

        def fake_run(cmd, *a, **k):
            captured["script"] = cmd[-1]
            return types.SimpleNamespace(returncode=0, stdout="", stderr="")

        evil_mac = "AA:BB:CC'; Start-Process calc; '"
        s = DeviceScanner(target="")
        with mock.patch("subprocess.run", fake_run):
            s._get_device_info_windows(evil_mac)

        script = captured["script"]
        # Antes: el script PS contenía el payload tal cual (inyección de comandos)
        self.assertNotIn("Start-Process", script)
        self.assertNotIn(";", script)
        self.assertNotIn("calc", script.lower())
        # Los operandos -like '*...*' solo pueden contener hex sanitizado
        operands = re.findall(r"'\*([^']*)\*'", script)
        self.assertTrue(operands)
        for op in operands:
            self.assertRegex(op, r"(?i)^aabbcc[0-9a-f]*$")


class TestKeystrokeHonestReporting(unittest.TestCase):
    """keystroke_injection: sin falsos positivos cuando /dev/hidg0 no existe."""

    def _fake_check_env(self):
        """Parchea subprocess.run: bluetoothctl responde 'HID', gatttool no existe."""
        class FakeProc:
            returncode = 0
            stdout = "Powered: yes\nHID: yes\n"
            stderr = ""

        def fake_run(cmd, *a, **kw):
            if cmd and cmd[0] == "gatttool":
                raise FileNotFoundError("gatttool")
            return FakeProc()

        return fake_run

    def test_18_no_false_positive_bluez_hid(self):
        """Sin /dev/hidg0 y sin gatttool, NO reporta 'Keystrokes injected'."""
        from bluesky.modules.exploits.keystroke_injection import KeystrokeInjection

        assert not os.path.exists("/dev/hidg0"), "el test requiere no tener /dev/hidg0"
        m = KeystrokeInjection(target=LAB_MAC, options={"payload": "hi"})
        real = subprocess.run
        subprocess.run = self._fake_check_env()
        try:
            res = m.run()
        finally:
            subprocess.run = real
        # Antes: method='bluez_hid' success=True con 0 teclas entregadas
        self.assertNotEqual(res["data"].get("method"), "bluez_hid")
        self.assertEqual(res["data"].get("method"), "payload_generated")

    def test_19_ble_hid_empty_text_returns_false(self):
        """_inject_ble_hid('') es False (antes True: falso positivo)."""
        from bluesky.modules.exploits.keystroke_injection import KeystrokeInjection

        m = KeystrokeInjection(target=LAB_MAC, options={})
        self.assertFalse(m._inject_ble_hid(LAB_MAC, ""))


class TestBluejackingTempLeak(unittest.TestCase):
    """bluejacking: los .vcf temporales se limpian aunque el envío expire."""

    def test_20_no_temp_file_leak_on_timeout(self):
        """TimeoutExpired no deja el .vcf en el tmpdir (antes: 1 fichero filtrado)."""
        from bluesky.modules.attacks.bluejacking import Bluejacking

        tmpdir = tempfile.gettempdir()
        before = set(Path(tmpdir).glob("*.vcf"))

        def fake_run(*a, **k):
            raise subprocess.TimeoutExpired(cmd="bluetooth-sendto", timeout=10)

        m = Bluejacking(target=LAB_MAC, options={})
        real = subprocess.run
        subprocess.run = fake_run
        try:
            ok = m._obex_push(LAB_MAC, "msg")
        finally:
            subprocess.run = real
        self.assertFalse(ok)
        leaked = set(Path(tmpdir).glob("*.vcf")) - before
        self.assertEqual(leaked, set(), f"ficheros filtrados: {leaked}")


class TestWindowsBackendBool(unittest.TestCase):
    """windows_backend.enable_bluetooth_windows debe devolver bool."""

    def test_21_enable_returns_bool(self):
        """Sin PowerShell devuelve False (antes None)."""
        from bluesky.utils import windows_backend as wb

        with mock.patch.object(wb, "_run_powershell", return_value=None):
            res = wb.enable_bluetooth_windows()
        self.assertIs(res, False)


class TestScapyCompatAndContract(unittest.TestCase):
    """Compatibilidad scapy 2.7 y shape uniforme de run_module."""

    def test_22_btlejack_scapy_available_with_scapy_27(self):
        """Con scapy 2.7 instalado, btlejack detecta scapy (nombres *_IND)."""
        try:
            import scapy
            _scapy_probe = bool(scapy)  # sondeo de disponibilidad
        except ImportError:
            self.skipTest("scapy no instalado en este entorno")
        del _scapy_probe
        from bluesky.modules.attacks import btlejack

        # Antes: ImportError por LL_DATA/LL_CONNECTION_UPDATE_REQ/LL_CHANNEL_MAP_REQ
        # → SCAPY_AVAILABLE=False con scapy instalado (degradación silenciosa).
        self.assertTrue(btlejack.SCAPY_AVAILABLE)

    def test_23_run_module_result_shape_uniform(self):
        """Todos los resultados de run_module comparten success/data/error."""
        eng = ModuleEngine(load_plugins=False)
        casos = [
            eng.run_module("no_existe_xyz"),                      # no encontrado
            eng.run_module("knob", target=LAB_MAC),               # prereqs fallan
            eng.run_module("crackle", target=LAB_MAC),            # ejecución ok
        ]
        for res in casos:
            self.assertIsInstance(res, dict)
            self.assertIn("success", res)
            self.assertIn("data", res)
            self.assertIsInstance(res["data"], dict)
            self.assertIn("error", res)


if __name__ == "__main__":
    unittest.main(verbosity=2)
