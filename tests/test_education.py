"""
Tests del modo educativo (BS-FEAT) — bluesky/core/education.py + integración
en console.py (educate) y cli.py (bluesky educate).

El modo educativo explica cada módulo paso a paso con foco defensivo:
qué es, cómo funciona, impacto y MITIGACIÓN.
"""

import io
import sys
import unittest
from contextlib import redirect_stdout
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from bluesky.core.education import (
    EDU_DB, get_education,
    format_education_plain, format_education_rich,
)
from bluesky.core.engine import ModuleEngine


class TestEducationDB(unittest.TestCase):
    """La base de conocimiento educativa debe cubrir todos los módulos."""

    @classmethod
    def setUpClass(cls):
        cls.engine = ModuleEngine()

    def test_01_covers_all_engine_modules(self):
        """Todo módulo del engine tiene entrada educativa (o alias válido)."""
        missing = []
        for info in self.engine.list_modules():
            name = info.get("name", "")
            if not name:
                continue
            if get_education(name) is None:
                missing.append(name)
        self.assertEqual(
            missing, [],
            f"Módulos del engine sin entrada educativa: {missing}")

    def test_02_entries_have_required_fields(self):
        required = {"title", "what", "how", "impact", "mitigation"}
        for name, entry in EDU_DB.items():
            for field in required:
                self.assertIn(field, entry, f"{name}: falta '{field}'")
                self.assertTrue(entry[field], f"{name}: '{field}' vacío")
            self.assertIsInstance(entry["how"], list)
            self.assertIsInstance(entry["mitigation"], list)
            # Cada mitigation debe ser una defensa (contenido accionable)
            for m in entry["mitigation"]:
                self.assertIsInstance(m, str)
                self.assertTrue(len(m) > 10, f"{name}: mitigación trivial")

    def test_03_get_education_normalizes_input(self):
        self.assertEqual(get_education("KNOB"), EDU_DB["knob"])
        self.assertEqual(get_education("attack/knob"), EDU_DB["knob"])
        self.assertEqual(get_education(" scanner/scan "), EDU_DB["scan"])
        self.assertEqual(get_education("keystroke_injection"),
                         EDU_DB["keystroke"])
        self.assertEqual(get_education("device_scanner"), EDU_DB["scan"])
        self.assertIsNone(get_education("__no_existe__"))
        self.assertIsNone(get_education(None))
        self.assertIsNone(get_education(123))

    def test_04_every_entry_mentions_mitigation_focus(self):
        """Cada entrada tiene al menos una mitigación sustantiva."""
        for name, entry in EDU_DB.items():
            self.assertGreaterEqual(
                len(entry["mitigation"]), 1,
                f"{name}: debe incluir mitigaciones")


class TestEducationRendering(unittest.TestCase):
    """Los formatters toleran datos y contextos (rich/no-rich)."""

    def test_05_plain_format_contains_all_sections(self):
        out = format_education_plain(EDU_DB["knob"])
        for section in ("QUÉ ES", "CÓMO FUNCIONA", "IMPACTO", "MITIGACIÓN"):
            self.assertIn(section, out)
        self.assertIn("CVE-2019-9506", out)

    def test_06_plain_format_tolerates_garbage(self):
        self.assertIn("Sin contenido", format_education_plain(None))
        self.assertIn("Sin contenido", format_education_plain({}))
        self.assertIn("Sin contenido", format_education_plain("junk"))

    def test_07_rich_format_runs_with_console(self):
        from rich.console import Console
        buf = io.StringIO()
        console = Console(file=buf, force_terminal=False, width=100)
        format_education_rich(EDU_DB["bias"], console)
        out = buf.getvalue()
        self.assertIn("BIAS", out)
        self.assertIn("Mitigación", out)


class TestConsoleIntegration(unittest.TestCase):
    """El comando 'educate' funciona dentro de la REPL."""

    def _console(self, plain: bool = True):
        from bluesky.console import BlueskyConsole
        c = BlueskyConsole()
        if plain:
            # Forzar salida plana: Rich Console no escribe en el buffer
            # capturado por redirect_stdout (mantiene su propio file).
            c.console = None
        return c

    def test_08_console_educate_index(self):
        c = self._console()
        buf = io.StringIO()
        with redirect_stdout(buf):
            c.do_educate("")
        out = buf.getvalue()
        self.assertIn("knob", out)
        self.assertIn("educate <módulo>", out)

    def test_09_console_educate_module(self):
        c = self._console()
        buf = io.StringIO()
        with redirect_stdout(buf):
            c.do_educate("bluejacking")
        out = buf.getvalue()
        self.assertIn("OBEX", out)
        self.assertIn("MITIGACIÓN", out)

    def test_10_console_educate_unknown_module(self):
        c = self._console()
        buf = io.StringIO()
        with redirect_stdout(buf):
            c.do_educate("__no_existe__")
        out = buf.getvalue()
        self.assertIn("Sin contenido educativo", out)

    def test_11_console_educate_tab_completion(self):
        c = self._console()
        completions = c.complete_educate("kn", "educate kn", 8, 10)
        self.assertIn("knob", completions)


class TestCLIIntegration(unittest.TestCase):
    """El comando CLI 'bluesky educate' está cableado en el dispatch."""

    def test_12_cli_route_registered(self):
        from bluesky import cli as cli_mod
        self.assertTrue(hasattr(cli_mod, "cmd_educate"))
        src = Path(cli_mod.__file__).read_text()
        self.assertIn('"educate": lambda: cmd_educate(args)', src)
        self.assertIn('"educate"', src)  # en no_banner también

    def test_13_cli_educate_index_runs(self):
        from bluesky import cli as cli_mod
        buf = io.StringIO()
        with redirect_stdout(buf):
            cli_mod.cmd_educate([])
        self.assertIn("MODO EDUCATIVO", buf.getvalue())

    def test_14_cli_educate_module_runs_offline(self):
        from bluesky import cli as cli_mod
        buf = io.StringIO()
        with redirect_stdout(buf):
            cli_mod.cmd_educate(["crackle"])
        out = buf.getvalue()
        self.assertIn("LTK", out)
        self.assertIn("MITIGACIÓN", out)


if __name__ == "__main__":
    unittest.main(verbosity=2)
