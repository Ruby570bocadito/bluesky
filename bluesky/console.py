#!/usr/bin/env python3
"""
Bluesky Console - Modo interactivo REPL
========================================
Consola interactiva tipo Metasploit para auditoría Bluetooth.

Comandos:
  use <modulo>       → Seleccionar módulo
  set <opcion> <val> → Configurar opción
  run [target]       → Ejecutar módulo
  show [options]     → Mostrar opciones
  scan               → Escanear dispositivos
  list               → Listar módulos
  info               → Info del módulo seleccionado
  session            → Gestionar sesiones
  report             → Generar reporte
  help               → Ayuda
  exit               → Salir
"""

import sys
import os
import cmd
import shlex
from pathlib import Path

# Asegurar path
_THIS_DIR = Path(__file__).parent.parent
if str(_THIS_DIR) not in sys.path:
    sys.path.insert(0, str(_THIS_DIR))

try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich.syntax import Syntax
    from rich.markdown import Markdown
    from rich import print as rprint
    from rich.prompt import Prompt
    from rich.layout import Layout
    RICH_AVAILABLE = True
except ImportError:
    RICH_AVAILABLE = False

from bluesky.core.engine import ModuleEngine
from bluesky.core.session import Session
from bluesky.core.hardware import HardwareDetector
from bluesky.core.reporter import Reporter
from bluesky.utils.format import colorize, separator, severity_icon, target_type_icon
from bluesky.utils.config import get_config, parse_key_value


class BlueskyConsole(cmd.Cmd):
    """Consola interactiva Bluesky estilo Metasploit."""

    intro = ""
    prompt = "bluesky > "

    def __init__(self):
        super().__init__()
        self.engine = ModuleEngine()
        self.session = Session("console_session")
        self.current_module = None
        self.current_module_cls = None
        self.current_module_info = None
        self.module_options = {}
        self.module_target = ""
        self.targets_cache = []
        self.console = Console() if RICH_AVAILABLE else None
        # Cargar configuración
        self.config = get_config()
        # Precargar favorites como targets
        for fav in self.config.get_favorites():
            self.targets_cache.append({
                "name": fav.get("name", fav.get("address", "")),
                "mac": fav.get("address", ""),
                "type": fav.get("type", "auto"),
            })

    def preloop(self):
        """Mostrar intro al iniciar."""
        if self.console:
            self.console.print(self.intro, style="bold cyan")
            self._show_status_bar()
        else:
            print(self.intro)

    def _get_prompt(self) -> str:
        """Prompt contextual que muestra el módulo activo."""
        mod = self.current_module or ""
        if mod:
            return f"bluesky ({mod}) > "
        return "bluesky > "

    @property
    def prompt(self):
        return self._get_prompt()

    def _show_status_bar(self):
        """Muestra barra de estado."""
        if not self.console:
            return
        mod_name = self.current_module or "none"
        target = self.module_target or "not set"
        n_mods = len(self.engine.list_modules())
        status = f"[bold]Module:[/] [cyan]{mod_name}[/]  "
        status += f"[bold]Target:[/] [yellow]{target}[/]  "
        status += f"[bold]Modules:[/] [green]{n_mods}[/]"
        self.console.print(Panel(status, style="dim"))

    # ─── Comandos principales ──────────────────────────────

    def completedefault(self, *args):
        """Tab-completion para nombres de módulos."""
        if len(args) == 2 and args[0]:
            text = args[0]
            mods = self.engine.list_modules()
            return [
                m.get("name", "") for m in mods
                if m.get("name", "").startswith(text.lower())
            ]
        return []

    def do_use(self, arg):
        """use <módulo> - Seleccionar un módulo para usar"""
        if not arg:
            print("  Uso: use <module_name>")
            print("  Módulos disponibles:")
            self.do_list("")
            return

        cls = self.engine.get_module(arg)
        if not cls:
            print(f"  {colorize('✘', 'red')} Módulo '{arg}' no encontrado")
            print(f"  Usa 'list' para ver módulos disponibles")
            return

        self.current_module = arg
        self.current_module_cls = cls
        inst = cls()
        self.current_module_info = inst.get_info()
        self.module_options = {}
        # Precargar opciones por defecto del módulo
        for opt_key in self.current_module_info.get("module_options", {}):
            if opt_key.upper() not in ("TARGET", "RHOST"):
                self.module_options[opt_key.lower()] = ""
        self.module_target = ""
        print(f"  {colorize('✅', 'green')} Módulo '{arg}' seleccionado")

        # Guardar sesión
        self.session.name = f"session_{arg}"

        # Mostrar info básica
        info = self.current_module_info
        if self.console:
            self.console.print(Panel(
                f"[bold]{info.get('name')}[/] - {info.get('description')}\n"
                f"Severity: {severity_icon(info.get('severity',''))} {info.get('severity','').title()}  |  "
                f"Target: {target_type_icon(info.get('target_type',''))} {info.get('target_type','').upper()}  |  "
                f"CVE: {info.get('cve', 'N/A')}\n"
                f"Hardware: {', '.join(info.get('requires_hardware',[])) or 'None'}  |  "
                f"Root: {'Yes' if info.get('requires_root') else 'No'}",
                title=f"[bold cyan]Module: {arg}[/]",
                border_style="cyan"
            ))

    def do_back(self, arg):
        """back - Deseleccionar el módulo actual"""
        self.current_module = None
        self.current_module_cls = None
        self.current_module_info = None
        self.module_options = {}
        self.module_target = ""
        print(f"  {colorize('⬅', 'yellow')} Módulo deseleccionado")

    def do_set(self, arg):
        """set <opción> <valor> - Configurar opción del módulo actual"""
        if not arg:
            print("  Uso: set <option> <value>")
            print("  Opciones comunes: TARGET, RHOST, RPORT, etc.")
            return

        parts = shlex.split(arg)
        if len(parts) < 2:
            print("  Uso: set <option> <value>")
            return

        key = parts[0].upper()
        value = " ".join(parts[1:])

        if key == "TARGET" or key == "RHOST":
            self.module_target = value
            print(f"  {colorize('✅', 'green')} TARGET => {value}")
        else:
            self.module_options[key.lower()] = value
            # Persistir en config
            if self.current_module:
                self.config.set_module_option(self.current_module, key.lower(), value)
            print(f"  {colorize('✅', 'green')} {key} => {value}")

    def do_run(self, arg):
        """run [target] - Ejecutar el módulo seleccionado"""
        if not self.current_module:
            print(f"  {colorize('✘', 'red')} No hay módulo seleccionado")
            print(f"  Usa 'use <módulo>' primero")
            return

        target = arg or self.module_target

        if not target:
            print(f"  {colorize('⚠️', 'yellow')} Sin target. Ejecutando modo discovery...")
            print()

        if self.console:
            self.console.print(f"[bold]Running module:[/] [cyan]{self.current_module}[/]")
            if target:
                self.console.print(f"[bold]Target:[/] [yellow]{target}[/]")
            if self.module_options:
                self.console.print(f"[bold]Options:[/] {self.module_options}")

        result = self.engine.run_module(
            self.current_module,
            target=target,
            options=self.module_options
        )

        # Mostrar resultado
        self._display_result(result)

        # Guardar en sesión
        self.session.add_result(
            self.current_module,
            target or "auto",
            result.get("success", False),
            result.get("data", {}),
            result.get("error")
        )

    def _display_result(self, result: dict):
        """Muestra resultado del módulo usando Rich o texto plano."""
        data = result.get("data", {})
        error = result.get("error")

        if self.console:
            # Panel principal
            if result.get("success"):
                self.console.print(Panel(
                    "[green]Module executed successfully[/]",
                    title="Result", border_style="green"
                ))
            else:
                self.console.print(Panel(
                    "[yellow]Module completed with notes[/]",
                    title="Result", border_style="yellow"
                ))

            # Mostrar mensajes/vulnerabilidades
            for key in ("message", "warning", "summary", "risk", "info", "help"):
                val = data.get(key)
                if val and isinstance(val, str) and len(val) > 3:
                    self.console.print(Panel(val, border_style="dim"))

            # Tabla de vulnerabilidades
            vulns = data.get("vulnerabilities", [])
            if vulns:
                table = Table(title="Vulnerabilities Detected", border_style="red")
                table.add_column("Name", style="cyan")
                table.add_column("Severity", style="bold")
                table.add_column("CVE", style="dim")
                for v in vulns:
                    table.add_row(
                        v.get("name", ""),
                        severity_icon(v.get("severity", "")) + " " + v.get("severity", "").title(),
                        v.get("cve", v.get("detail", ""))
                    )
                self.console.print(table)

            # Tabla de dispositivos
            devices = data.get("devices", [])
            if devices:
                table = Table(title="Devices Found", border_style="blue")
                table.add_column("#", style="dim")
                table.add_column("Name", style="cyan")
                table.add_column("MAC", style="green")
                table.add_column("Type", style="yellow")
                for i, d in enumerate(devices, 1):
                    table.add_row(
                        str(i),
                        d.get("name", "?"),
                        d.get("mac", "N/A"),
                        d.get("type", "?")
                    )
                self.console.print(table)

            # Dispositivos vulnerables
            vdevs = data.get("vulnerable_devices", [])
            if vdevs:
                table = Table(title="Vulnerable Devices", border_style="red")
                table.add_column("Device", style="cyan")
                table.add_column("MAC", style="green")
                table.add_column("Risk", style="bold")
                for vd in vdevs:
                    table.add_row(
                        vd.get("name", "?"),
                        vd.get("mac", "N/A"),
                        vd.get("status", "VULNERABLE")
                    )
                self.console.print(table)

        else:
            # Fallback a texto plano
            if result.get("success"):
                print(f"  {colorize('✅', 'green')} Módulo ejecutado")
            for key in ("message", "warning", "summary", "risk", "help"):
                val = data.get(key)
                if val and isinstance(val, str):
                    for line in val.split("\n"):
                        if line.strip():
                            print(f"  {line.strip()}")

        if error and not result.get("success"):
            print(f"  {colorize(f'✘ {error}', 'red')}")
        print()

    # ─── Comandos de información ───────────────────────────

    def do_list(self, arg):
        """list - Listar todos los módulos disponibles"""
        modules = self.engine.list_modules()

        if self.console:
            # Agrupar por severidad
            by_sev = {}
            for m in modules:
                s = m.get("severity", "low")
                by_sev.setdefault(s, []).append(m)

            table = Table(title=f"Available Modules ({len(modules)} total)", border_style="cyan")
            table.add_column("", style="bold", width=2)
            table.add_column("Name", style="cyan", width=16)
            table.add_column("Type", width=6)
            table.add_column("Description", style="white")
            table.add_column("CVE", style="dim")

            for severity in ["critical", "high", "medium", "low"]:
                for m in by_sev.get(severity, []):
                    table.add_row(
                        severity_icon(severity),
                        m.get("name", ""),
                        target_type_icon(m.get("target_type", "")),
                        m.get("description", "")[:55],
                        m.get("cve", "")[:25]
                    )
            self.console.print(table)
        else:
            print(f"\n  {colorize(f'{len(modules)} módulo(s) disponible(s)', 'bold')}\n")
            for m in modules:
                print(f"  {severity_icon(m.get('severity',''))} {colorize(m.get('name',''), 'green'):15} {m.get('description','')[:60]}")
        print()

    def do_search(self, arg):
        """search <keyword> - Buscar módulos por nombre, CVE, descripción o palabra clave"""
        if not arg:
            print("  Uso: search <keyword>")
            print("  Ej: search knob, search blueborne, search cve-2023, search ble")
            return

        query = arg.lower().strip()
        modules = self.engine.list_modules()
        results = []

        for m in modules:
            name = m.get("name", "").lower()
            desc = m.get("description", "").lower()
            cve = m.get("cve", "").lower()
            author = m.get("author", "").lower()
            mod_type = m.get("target_type", "").lower()

            if (query in name or query in desc or query in cve
                    or query in author or query in mod_type or query in m.get("severity", "")):
                results.append(m)

        if not results:
            print(f"  {colorize('✘', 'yellow')} No se encontraron módulos para: '{arg}'")
            return

        if self.console:
            table = Table(title=f"Search Results: '{arg}' ({len(results)} matches)", border_style="cyan")
            table.add_column("", width=2)
            table.add_column("Name", style="cyan", width=16)
            table.add_column("Type", width=6)
            table.add_column("Description", width=50)
            table.add_column("CVE", style="dim", width=20)
            for m in results:
                table.add_row(
                    severity_icon(m.get("severity", "")),
                    m.get("name", ""),
                    target_type_icon(m.get("target_type", "")),
                    m.get("description", "")[:48],
                    m.get("cve", "")[:18]
                )
            self.console.print(table)
        else:
            print(f"\n  {colorize(f'{len(results)} resultado(s) para: {arg}', 'bold')}\n")
            for m in results:
                print(f"  {severity_icon(m.get('severity',''))} {colorize(m.get('name',''), 'green'):15} {m.get('description','')[:60]}")

    def do_check(self, arg):
        """check [target] - Verificar si el módulo actual puede ejecutarse contra el target"""
        if not self.current_module:
            print(f"  {colorize('✘', 'red')} No hay módulo seleccionado. Usa 'use <módulo>' primero")
            return

        target = arg or self.module_target
        if not target:
            print(f"  {colorize('⚠️', 'yellow')} Sin target. Usa 'set TARGET <MAC>' o pasa target al comando")
            print(f"  check <MAC>")
            return

        cls = self.engine.get_module(self.current_module)
        if not cls:
            print(f"  {colorize('✘', 'red')} Módulo '{self.current_module}' no disponible")
            return

        try:
            inst = cls(target=target)
            ok, msg = inst.check_prerequisites()
            info = inst.get_info()

            if self.console:
                content = f"[bold]Module:[/] [cyan]{self.current_module}[/]\n"
                content += f"[bold]Target:[/] [yellow]{target}[/]\n\n"
                content += f"[bold]Prerequisites:[/] {'[green]✅ OK[/]' if ok else '[red]❌ FAIL[/]'}\n"
                if msg:
                    content += f"[bold]Message:[/] {msg}\n"
                content += f"\n[bold]Target Type:[/] {info.get('target_type','?').upper()}\n"
                content += f"[bold]Severity:[/] {severity_icon(info.get('severity',''))} {info.get('severity','').title()}\n"
                content += f"[bold]CVE:[/] {info.get('cve', 'N/A')}\n"
                content += f"[bold]Requires Root:[/] {'Yes' if info.get('requires_root') else 'No'}\n"
                if info.get("requires_hardware"):
                    content += f"[bold]Hardware:[/] {', '.join(info['requires_hardware'])}\n"
                self.console.print(Panel(content, title="Check Results", border_style="green" if ok else "red"))
            else:
                print(f"\n  Check: {self.current_module} → {target}")
                print(f"  Prerequisitos: {'✅ OK' if ok else '❌ Fallo'}")
                if msg:
                    print(f"  Mensaje: {msg}")

        except Exception as e:
            print(f"  {colorize(f'✘ Error en check: {e}', 'red')}")

    def do_info(self, arg):
        """info [módulo] - Mostrar información del módulo actual o de un módulo específico"""
        target_mod = arg or self.current_module
        if not target_mod:
            print("  Uso: info <module_name>")
            return

        cls = self.engine.get_module(target_mod)
        if not cls:
            print(f"  {colorize('✘', 'red')} Módulo '{target_mod}' no encontrado")
            return

        inst = cls()
        info = inst.get_info()

        if self.console:
            self.console.print(Panel(
                f"[bold]{info.get('name')}[/]\n\n"
                f"[dim]{info.get('description')}[/]\n\n"
                f"[bold]Severity:[/] {severity_icon(info.get('severity',''))} {info.get('severity','').title()}\n"
                f"[bold]Target Type:[/] {target_type_icon(info.get('target_type',''))} {info.get('target_type','').upper()}\n"
                f"[bold]CVE:[/] {info.get('cve', 'N/A')}\n"
                f"[bold]Requires Root:[/] {'Yes' if info.get('requires_root') else 'No'}\n"
                f"[bold]Hardware Required:[/] {', '.join(info.get('requires_hardware',[])) or 'None (built-in BT)'}\n"
                f"[bold]Version:[/] {info.get('version', '?')}",
                title=f"[bold cyan]{info.get('name')}[/]",
                border_style="cyan"
            ))
        else:
            print(f"\n  {colorize(info.get('name',''), 'bold')}")
            print(f"  {info.get('description','')}")
            print(f"  Severidad: {severity_icon(info.get('severity',''))} {info.get('severity','').title()}")
            print(f"  CVE: {info.get('cve','N/A')}")
            print(f"  Target: {info.get('target_type','').upper()}")

    def do_show(self, arg):
        """show [modules|options|targets|advanced] - Mostrar información"""
        what = arg.strip().lower() if arg else "options"

        if what == "modules" or what == "mod":
            self.do_list("")

        elif what == "options" or what == "opt":
            if self.current_module and self.current_module_info:
                mod_opts = self.current_module_info.get("module_options", {})
                if self.console:
                    table = Table(title=f"Options for {self.current_module}", border_style="blue")
                    table.add_column("Option", style="cyan", width=14)
                    table.add_column("Value", style="yellow", width=24)
                    table.add_column("Description", style="dim")
                    table.add_column("Required", style="bold", width=10)
                    table.add_row("TARGET", self.module_target or "(not set)", "Target MAC address", "Yes")
                    for k, v in self.module_options.items():
                        desc = mod_opts.get(k.upper(), mod_opts.get(k.lower(), ""))
                        table.add_row(k.upper(), v or "(not set)", desc, "No")
                    for k, desc in mod_opts.items():
                        k_upper = k.upper()
                        if k_upper in ("TARGET", "RHOST"):
                            continue
                        if k_upper not in [o.upper() for o in self.module_options.keys()]:
                            table.add_row(k_upper, "(not set)", desc, "No")
                    self.console.print(table)
                else:
                    print(f"\n  Opciones para {self.current_module}:")
                    print(f"    TARGET = {self.module_target or '(not set)'}")
                    for k, v in self.module_options.items():
                        print(f"    {k.upper()} = {v or '(not set)'}")
            else:
                print("  No hay módulo seleccionado")

        elif what == "targets" or what == "hosts":
            if self.targets_cache:
                if self.console:
                    table = Table(title="Known Targets", border_style="green")
                    table.add_column("#", style="dim")
                    table.add_column("Name", style="cyan")
                    table.add_column("MAC", style="green")
                    for i, t in enumerate(self.targets_cache, 1):
                        table.add_row(str(i), t.get("name","?"), t.get("mac","N/A"))
                    self.console.print(table)
                else:
                    print(f"\n  Targets conocidos ({len(self.targets_cache)}):")
                    for i, t in enumerate(self.targets_cache, 1):
                        print(f"    {i}. {t.get('name','?')} ({t.get('mac','N/A')})")
            else:
                print("  No hay targets. Usa 'scan' primero.")

        elif what == "advanced" or what == "adv":
            self._show_advanced_info()

        else:
            print("  Uso: show [modules|options|targets|advanced]")

    def _show_advanced_info(self):
        """Muestra información avanzada: CVE, exploits, referencias."""
        if not self.current_module or not self.current_module_info:
            print("  No hay módulo seleccionado")
            return

        info = self.current_module_info
        cve = info.get("cve", "")
        cve_url = info.get("cve_url", "")
        exploits = info.get("exploit_links", [])
        refs = info.get("references", [])
        version = info.get("version", "?")
        author = info.get("author", "?")

        if self.console:
            content = f"[bold]Module:[/] [cyan]{info.get('name')}[/]\n"
            content += f"[bold]Author:[/] {author}\n"
            content += f"[bold]Version:[/] {version}\n\n"

            if cve:
                content += f"[bold]CVE:[/] [red]{cve}[/]\n"
                if cve_url:
                    content += f"[bold]CVE URL:[/] [blue]{cve_url}[/]\n"
            content += f"\n"

            if exploits:
                content += f"[bold]Exploit Links:[/]\n"
                for e in exploits:
                    content += f"  • [blue]{e}[/]\n"

            if refs:
                content += f"\n[bold]References:[/]\n"
                for r in refs:
                    content += f"  • [blue]{r}[/]\n"

            self.console.print(Panel(content, title="Advanced Info", border_style="magenta"))
        else:
            print(f"\n  [{info.get('name')}] Advanced Info")
            print(f"  Author: {author}  |  Version: {version}")
            if cve:
                print(f"  CVE: {cve}")
                if cve_url:
                    print(f"  CVE URL: {cve_url}")
            if exploits:
                print(f"  Exploits:")
                for e in exploits:
                    print(f"    • {e}")
            if refs:
                print(f"  References:")
                for r in refs:
                    print(f"    • {r}")
        print()

    # ─── Comandos de acción ───────────────────────────────

    def do_vuln(self, arg):
        """vuln [target] - Escanear vulnerabilidades Bluetooth del dispositivo"""
        target = arg.strip() if arg else self.module_target
        if not target:
            print(f"  {colorize('⚠️', 'yellow')} Sin target. Usa: vuln <MAC> o set TARGET <MAC>")
            return

        print(f"  {colorize('🔍', 'cyan')} Escaneando vulnerabilidades de {target}...")

        if self.console:
            with self.console.status("[bold cyan]Scanning vulnerabilities...") as status:
                result = self.engine.run_module("vuln", target=target)
        else:
            result = self.engine.run_module("vuln", target=target)

        self._display_result(result)

        # Guardar en sesión
        data = result.get("data", {})
        vulns = data.get("vulnerabilities", [])
        found = [v for v in vulns if v.get("vulnerable")]
        if found:
            self.session.add_result("vuln", target, result.get("success", False), data)

    def do_auto(self, arg):
        """auto [target] [--mode detect|attack|full] - Ejecutar autopilot completo"""
        args = arg.split() if arg else []
        target = ""
        mode = "full"

        i = 0
        while i < len(args):
            if args[i] == "--mode" and i + 1 < len(args):
                mode = args[i + 1]
                i += 2
            elif not args[i].startswith("--"):
                target = args[i]
                i += 1
            else:
                i += 1

        if not target:
            target = self.module_target

        print(f"  {colorize('⚡', 'cyan')} Autopilot mode={mode} target={target or 'all'}")

        if self.console:
            with self.console.status("[bold cyan]Running Autopilot...") as status:
                result = self.engine.run_module(
                    "autopilot",
                    target=target,
                    options={"MODE": mode, "REPORT": "true"}
                )
        else:
            result = self.engine.run_module(
                "autopilot",
                target=target,
                options={"MODE": mode, "REPORT": "true"}
            )

        self._display_result(result)

    def do_scan(self, arg):
        """scan [--ble|--classic] - Escanear dispositivos Bluetooth"""
        scan_type = arg.strip() if arg else "all"

        from bluesky.modules.scanners.device_scanner import DeviceScanner
        timeout = self.config.get("scanner.scan_duration", 8)
        if "--ble" in scan_type:
            scan_type = "ble"
        elif "--classic" in scan_type:
            scan_type = "classic"

        if self.console:
            with self.console.status(f"[bold cyan]Scanning {scan_type.upper()} devices...") as status:
                scanner = DeviceScanner(options={"type": scan_type, "timeout": str(timeout)})
                result = scanner.run()
        else:
            print(f"  Escaneando {scan_type.upper()}...")
            scanner = DeviceScanner(options={"type": scan_type, "timeout": str(timeout)})
            result = scanner.run()

        if result.get("success"):
            devices = result.get("data", {}).get("devices", [])
            self.targets_cache = devices

            if self.console:
                table = Table(title=f"Devices Found ({len(devices)})", border_style="green")
                table.add_column("#", style="dim")
                table.add_column("Name", style="cyan")
                table.add_column("MAC", style="green")
                table.add_column("Type", style="yellow")
                table.add_column("RSSI", style="dim")
                for i, d in enumerate(devices, 1):
                    info = d.get("info", {})
                    table.add_row(
                        str(i),
                        d.get("name", "?"),
                        d.get("mac", "N/A"),
                        d.get("type", "?"),
                        str(info.get("rssi", ""))
                    )
                self.console.print(table)
            else:
                print(f"\n  {colorize(f'{len(devices)} dispositivo(s) encontrado(s)', 'green')}")
                for i, d in enumerate(devices, 1):
                    print(f"  {i:2d}. {d.get('name','?')} ({d.get('mac','N/A')})")

            # Guardar en sesión
            for d in devices:
                self.session.add_target(d.get("mac",""), d.get("name",""), d.get("rssi",0))
        else:
            print(f"  {colorize('⚠️  No se encontraron dispositivos', 'yellow')}")

    def do_session(self, arg):
        """session [save|load|list|summary] - Gestionar sesiones"""
        args = shlex.split(arg) if arg else []

        if not args or args[0] == "list":
            sessions = Session.list_sessions()
            if sessions:
                if self.console:
                    table = Table(title="Saved Sessions", border_style="blue")
                    table.add_column("Name", style="cyan")
                    for s in sessions:
                        table.add_row(s)
                    self.console.print(table)
                else:
                    print(f"\n  Sesiones:")
                    for s in sessions:
                        print(f"    📁 {s}")

        elif args[0] == "save" and len(args) >= 2:
            self.session.name = args[1]
            self.session._save()
            print(f"  {colorize(f'✅ Sesión guardada: {args[1]}', 'green')}")

        elif args[0] == "load" and len(args) >= 2:
            if self.session.load(args[1]):
                self.targets_cache = self.session.targets
                print(f"  {colorize(f'✅ Sesión cargada: {args[1]}', 'green')}")
            else:
                print(f"  {colorize(f'✘ Sesión no encontrada: {args[1]}', 'red')}")

        elif args[0] == "summary":
            summary = self.session.summary()
            if self.console:
                self.console.print(Panel(
                    f"[bold]Name:[/] {summary.get('name','N/A')}\n"
                    f"[bold]Targets:[/] {summary.get('total_targets',0)}\n"
                    f"[bold]Results:[/] {summary.get('total_results',0)}\n"
                    f"[bold]Successful:[/] [green]{summary.get('successful_attacks',0)}[/]\n"
                    f"[bold]Failed:[/] [red]{summary.get('failed_attacks',0)}[/]",
                    title="Session Summary", border_style="blue"
                ))
            else:
                print(f"\n  Sesión: {summary.get('name','N/A')}")
                print(f"  Targets: {summary.get('total_targets',0)}")
                print(f"  Resultados: {summary.get('total_results',0)}")

    def do_report(self, arg):
        """report [--html|--json|--txt] [filename] - Generar reporte"""
        fmt = self.config.get("general.report_format", "html")
        filename = ""

        args = shlex.split(arg) if arg else []
        for a in args:
            if a.startswith("--"):
                fmt = a[2:]
            else:
                filename = a

        summary = self.session.summary()
        summary["session"] = {
            "name": self.session.name,
            "date": __import__('datetime').datetime.now().isoformat()[:10],
            "environment": "Termux" if HardwareDetector.is_termux() else "Linux",
            "duration": "N/A",
        }
        reporter = Reporter(summary)

        if not filename:
            filename = f"bluesky_report_{self.session.name}.{fmt}"

        output_dir = Path("reports")
        output_dir.mkdir(exist_ok=True)
        filepath = output_dir / filename

        if fmt == "html":
            reporter.to_html(str(filepath))
        elif fmt == "json":
            reporter.to_json(str(filepath))
        else:
            reporter.to_txt(str(filepath))

        print(f"  {colorize(f'✅ Reporte generado: {filepath}', 'green')}")

    def do_config(self, arg):
        """config [set|save|show] - Gestionar configuración de Bluesky"""
        args = shlex.split(arg) if arg else []

        if not args or args[0] == "show":
            if self.console:
                all_cfg = self.config.get_all()
                content = f"[bold]Config file:[/] [dim]{self.config._path or '(defaults)'}[/]\n"
                content += f"[bold]Dirty:[/] {'[yellow]Yes[/]' if self.config.is_dirty() else '[green]No[/]'}\n\n"

                def _add_section(data, indent=0):
                    prefix = "  " * indent
                    for key, value in data.items():
                        if isinstance(value, dict):
                            content_part = f"{prefix}[bold]{key}[/]:\n"
                            # Can't modify content from nested function easily, just print
                        elif isinstance(value, list):
                            if value:
                                content += f"{prefix}{key}: {len(value)} items\n"
                            else:
                                content += f"{prefix}{key}: []\n"
                        else:
                            content += f"{prefix}{key}: [cyan]{value}[/]\n"

                # Rebuild with proper approach
                content = f"[bold]Config file:[/] [dim]{self.config._path or '(defaults)'}[/]\n"
                content += f"[bold]Dirty:[/] {'[yellow]Yes[/]' if self.config.is_dirty() else '[green]No[/]'}\n\n"

                for section_key, section_val in all_cfg.items():
                    if isinstance(section_val, dict):
                        content += f"[bold underline]{section_key}[/]\n"
                        for k, v in section_val.items():
                            if isinstance(v, dict):
                                content += f"  [bold]{k}[/]\n"
                                for sk, sv in v.items():
                                    content += f"    {sk}: [cyan]{sv}[/]\n"
                            elif isinstance(v, list):
                                content += f"  {k}: [dim]{len(v)} items[/]\n"
                                for item in v:
                                    content += f"    - [cyan]{item}[/]\n" if isinstance(item, str) else f"    - {item}\n"
                            else:
                                content += f"  {k}: [cyan]{v}[/]\n"
                    elif isinstance(section_val, list):
                        content += f"[bold]{section_key}[/]: [dim]{len(section_val)} items[/]\n"

                self.console.print(Panel(content, title="Configuration", border_style="blue"))
            else:
                print(self.config.export_summary())
            return

        action = args[0]
        if action == "set" and len(args) >= 2:
            try:
                key, value = parse_key_value(args[1])
                old = self.config.get(key)
                self.config.set(key, value)
                print(f"  {colorize('✅', 'green')} {key} = {value}  (previous: {old})")
                print(f"  {colorize('⚠️', 'yellow')} Use 'config save' to persist")
            except ValueError as e:
                print(f"  {colorize('✘', 'red')} {e}")
        elif action == "save":
            self.config.save()
            print(f"  {colorize('✅', 'green')} Config saved to {self.config._path}")
        elif action == "reset":
            self.config.reset_to_defaults()
            print(f"  {colorize('🔄', 'yellow')} Config reset to defaults")
        else:
            print(f"  {colorize('Uso:', 'bold')} config [show|set <kv>|save|reset]")

    def do_help(self, arg):
        """help [comando] - Mostrar ayuda"""
        if arg:
            super().do_help(arg)
        else:
            help_text = """
            [bold cyan]╔══════════════════════════════════════════╗[/]
            [bold cyan]║     BLUESKY CONSOLE - METASPLOIT MODE  ║[/]
            [bold cyan]╚══════════════════════════════════════════╝[/]

            [bold]Navegación y Búsqueda[/]
              [cyan]use <módulo>[/]       Seleccionar módulo de ataque/escaneo
              [cyan]back[/]                Deseleccionar módulo actual
              [cyan]list[/]                Listar todos los módulos disponibles
              [cyan]search <palabra>[/]    Buscar módulos por nombre, CVE, keyword
              [cyan]info [módulo][/]        Info del módulo actual o específico

            [bold]Configuración[/]
              [cyan]set <opción> <val>[/]   Configurar opción (TARGET, RHOST, etc.)
              [cyan]show options[/]         Mostrar opciones del módulo actual
              [cyan]show targets[/]         Mostrar targets conocidos
              [cyan]show advanced[/]        Mostrar info CVE, exploits, referencias

            [bold]Ejecución[/]
              [cyan]run [target][/]          Ejecutar módulo actual
              [cyan]check [target][/]        Verificar prerequisitos contra target
              [cyan]scan [--ble|--classic][/] Escanear dispositivos Bluetooth
              [cyan]vuln <target>[/]         Escanear vulnerabilidades Bluetooth
              [cyan]auto [target][/]         Autopilot: scan → vuln → attack → report

            [bold]Sesión y Reportes[/]
              [cyan]session list[/]          Listar sesiones guardadas
              [cyan]session save <name>[/]   Guardar sesión actual
              [cyan]session load <name>[/]   Cargar sesión
              [cyan]report [--html|--json][/] Generar reporte

            [bold]Configuración Global[/]
              [cyan]config show[/]           Mostrar configuración actual
              [cyan]config set <kv>[/]       Cambiar valor (ej: general.timeout=60)
              [cyan]config save[/]           Persistir cambios a disco
              [cyan]config reset[/]          Restaurar valores por defecto

            [bold]Generales[/]
              [cyan]help[/]                 Mostrar esta ayuda
              [cyan]exit / quit[/]          Salir de la consola
            """

            if self.console:
                from rich.markdown import Markdown
                self.console.print(Panel(Markdown(help_text), border_style="cyan"))
            else:
                print(help_text)

    def do_exit(self, arg):
        """exit - Salir de Bluesky Console"""
        print(f"\n  {colorize('👋 Hasta luego!', 'cyan')}")
        return True

    def do_quit(self, arg):
        """quit - Salir de Bluesky Console"""
        return self.do_exit(arg)

    def do_EOF(self, arg):
        """Ctrl+D - Salir"""
        print()
        return self.do_exit(arg)

    def emptyline(self):
        """No hacer nada en línea vacía"""
        pass

    def default(self, line):
        """Comando no reconocido"""
        print(f"  {colorize('✘', 'red')} Comando desconocido: '{line}'")
        print(f"  Escribe 'help' para ayuda")


def start_console():
    """Inicia la consola interactiva Bluesky."""
    # Fix para Windows: readline no tiene atributo 'backend'
    if sys.platform == "win32":
        try:
            import readline as _rl
            if not hasattr(_rl, 'backend'):
                _rl.backend = 'windows'
        except ImportError:
            pass

    try:
        console = BlueskyConsole()
        console.cmdloop()
    except KeyboardInterrupt:
        print(f"\n  {colorize('👋 Hasta luego!', 'cyan')}")
    except AttributeError as e:
        if "readline" in str(e).lower():
            # Fallback: consola sin readline (cmd raw)
            print(f"  {colorize('⚠️', 'yellow')} Usando modo consola básico")
            console = BlueskyConsole()
            console.use_rawinput = True
            try:
                console.cmdloop()
            except KeyboardInterrupt:
                print(f"\n  {colorize('👋 Hasta luego!', 'cyan')}")
        else:
            print(f"\n  {colorize(f'✘ Error: {e}', 'red')}")
            return 1
    except Exception as e:
        print(f"\n  {colorize(f'✘ Error: {e}', 'red')}")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(start_console())
