#!/usr/bin/env python3
"""
bluesky Console - Modo interactivo REPL
=======================================
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
import cmd
import shlex
from pathlib import Path

try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    RICH_AVAILABLE = True
except ImportError:
    RICH_AVAILABLE = False

from bluesky import __version__
from bluesky.core.engine import ModuleEngine
from bluesky.core.session import Session
from bluesky.core.hardware import HardwareDetector
from bluesky.core.reporter import Reporter
from bluesky.utils.format import (
    ASCII_LOGO, colorize, severity_icon, target_type_icon,
)
from bluesky.utils.config import get_config, parse_key_value


class BlueskyConsole(cmd.Cmd):
    """Consola interactiva bluesky estilo Metasploit."""

    intro = ""

    # Ayuda organizada por categorías (estilo msfconsole). Fuente única
    # usada tanto por el render Rich como por el fallback en texto plano.
    HELP_SECTIONS = [
        ("Módulos", [
            ("use <módulo>", "Seleccionar módulo de ataque/escaneo"),
            ("back", "Deseleccionar el módulo actual"),
            ("list", "Listar todos los módulos disponibles"),
            ("search <palabra>", "Buscar por nombre, CVE o palabra clave"),
            ("info [módulo]", "Info del módulo actual o específico"),
            ("educate [módulo]", "Explicación didáctica: qué es, cómo funciona y cómo mitigarlo"),
        ]),
        ("Configuración", [
            ("set <opción> <val>", "Configurar opción (TARGET, RHOST, ...)"),
            ("show options", "Opciones del módulo actual"),
            ("show targets", "Targets conocidos (favoritos y escaneos)"),
            ("show advanced", "Info CVE, exploits y referencias"),
            ("config show|set|save", "Configuración global de bluesky"),
        ]),
        ("Ejecución", [
            ("run [target]", "Ejecutar el módulo actual"),
            ("check [target]", "Verificar prerequisitos contra el target"),
            ("scan [--ble|--classic]", "Escanear dispositivos Bluetooth cercanos"),
            ("vuln <target>", "Análisis de vulnerabilidades del target"),
            ("auto [target]", "Autopilot: scan → vuln → attack → report"),
        ]),
        ("Sesión y reportes", [
            ("session list|save|load", "Gestionar sesiones de auditoría"),
            ("report [--html|--json|--txt]", "Generar reporte de la sesión"),
        ]),
        ("Generales", [
            ("help [comando]", "Mostrar esta ayuda"),
            ("exit / quit", "Salir de la consola"),
        ]),
    ]

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
        """Mostrar banner de bienvenida (estilo msfconsole) al iniciar."""
        if self.console:
            self.console.print()
            self.console.print(ASCII_LOGO, style="bold cyan")
            self.console.print(
                f"  [bold]bluesky[/] [dim]v{__version__} · consola interactiva · "
                f"{len(self.engine.list_modules())} módulos[/]"
            )
            self.console.print(
                "[dim]  Úsalo solo en auditorías autorizadas · escribe 'help' para ver los comandos[/]"
            )
            self.console.print()
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
        """Línea de estado compacta: UNA línea, sin panel.

        Antes se pintaba un Panel completo en cada arranque y sumado al
        resto de paneles rompía el layout de terminales bajas.
        """
        if not self.console:
            return
        mod_name = self.current_module or "ninguno"
        target = self.module_target or "no establecido"
        n_mods = len(self.engine.list_modules())
        self.console.print(
            f"[dim]Módulos:[/] [green]{n_mods}[/]"
            f"  [dim]·  Módulo:[/] [cyan]{mod_name}[/]"
            f"  [dim]·  Target:[/] [yellow]{target}[/]"
        )

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
            print("  Uso: use <módulo>")
            print("  Módulos disponibles:")
            self.do_list("")
            return

        cls = self.engine.get_module(arg)
        if not cls:
            print(f"  {colorize('✘', 'red')} Módulo '{arg}' no encontrado")
            print("  Usa 'list' para ver módulos disponibles")
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
                f"Severidad: {severity_icon(info.get('severity',''))} {info.get('severity','').title()}  |  "
                f"Target: {target_type_icon(info.get('target_type',''))} {info.get('target_type','').upper()}  |  "
                f"CVE: {info.get('cve', 'N/A')}\n"
                f"Hardware: {', '.join(info.get('requires_hardware',[])) or 'Ninguno'}  |  "
                f"Root: {'sí' if info.get('requires_root') else 'no'}",
                title=f"[bold cyan]Módulo: {arg}[/]",
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
            print("  Usa 'use <módulo>' primero")
            return

        target = arg or self.module_target

        if not target:
            print(f"  {colorize('⚠️', 'yellow')} Sin target. Ejecutando modo discovery...")
            print()

        if self.console:
            self.console.print(f"[bold]Ejecutando módulo:[/] [cyan]{self.current_module}[/]")
            if target:
                self.console.print(f"[bold]Target:[/] [yellow]{target}[/]")
            if self.module_options:
                self.console.print(f"[bold]Opciones:[/] {self.module_options}")

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
            # Estado en UNA línea (antes: panel 'Resultado' + un panel
            # adicional por cada mensaje → salida interminable).
            if result.get("success"):
                self.console.print("[bold green]✔ Módulo ejecutado correctamente[/]")
            else:
                self.console.print("[bold yellow]● Módulo completado con avisos[/]")

            # Mensajes del módulo, sangrados y SIN interpretar markup:
            # proceden de datos externos (dispositivos, módulos) y podrían
            # contener corchetes que Rich trataría como estilos.
            for key in ("message", "warning", "summary", "risk", "info", "help"):
                val = data.get(key)
                if val and isinstance(val, str) and len(val) > 3:
                    for line in val.split("\n"):
                        if line.strip():
                            self.console.print(
                                f"  {line.strip()}", markup=False, highlight=False
                            )

            # Tabla de vulnerabilidades
            vulns = data.get("vulnerabilities", [])
            if vulns:
                table = Table(title="Vulnerabilidades detectadas", border_style="red")
                table.add_column("Nombre", style="cyan")
                table.add_column("Severidad", style="bold")
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
                table = Table(title=f"Dispositivos encontrados ({len(devices)})", border_style="blue")
                table.add_column("#", style="dim")
                table.add_column("Nombre", style="cyan")
                table.add_column("MAC", style="green")
                table.add_column("Tipo", style="yellow")
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
                table = Table(title="Dispositivos vulnerables", border_style="red")
                table.add_column("Dispositivo", style="cyan")
                table.add_column("MAC", style="green")
                table.add_column("Riesgo", style="bold")
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

            table = Table(title=f"Módulos disponibles ({len(modules)} en total)", border_style="cyan")
            table.add_column("", style="bold", width=2)
            table.add_column("Nombre", style="cyan", width=16)
            table.add_column("Tipo", width=5)
            table.add_column("Descripción", style="white")
            table.add_column("CVE", style="dim", width=20)

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
            table = Table(title=f"Resultados de búsqueda: '{arg}' ({len(results)} coincidencias)", border_style="cyan")
            table.add_column("", width=2)
            table.add_column("Nombre", style="cyan", width=16)
            table.add_column("Tipo", width=5)
            table.add_column("Descripción")
            table.add_column("CVE", style="dim", width=20)
            for m in results:
                table.add_row(
                    severity_icon(m.get("severity", "")),
                    m.get("name", ""),
                    target_type_icon(m.get("target_type", "")),
                    m.get("description", ""),
                    m.get("cve", "")[:20]
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
            print("  check <MAC>")
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
                content = f"[bold]Módulo:[/] [cyan]{self.current_module}[/]\n"
                content += f"[bold]Target:[/] [yellow]{target}[/]\n\n"
                content += f"[bold]Prerrequisitos:[/] {'[green]✅ OK[/]' if ok else '[red]❌ Fallo[/]'}\n"
                if msg:
                    content += f"[bold]Mensaje:[/] {msg}\n"
                content += f"\n[bold]Tipo de target:[/] {info.get('target_type','?').upper()}\n"
                content += f"[bold]Severidad:[/] {severity_icon(info.get('severity',''))} {info.get('severity','').title()}\n"
                content += f"[bold]CVE:[/] {info.get('cve', 'N/A')}\n"
                content += f"[bold]Requiere root:[/] {'sí' if info.get('requires_root') else 'no'}\n"
                if info.get("requires_hardware"):
                    content += f"[bold]Hardware:[/] {', '.join(info['requires_hardware'])}\n"
                self.console.print(Panel(content, title="Verificación", border_style="green" if ok else "red"))
            else:
                print(f"\n  Verificación: {self.current_module} → {target}")
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
                f"[bold]Severidad:[/] {severity_icon(info.get('severity',''))} {info.get('severity','').title()}\n"
                f"[bold]Tipo de target:[/] {target_type_icon(info.get('target_type',''))} {info.get('target_type','').upper()}\n"
                f"[bold]CVE:[/] {info.get('cve', 'N/A')}\n"
                f"[bold]Requiere root:[/] {'sí' if info.get('requires_root') else 'no'}\n"
                f"[bold]Hardware requerido:[/] {', '.join(info.get('requires_hardware',[])) or 'Ninguno (BT integrado)'}\n"
                f"[bold]Versión:[/] {info.get('version', '?')}",
                title=f"[bold cyan]{info.get('name')}[/]",
                border_style="cyan"
            ))
        else:
            print(f"\n  {colorize(info.get('name',''), 'bold')}")
            print(f"  {info.get('description','')}")
            print(f"  Severidad: {severity_icon(info.get('severity',''))} {info.get('severity','').title()}")
            print(f"  CVE: {info.get('cve','N/A')}")
            print(f"  Target: {info.get('target_type','').upper()}")

    def do_educate(self, arg):
        """educate [ódulo] - Explicación educativa paso a paso (qué es, cómo funciona, mitigación)"""
        from bluesky.core.education import (
            get_education, covered_modules, format_education_plain,
            format_education_rich,
        )

        target_mod = arg.strip().lower() or self.current_module
        if not target_mod:
            # Índice de contenidos disponibles
            mods = covered_modules()
            if self.console:
                table = Table(title="Modo educativo — módulos disponibles", border_style="cyan")
                table.add_column("Módulo", style="cyan", width=16)
                table.add_column("Tema", style="dim")
                from bluesky.core.education import EDU_DB
                for m in mods:
                    table.add_row(m, EDU_DB[m]["title"])
                self.console.print(table)
            else:
                print("  Modo educativo — usa: educate <módulo>")
                for m in mods:
                    print(f"    - {m}")
            print("  Uso: educate <módulo>")
            return

        entry = get_education(target_mod)
        if entry is None:
            print(f"  {colorize('✘', 'red')} Sin contenido educativo para '{target_mod}'")
            print(f"  Disponibles: {', '.join(covered_modules())}")
            return

        if self.console:
            format_education_rich(entry, self.console)
        else:
            print(format_education_plain(entry))

    def complete_educate(self, text, line, begidx, endidx):
        """Tab-completion para educate con los módulos cubiertos."""
        from bluesky.core.education import covered_modules
        args = shlex.split(line) if line else []
        if len(args) > 1 and not line.endswith(" "):
            current = args[-1]
        else:
            current = ""
        return [m for m in covered_modules() if m.startswith(current)]

    def do_show(self, arg):
        """show [modules|options|targets|advanced] - Mostrar información"""
        what = arg.strip().lower() if arg else "options"

        if what == "modules" or what == "mod":
            self.do_list("")

        elif what == "options" or what == "opt":
            if self.current_module and self.current_module_info:
                mod_opts = self.current_module_info.get("module_options", {})
                if self.console:
                    table = Table(title=f"Opciones de {self.current_module}", border_style="blue")
                    table.add_column("Opción", style="cyan", width=14)
                    table.add_column("Valor", style="yellow", width=24)
                    table.add_column("Descripción", style="dim")
                    table.add_column("Obligatorio", style="bold", width=10)
                    table.add_row("TARGET", self.module_target or "(no establecido)", "MAC del target", "Sí")
                    for k, v in self.module_options.items():
                        desc = mod_opts.get(k.upper(), mod_opts.get(k.lower(), ""))
                        table.add_row(k.upper(), v or "(no establecido)", desc, "No")
                    for k, desc in mod_opts.items():
                        k_upper = k.upper()
                        if k_upper in ("TARGET", "RHOST"):
                            continue
                        if k_upper not in [o.upper() for o in self.module_options.keys()]:
                            table.add_row(k_upper, "(no establecido)", desc, "No")
                    self.console.print(table)
                else:
                    print(f"\n  Opciones para {self.current_module}:")
                    print(f"    TARGET = {self.module_target or '(no establecido)'}")
                    for k, v in self.module_options.items():
                        print(f"    {k.upper()} = {v or '(no establecido)'}")
            else:
                print("  No hay módulo seleccionado")

        elif what == "targets" or what == "hosts":
            if self.targets_cache:
                if self.console:
                    table = Table(title="Targets conocidos", border_style="green")
                    table.add_column("#", style="dim")
                    table.add_column("Nombre", style="cyan")
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
            print("  Uso: show [módulos|options|targets|advanced]")

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
            content = f"[bold]Módulo:[/] [cyan]{info.get('name')}[/]\n"
            content += f"[bold]Autor:[/] {author}\n"
            content += f"[bold]Versión:[/] {version}\n\n"

            if cve:
                content += f"[bold]CVE:[/] [red]{cve}[/]\n"
                if cve_url:
                    content += f"[bold]CVE URL:[/] [blue]{cve_url}[/]\n"
            content += "\n"

            if exploits:
                content += "[bold]Enlaces de exploits:[/]\n"
                for e in exploits:
                    content += f"  • [blue]{e}[/]\n"

            if refs:
                content += "\n[bold]Referencias:[/]\n"
                for r in refs:
                    content += f"  • [blue]{r}[/]\n"

            self.console.print(Panel(content, title="Info avanzada", border_style="magenta"))
        else:
            print(f"\n  [{info.get('name')}] Info avanzada")
            print(f"  Autor: {author}  |  Versión: {version}")
            if cve:
                print(f"  CVE: {cve}")
                if cve_url:
                    print(f"  CVE URL: {cve_url}")
            if exploits:
                print("  Exploits:")
                for e in exploits:
                    print(f"    • {e}")
            if refs:
                print("  Referencias:")
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
            with self.console.status("[bold cyan]Escaneando vulnerabilidades..."):
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
            with self.console.status("[bold cyan]Ejecutando Autopilot..."):
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
            with self.console.status(f"[bold cyan]Escaneando dispositivos ({scan_type.upper()})..."):
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
                table = Table(title=f"Dispositivos encontrados ({len(devices)})", border_style="green")
                table.add_column("#", style="dim")
                table.add_column("Nombre", style="cyan")
                table.add_column("MAC", style="green")
                table.add_column("Tipo", style="yellow")
                table.add_column("Fabricante", style="magenta")
                table.add_column("RSSI", style="dim")
                for i, d in enumerate(devices, 1):
                    info = d.get("info", {})
                    table.add_row(
                        str(i),
                        d.get("name", "?"),
                        d.get("mac", "N/A"),
                        d.get("type", "?"),
                        d.get("vendor", "-") or "-",
                        str(info.get("rssi", ""))
                    )
                self.console.print(table)
            else:
                print(f"\n  {colorize(f'{len(devices)} dispositivo(s) encontrado(s)', 'green')}")
                for i, d in enumerate(devices, 1):
                    vendor = f" · {d.get('vendor')}" if d.get("vendor") else ""
                    print(f"  {i:2d}. {d.get('name','?')} ({d.get('mac','N/A')}){vendor}")

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
                    table = Table(title="Sesiones guardadas", border_style="blue")
                    table.add_column("Nombre", style="cyan")
                    for s in sessions:
                        table.add_row(s)
                    self.console.print(table)
                else:
                    print("\n  Sesiones:")
                    for s in sessions:
                        print(f"    📁 {s}")

        elif args[0] == "save" and len(args) >= 2:
            self.session.name = args[1]
            self.session.save()
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
                    f"[bold]Nombre:[/] {summary.get('name','N/A')}\n"
                    f"[bold]Targets:[/] {summary.get('total_targets',0)}\n"
                    f"[bold]Resultados:[/] {summary.get('total_results',0)}\n"
                    f"[bold]Éxitos:[/] [green]{summary.get('successful_attacks',0)}[/]\n"
                    f"[bold]Fallos:[/] [red]{summary.get('failed_attacks',0)}[/]",
                    title="Resumen de sesión", border_style="blue"
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
                # Whitelist de formatos válidos. Antes se aceptaba
                # cualquier valor como fmt (p.ej. --../../../tmp/evil),
                # que terminaba como parte del filename más abajo.
                candidate = a[2:].lower()
                if candidate in ("html", "json", "txt"):
                    fmt = candidate
            else:
                filename = a

        # Reporter espera un payload con claves 'session{name,date,...}',
        # 'targets[]' y 'results[]'. Antes pasábamos session.summary()
        # que tiene claves distintas (total_targets, total_results, sin
        # results[]), lo que producía reportes con sección de resultados
        # vacía (Tests=0) aunque la sesión tuviera resultados cargados.
        reporter_payload = {
            "session": {
                "name": self.session.name,
                "date": __import__('datetime').datetime.now().isoformat()[:10],
                "environment": "Termux" if HardwareDetector.is_termux() else "Linux",
                "duration": "N/A",
            },
            "targets": self.session.targets if isinstance(self.session.targets, list) else [],
            "results": self.session.results if isinstance(self.session.results, list) else [],
        }
        reporter = Reporter(reporter_payload)

        if not filename:
            filename = f"bluesky_report_{self.session.name}.{fmt}"

        output_dir = Path("reports")
        output_dir.mkdir(exist_ok=True)
        filepath = output_dir / filename
        # Defensa contra path traversal: el filename puede venir del input
        # del usuario (REPL), y sin esta comprobación un nombre como
        # '../../tmp/evil.html' escribiría fuera de reports/.
        try:
            resolved = filepath.resolve()
            base = output_dir.resolve()
            if base not in resolved.parents and resolved != base:
                print(f"  {colorize('Filename inválido (path traversal).', 'red')}")
                return
        except (OSError, RuntimeError):
            print(f"  {colorize('Filename inválido.', 'red')}")
            return

        if fmt == "html":
            reporter.to_html(str(filepath))
        elif fmt == "json":
            reporter.to_json(str(filepath))
        else:
            reporter.to_txt(str(filepath))

        print(f"  {colorize(f'✅ Reporte generado: {filepath}', 'green')}")

    def do_config(self, arg):
        """config [set|save|show] - Gestionar configuración de bluesky"""
        args = shlex.split(arg) if arg else []

        if not args or args[0] == "show":
            if self.console:
                all_cfg = self.config.get_all()
                content = f"[bold]Archivo de configuración:[/] [dim]{self.config.path or '(predeterminados)'}[/]\n"
                content += f"[bold]Modificado:[/] {'[yellow]sí[/]' if self.config.is_dirty() else '[green]no[/]'}\n\n"

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

                self.console.print(Panel(content, title="Configuración", border_style="blue"))
            else:
                print(self.config.export_summary())
            return

        action = args[0]
        if action == "set" and len(args) >= 2:
            try:
                key, value = parse_key_value(args[1])
                old = self.config.get(key)
                self.config.set(key, value)
                print(f"  {colorize('✅', 'green')} {key} = {value}  (anterior: {old})")
                print(f"  {colorize('⚠️', 'yellow')} Usa 'config save' para persistir")
            except ValueError as e:
                print(f"  {colorize('✘', 'red')} {e}")
        elif action == "save":
            self.config.save()
            print(f"  {colorize('✅', 'green')} Configuración guardada en {self.config.path}")
        elif action == "reset":
            self.config.reset_to_defaults()
            print(f"  {colorize('🔄', 'yellow')} Configuración restablecida a los valores por defecto")
        else:
            print(f"  {colorize('Uso:', 'bold')} config [show|set <kv>|save|reset]")

    def do_help(self, arg):
        """help [comando] - Mostrar ayuda"""
        if arg:
            super().do_help(arg)
            return

        if self.console:
            # Render con tablas Rich reales. ANTES este bloque envolvía
            # markup Rich en rich.markdown.Markdown(), que NO interpreta
            # estilos: el usuario veía los tags '[bold cyan]...[/]' como
            # texto literal y la caja quedaba rota.
            tbl = Table(box=None, show_header=False, padding=(0, 2), pad_edge=False)
            tbl.add_column(no_wrap=True)   # comando
            tbl.add_column()               # descripción
            n_sections = len(self.HELP_SECTIONS)
            for i, (title, rows) in enumerate(self.HELP_SECTIONS):
                tbl.add_row(f"[bold magenta]{title}[/]", "")
                for c, d in rows:
                    tbl.add_row(f"  [cyan]{c}[/]", d)
                if i < n_sections - 1:
                    tbl.add_row("", "")
            self.console.print(
                Panel(
                    tbl,
                    title=f"[bold cyan]bluesky v{__version__} — comandos[/]",
                    border_style="cyan",
                    padding=(0, 1),
                )
            )
        else:
            # Fallback texto plano alineado, sin markup de ningún tipo
            for title, rows in self.HELP_SECTIONS:
                print(f"\n  {title}")
                for c, d in rows:
                    print(f"    {c:<30} {d}")
            print()

    def do_exit(self, arg):
        """exit - Salir de bluesky Console"""
        print(f"\n  {colorize('👋 Hasta luego!', 'cyan')}")
        return True

    def do_quit(self, arg):
        """quit - Salir de bluesky Console"""
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
        print("  Escribe 'help' para ayuda")


def start_console():
    """Inicia la consola interactiva bluesky."""
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
