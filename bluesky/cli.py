#!/usr/bin/env python3
"""
Bluesky CLI - Bluetooth Security Auditing Framework
Main entry point for the command-line interface.
"""

import sys
import json
import os
from pathlib import Path

# Asegurar que el paquete bluesky se encuentra aunque no esté instalado vía pip
_THIS_DIR = Path(__file__).parent.parent
if str(_THIS_DIR) not in sys.path:
    sys.path.insert(0, str(_THIS_DIR))

from bluesky import __version__, __description__
from bluesky.console import start_console
from bluesky.core.engine import ModuleEngine
from bluesky.core.session import Session
from bluesky.core.hardware import HardwareDetector
from bluesky.core.reporter import Reporter
from bluesky.utils.format import (
    colorize, separator, severity_icon, target_type_icon,
    format_device_list, format_service_list
)


def print_banner():
    """Muestra el banner de Bluesky."""
    banner = f"""
{colorize('██████╗ ██╗     ██╗   ██╗███████╗██╗  ██╗██╗   ██╗', 'cyan')}
{colorize('██╔══██╗██║     ██║   ██║██╔════╝██║ ██╔╝╚██╗ ██╔╝', 'cyan')}
{colorize('██████╔╝██║     ██║   ██║███████╗█████╔╝  ╚████╔╝ ', 'cyan')}
{colorize('██╔══██╗██║     ██║   ██║╚════██║██╔═██╗   ╚██╔╝  ', 'cyan')}
{colorize('██████╔╝███████╗╚██████╔╝███████║██║  ██╗   ██║   ', 'cyan')}
{colorize('╚═════╝ ╚══════╝ ╚═════╝ ╚══════╝╚═╝  ╚═╝   ╚═╝   ', 'cyan')}
{colorize(f'  v{__version__} - {__description__}', 'dim')}
{colorize('  Auditoría Bluetooth para Termux & Linux', 'dim')}
    """
    print(banner)


def print_help():
    """Muestra la ayuda principal."""
    print(f"\n{colorize('USO:', 'bold')}")
    print(f"  bluesky [COMANDO] [ARGS] [OPCIONES]")
    print()
    print(f"{colorize('COMANDOS PRINCIPALES:', 'bold')}")
    print(f"  {colorize('scan', 'cyan'):20} Escanear dispositivos Bluetooth cercanos")
    print(f"  {colorize('scan --ble', 'cyan'):20} Escanear solo dispositivos BLE")
    print(f"  {colorize('list', 'cyan'):20} Listar todos los módulos de ataque disponibles")
    print(f"  {colorize('info <módulo>', 'cyan'):20} Ver información detallada de un módulo")
    print(f"  {colorize('attack <módulo> <target>', 'cyan'):20} Ejecutar un ataque sobre un target")
    print(f"  {colorize('services <target>', 'cyan'):20} Enumerar servicios SDP de un dispositivo")
    print(f"  {colorize('status', 'cyan'):20} Ver estado del hardware Bluetooth")
    print(f"  {colorize('console', 'cyan'):20} Consola interactiva estilo Metasploit")
    print(f"  {colorize('report', 'cyan'):20} Generar reporte de la sesión actual")
    print(f"  {colorize('session', 'cyan'):20} Gestionar sesiones de auditoría")
    print(f"  {colorize('config', 'cyan'):20} Ver/editar configuración")
    print(f"  {colorize('plugin', 'cyan'):20} Gestionar plugins")
    print(f"  {colorize('web', 'cyan'):20} Iniciar dashboard web (Flask)")
    print()
    print(f"  {colorize('OPCIONES GLOBALES:', 'bold')}")
    print(f"  {colorize('--config <archivo>', 'cyan'):20} Usar archivo de configuración personalizado")
    print()
    print(f"{colorize('MÓDULOS DE ATAQUE:', 'bold')}")
    engine = ModuleEngine()
    for mod in engine.list_modules():
        name = mod.get("name", "?")
        desc = mod.get("description", "")[:60]
        sev = mod.get("severity", "low")
        sev_icon = severity_icon(sev)
        ttype = mod.get("target_type", "both")
        ttype_icon = target_type_icon(ttype)
        print(f"  {sev_icon} {colorize(name, 'green'):15} {ttype_icon} {desc}")
    print()
    print(f"{colorize('EJEMPLOS:', 'bold')}")
    print(f"  bluesky scan")
    print(f"  bluesky attack bluejacking XX:XX:XX:XX:XX:XX")
    print(f"  bluesky attack blueborne")
    print(f"  bluesky info knob")
    print(f"  bluesky services XX:XX:XX:XX:XX:XX")
    print(f"  bluesky report --html report.html")
    print()


def print_module_info(module_name: str):
    """Muestra información detallada de un módulo."""
    engine = ModuleEngine()
    mod_cls = engine.get_module(module_name)

    if not mod_cls:
        print(f"\n{colorize('✘ Módulo no encontrado:', 'red')} '{module_name}'")
        print(f"  Usa '{colorize('bluesky list', 'cyan')}' para ver los módulos disponibles.\n")
        return

    mod = mod_cls()
    info = mod.get_info()

    print(f"\n{separator(title=f' {info.get("name", "?")} ')}")
    print(f"  {colorize(info.get('description', ''), 'dim')}")
    print()
    print(f"  {colorize('Tipo de target:', 'bold'):20} {target_type_icon(info.get('target_type', 'both'))} {info.get('target_type', 'both').upper()}")
    print(f"  {colorize('Severidad:', 'bold'):20} {severity_icon(info.get('severity', 'low'))} {info.get('severity', 'low').title()}")
    print(f"  {colorize('CVE:', 'bold'):20} {info.get('cve', 'N/A')}")
    print(f"  {colorize('Requiere root:', 'bold'):20} {'✅ Sí' if info.get('requires_root') else '❌ No'}")
    print(f"  {colorize('Hardware:', 'bold'):20} {', '.join(info.get('requires_hardware', [])) or 'Ninguno (solo BT interno)'}")
    print(f"  {colorize('Versión:', 'bold'):20} {info.get('version', '?')}")
    print()

    # Mostrar cómo usarlo
    print(f"  {colorize('USO:', 'bold')}")
    print(f"    bluesky attack {info.get('name')} <MAC>")
    print()


def cmd_status():
    """Muestra el estado del hardware Bluetooth."""
    print(f"\n{separator(title=' Estado del Sistema ')}")
    hw = HardwareDetector()

    # Info del adaptador
    adapter = hw.get_adapter_info()
    print(f"\n  {colorize('📡 Adaptador Bluetooth', 'bold')}")
    print(f"    {'Disponible:':15} {'✅ Sí' if adapter.get('available') else '❌ No'}")
    if adapter.get('available'):
        print(f"    {'Interfaz:':15} {adapter.get('interface', 'N/A')}")
        print(f"    {'MAC:':15} {adapter.get('mac', 'N/A')}")
        print(f"    {'Encendido:':15} {'✅ Sí' if adapter.get('powered') else '❌ No'}")
        print(f"    {'Tipo:':15} {adapter.get('type', 'N/A')}")

    # Capacidades
    caps = hw.get_capabilities()
    print(f"\n  {colorize('🔋 Capacidades', 'bold')}")
    print(f"    {'BLE:':15} {'✅ Sí' if caps.get('ble_support') else '❌ No'}")
    print(f"    {'Classic:':15} {'✅ Sí' if caps.get('classic_support') else '❌ No'}")
    print(f"    {'Root/Admin:':15} {'✅ Sí' if caps.get('is_root') else '❌ No'}")
    print(f"    {'Termux:':15} {'✅ Sí' if caps.get('is_termux') else '❌ No'}")
    print(f"    {'Windows:':15} {'✅ Sí' if caps.get('is_windows') else '❌ No'}")
    print(f"    {'WSL:':15} {'✅ Sí' if caps.get('is_wsl') else '❌ No'}")
    print(f"    {'Bleak lib:':15} {'✅ Sí' if caps.get('bleak_available') else '❌ No'}")
    print(f"    {'CSR Dongle:':15} {'✅ Sí' if caps.get('csr_dongle') else '❌ No'}")

    # Entorno
    from bluesky.utils.platform import get_os_name, get_available_backends
    print(f"\n  {colorize('💻 Entorno', 'bold')}")
    print(f"    {'Sistema:':15} {get_os_name()}")
    print(f"    {'Python:':15} {sys.version.split()[0]}")
    print(f"    {'Plataforma:':15} {caps.get('platform', 'unknown').title()}")

    # Backends disponibles
    backends = get_available_backends()
    available = [k for k, v in backends.items() if v]
    if available:
        print(f"\n  {colorize('🔌 Backends disponibles', 'bold')}")
        for b in available:
            print(f"    ✅ {b}")
    else:
        print(f"\n  {colorize('⚠️  No hay backends Bluetooth disponibles', 'yellow')}")

    # Dispositivos BT disponibles
    bt_devices = hw.get_bluetooth_devices()
    if bt_devices:
        print(f"\n  {colorize('📱 Dispositivos BT Detectados', 'bold')}")
        for dev in bt_devices:
            mac = dev.get("mac", "N/A")
            name = dev.get("name", "Unknown")
            iface = dev.get("interface", "")
            platform = dev.get("platform", "linux")
            print(f"    {iface}: {name} ({mac}) [{platform}]")
    else:
        print(f"\n  {colorize('⚠️  No se detectaron adaptadores Bluetooth', 'yellow')}")
        print(f"    Asegúrate de que Bluetooth esté encendido:")
        if caps.get('is_windows'):
            print(f"    Windows: Activa Bluetooth desde Configuración → Bluetooth y dispositivos")
            print(f"    O usa: Settings > Bluetooth & devices > Turn Bluetooth on")
        elif caps.get('is_termux'):
            print(f"    Termux: termux-bluetooth-enable")
        else:
            print(f"    Linux:  sudo hciconfig hci0 up  o  systemctl start bluetooth")

    print()


def cmd_scan(args: list):
    """Ejecuta escaneo de dispositivos."""
    from bluesky.utils.config import get_config
    from bluesky.modules.scanners.device_scanner import DeviceScanner

    cfg = get_config()
    scan_type = "all"
    timeout = cfg.get("scanner.scan_duration", 8)

    if "--ble" in args:
        scan_type = "ble"
    elif "--classic" in args:
        scan_type = "classic"

    for i, arg in enumerate(args):
        if arg == "--timeout" and i + 1 < len(args):
            try:
                timeout = int(args[i + 1])
            except ValueError:
                pass

    print(f"\n{separator(title=' Escaneando... ')}")
    print(f"  Tipo: {scan_type.upper()}  |  Timeout: {timeout}s\n")

    scanner = DeviceScanner(options={"type": scan_type, "timeout": str(timeout)})
    result = scanner.run()

    if result.get("success"):
        devices = result.get("data", {}).get("devices", [])
        print(f"  {colorize(f'✅ {len(devices)} dispositivo(s) encontrado(s)', 'green')}\n")

        for i, dev in enumerate(devices, 1):
            name = dev.get("name", "Unknown")
            mac = dev.get("mac", "N/A")
            dev_type = dev.get("type", "?")
            rssi = dev.get("info", {}).get("rssi", "")
            paired = dev.get("info", {}).get("paired", False)

            type_icon = target_type_icon(dev_type)
            paired_str = f" {colorize('(emparejado)', 'yellow')}" if paired else ""
            rssi_str = f" [{rssi} dBm]" if rssi else ""

            print(f"  {i:2d}. {type_icon} {colorize(name, 'cyan')} {colorize(mac, 'dim')}{rssi_str}{paired_str}")
    else:
        msg = result.get("data", {}).get("message", "No se encontraron dispositivos")
        print(f"  {colorize('⚠️', 'yellow')} {msg}")

    print()


def cmd_attack(args: list):
    """Ejecuta un ataque."""
    if len(args) < 1:
        print(f"\n  {colorize('✘ Error:', 'red')} Se requiere un módulo de ataque")
        print(f"  Uso: bluesky attack <módulo> [target] [--options '...']\n")
        return

    module_name = args[0]
    target = ""
    options = {}

    # Soporte para --target <MAC> o target posicional
    i = 1
    while i < len(args):
        arg = args[i]
        if arg == "--target" and i + 1 < len(args):
            target = args[i + 1]
            i += 2
        elif arg == "--options" and i + 1 < len(args):
            try:
                options = json.loads(args[i + 1])
            except json.JSONDecodeError:
                print(f"  {colorize('✘ Error:', 'red')} Opciones JSON inválidas\n")
                return
            i += 2
        elif arg.startswith("--"):
            # Ignorar otros flags
            i += 1
        elif not target and i < len(args):
            # Primer argumento no-flag es el target
            target = arg
            i += 1
        else:
            i += 1

    engine = ModuleEngine()
    print(f"\n{separator(title=f' Ejecutando: {module_name} ')}")

    if target:
        print(f"  Target: {colorize(target, 'cyan')}")
    if options:
        print(f"  Options: {options}")

    print()
    result = engine.run_module(module_name, target=target, options=options)

    if result.get("success"):
        print(f"  {colorize('✅ Módulo ejecutado correctamente', 'green')}\n")
    else:
        print(f"  {colorize('⚠️  Módulo completado con notas', 'yellow')}\n")

    # Mostrar resultados relevantes
    data = result.get("data", {})
    for key, value in data.items():
        if key in ("message", "warning", "summary", "risk", "info"):
            if isinstance(value, str) and len(value) > 5:
                for line in value.split("\n"):
                    if line.strip():
                        print(f"  {line.strip()}")

    # Mostrar vulnerabilidades encontradas
    vulns = data.get("vulnerabilities", [])
    if vulns:
        print(f"\n  {colorize('📋 Vulnerabilidades detectadas:', 'bold')}")
        for v in vulns:
            sev = severity_icon(v.get("severity", "low"))
            print(f"    {sev} {colorize(v.get('name', ''), 'yellow')}")
            if v.get("cve"):
                print(f"       CVE: {colorize(v['cve'], 'dim')}")
            if v.get("detail"):
                print(f"       {v['detail']}")

    # Mostrar dispositivos encontrados
    devices = data.get("devices", [])
    if devices:
        print(f"\n  {colorize('📱 Dispositivos:', 'bold')}")
        print(format_device_list(devices))

    # Mostrar servicios
    services = data.get("services", [])
    if services:
        print(f"\n  {colorize('🔌 Servicios:', 'bold')}")
        print(format_service_list(services))

    # Mostrar dispositivos vulnerables (WhisperPair, SweynTooth)
    vuln_devices = data.get("vulnerable_devices", [])
    if vuln_devices:
        print(f"\n  {colorize(f'⚠️  {len(vuln_devices)} dispositivo(s) VULNERABLE(S):', 'red')}")
        for vd in vuln_devices:
            print(f"    {vd.get('name', '?')} ({vd.get('mac', 'N/A')})")

    # Mostrar error si existe
    error = result.get("error")
    if error and not result.get("success"):
        print(f"\n  {colorize(f'✘ {error}', 'red')}")

    print()


def cmd_services(args: list):
    """Enumera servicios SDP de un dispositivo."""
    if not args:
        print(f"\n  {colorize('✘ Error:', 'red')} Se requiere una dirección MAC")
        print(f"  Uso: bluesky services <MAC>\n")
        return

    target = args[0]
    from bluesky.modules.scanners.service_scanner import ServiceScanner

    print(f"\n{separator(title=f' Servicios de {target} ')}")
    print()

    scanner = ServiceScanner(target=target)
    result = scanner.run()

    if result.get("success"):
        services = result.get("data", {}).get("services", [])
        print(f"  {colorize(f'✅ {len(services)} servicio(s) encontrado(s)', 'green')}\n")

        for svc in services:
            name = svc.get("name", "Unknown")
            channel = svc.get("channel", "")
            risk = svc.get("risk", "low")
            svc_type = svc.get("type", "other")

            risk_icon = severity_icon(risk)
            channel_str = f" (Canal {channel})" if channel else ""
            print(f"  {risk_icon} {colorize(name, 'cyan')}{channel_str}")

            if risk == "high":
                print(f"     {colorize('⚠️  Servicio de alto riesgo - posible superficie de ataque', 'yellow')}")
    else:
        error = result.get("error", "Error desconocido")
        print(f"  {colorize(f'✘ {error}', 'red')}")

    print()


def cmd_list():
    """Lista todos los módulos disponibles."""
    engine = ModuleEngine()
    modules = engine.list_modules()

    print(f"\n{separator(title=' Módulos Disponibles ')}")
    print(f"\n  {colorize(f'{len(modules)} módulo(s) cargado(s)', 'bold')}\n")

    # Agrupar por severidad
    by_severity = {}
    for m in modules:
        sev = m.get("severity", "low")
        if sev not in by_severity:
            by_severity[sev] = []
        by_severity[sev].append(m)

    for severity in ["critical", "high", "medium", "low"]:
        if severity in by_severity:
            print(f"  {severity_icon(severity)} {colorize(severity.upper(), 'bold')}")
            for m in by_severity[severity]:
                name = m.get("name", "?")
                desc = m.get("description", "")[:70]
                ttype = m.get("target_type", "both")
                ttype_icon = target_type_icon(ttype)
                cve = m.get("cve", "")
                cve_str = f" [{cve}]" if cve else ""
                print(f"    {ttype_icon} {colorize(name, 'green'):18} {desc}{colorize(cve_str, 'dim')}")
            print()

    print(f"  {colorize('💡 Tip:', 'dim')} Usa '{colorize('bluesky info <módulo>', 'cyan')}' para más detalles\n")


def cmd_report(args: list):
    """Genera reporte de la sesión actual."""
    from bluesky.utils.config import get_config
    cfg = get_config()
    fmt = cfg.get("general.report_format", "txt")
    output_file = ""

    for i, arg in enumerate(args):
        if arg == "--html":
            fmt = "html"
        elif arg == "--json":
            fmt = "json"
        elif arg == "--txt":
            fmt = "txt"
        elif arg.startswith("--output") and i + 1 < len(args):
            output_file = args[i + 1]
        elif not arg.startswith("--"):
            output_file = arg

    # Cargar sesión actual o crear una por defecto
    session = Session()
    if not session.load():
        # Crear sesión en memoria con datos de prueba
        session.name = "default"
        session.targets = []
        session.results = []
        session.created_at = __import__('datetime').datetime.now().isoformat()
        print(f"\n  {colorize('📋 Creando sesión por defecto...', 'dim')}")

    summary = session.summary()
    reporter = Reporter(summary)

    if not output_file:
        if fmt == "html":
            output_file = f"bluesky_report_{session.name}.html"
        elif fmt == "json":
            output_file = f"bluesky_report_{session.name}.json"
        else:
            output_file = f"bluesky_report_{session.name}.txt"

    print(f"\n{separator(title=' Generando Reporte ')}")
    print(f"  Formato: {fmt.upper()}")
    print(f"  Sesión:  {session.name}")
    print(f"  Archivo: {output_file}\n")

    if fmt == "html":
        reporter.to_html(output_file)
    elif fmt == "json":
        reporter.to_json(output_file)
    else:
        report_text = reporter.to_txt(output_file)
        # Mostrar preview
        lines = report_text.split("\n")
        for line in lines[:20]:
            print(f"  {line}")

    print(f"\n  {colorize(f'✅ Reporte guardado: {output_file}', 'green')}\n")


def cmd_session(args: list):
    """Gestiona sesiones de auditoría."""
    if not args:
        print(f"\n  {colorize('USO:', 'bold')}")
        print(f"    bluesky session save <nombre>   Guardar sesión actual")
        print(f"    bluesky session load <nombre>   Cargar sesión")
        print(f"    bluesky session list            Listar sesiones")
        print(f"    bluesky session summary         Resumen de sesión actual\n")
        return

    action = args[0]
    session = Session()

    if action == "list":
        sessions = Session.list_sessions()
        if sessions:
            print(f"\n  {colorize('Sesiones guardadas:', 'bold')}")
            for s in sessions:
                print(f"    📁 {s}")
        else:
            print(f"\n  {colorize('No hay sesiones guardadas', 'yellow')}\n")

    elif action == "save" and len(args) >= 2:
        session.name = args[1]
        session._save()
        print(f"\n  {colorize(f'✅ Sesión guardada: {args[1]}', 'green')}\n")

    elif action == "load" and len(args) >= 2:
        if session.load(args[1]):
            summary = session.summary()
            print(f"\n  {colorize(f'✅ Sesión cargada: {args[1]}', 'green')}")
            print(f"  Targets: {summary.get('total_targets', 0)}")
            print(f"  Resultados: {summary.get('total_results', 0)}")
            print(f"  Exitosos: {summary.get('successful_attacks', 0)}")
            print()
        else:
            print(f"\n  {colorize(f'✘ Sesión no encontrada: {args[1]}', 'red')}\n")

    elif action == "summary":
        if session.load():
            summary = session.summary()
            print(f"\n{separator(title=f' Sesión: {session.name} ')}")
            print(f"  Creada:  {summary.get('created_at', 'N/A')[:19]}")
            print(f"  Targets: {summary.get('total_targets', 0)}")
            print(f"  Tests:   {summary.get('total_results', 0)}")
            print(f"  Éxitos:  {summary.get('successful_attacks', 0)}")
            print(f"  Fallos:  {summary.get('failed_attacks', 0)}")
            print()
        else:
            print(f"\n  {colorize('⚠️  No hay sesión activa', 'yellow')}")
            print("  Usa 'bluesky session save <nombre>' para crear una.\n")


def cmd_config(args: list):
    """Gestiona la configuración de Bluesky."""
    from bluesky.utils.config import get_config, parse_key_value

    cfg = get_config()

    if not args:
        # Mostrar configuración actual
        print(f"\n{separator(title=' Configuración ')}")
        print(f"  Archivo: {colorize(str(cfg._path or '(defaults)'), 'dim')}")
        print(f"  Modificado: {colorize('✅ Sí' if cfg.is_dirty() else '❌ No', 'dim')}")
        print()
        all_cfg = cfg.get_all()

        def _print_section(name: str, data: dict, indent: int = 2):
            for key, value in data.items():
                if isinstance(value, dict):
                    print(f"  {' ' * indent}{colorize(f'[{key}]', 'bold')}")
                    _print_section(f"{name}.{key}", value, indent + 2)
                elif isinstance(value, list):
                    if value:
                        print(f"  {' ' * indent}{key}:")
                        for item in value:
                            print(f"  {' ' * (indent + 2)}- {item}")
                    else:
                        print(f"  {' ' * indent}{key}: []")
                else:
                    colored_val = colorize(str(value), 'cyan') if value else colorize(str(value), 'dim')
                    print(f"  {' ' * indent}{key}: {colored_val}")

        _print_section("", all_cfg)

        print(f"\n  {colorize('💡 Tip:', 'dim')} Usa 'bluesky config set <clave>=<valor>' para cambiar valores")
        print(f"  {colorize('💡 Tip:', 'dim')} Usa 'bluesky config save' para persistir cambios")
        print()
        return

    action = args[0]

    if action == "set" and len(args) >= 2:
        try:
            key, value = parse_key_value(args[1])
            old = cfg.get(key)
            cfg.set(key, value)
            print(f"\n  {colorize('✅ Config actualizada:', 'green')} {key} = {value}")
            print(f"    {'(anterior: ' + str(old) + ')' if old is not None else ''}")
            print(f"  {colorize('⚠️', 'yellow')} Cambios no guardados. Usa 'bluesky config save' para persistir.\n")
        except ValueError as e:
            print(f"\n  {colorize('✘ Error:', 'red')} {e}\n")

    elif action == "save":
        try:
            cfg.save()
            print(f"\n  {colorize('✅ Configuración guardada en:', 'green')} {cfg._path}\n")
        except Exception as e:
            print(f"\n  {colorize('✘ Error guardando:', 'red')} {e}\n")

    elif action == "reset":
        cfg.reset_to_defaults()
        print(f"\n  {colorize('🔄 Configuración reseteada a valores por defecto', 'yellow')}\n")

    elif action == "favorite" and len(args) >= 3:
        if args[1] == "add" and len(args) >= 3:
            addr = args[2]
            name = args[3] if len(args) >= 4 else ""
            type_ = args[4] if len(args) >= 5 else "auto"
            cfg.add_favorite(addr, name, type_)
            print(f"\n  {colorize('✅ Favorito añadido:', 'green')} {addr} ({name})\n")
        elif args[1] == "remove" and len(args) >= 3:
            cfg.remove_favorite(args[2])
            print(f"\n  {colorize('✅ Favorito eliminado:', 'green')} {args[2]}\n")
        else:
            print(f"\n  {colorize('Uso:', 'bold')}")
            print(f"    bluesky config favorite add <MAC> [nombre] [tipo]")
            print(f"    bluesky config favorite remove <MAC>\n")

    else:
        print(f"\n  {colorize('Uso:', 'bold')}")
        print(f"    bluesky config               Ver configuración")
        print(f"    bluesky config set <kv>      Cambiar valor (ej: general.timeout=60)")
        print(f"    bluesky config save          Persistir cambios")
        print(f"    bluesky config reset         Valores por defecto")
        print(f"    bluesky config favorite ...  Gestionar favoritos\n")


def cmd_plugin(args: list):
    """Gestiona los plugins de Bluesky."""
    from bluesky.core.engine import ModuleEngine

    engine = ModuleEngine(load_plugins=True)

    if not args or args[0] == "list":
        plugins = engine.plugin_loader.list_plugins() if engine.plugin_loader else []
        print(f"\n{separator(title=' Plugins ')}")
        print(f"  {colorize(f'{len(plugins)} plugin(s) descubierto(s)', 'bold')}")
        print(f"  {colorize(f'{sum(1 for p in plugins if p.loaded)} cargado(s)', 'bold')}\n")

        for p in plugins:
            status = colorize('✅', 'green') if p.loaded else colorize('❌', 'red')
            print(f"  {status} {colorize(p.name, 'cyan'):20} {p.description[:50]}")
            print(f"      Type: {p.plugin_type}  |  v{p.version}  |  Author: {p.author}")
            if p.error:
                print(f"      {colorize(f'Error: {p.error}', 'red')}")
            print()
        return

    action = args[0]
    if action == "info" and len(args) >= 2:
        if not engine.plugin_loader:
            print(f"\n  {colorize('⚠️  No hay sistema de plugins cargado', 'yellow')}\n")
            return
        info = engine.plugin_loader.get_plugin_info(args[1])
        if info:
            print(f"\n{separator(title=f' Plugin: {info.name} ')}")
            print(f"  Name:     {info.name}")
            print(f"  Version:  {info.version}")
            print(f"  Type:     {info.plugin_type}")
            print(f"  Author:   {info.author}")
            print(f"  Desc:     {info.description}")
            print(f"  Class:    {info.module_class}")
            print(f"  Path:     {info.path}")
            print(f"  Loaded:   {colorize('✅' if info.loaded else '❌', 'green' if info.loaded else 'red')}")
            if info.error:
                print(f"  Error:    {colorize(info.error, 'red')}")
            print()
        else:
            print(f"\n  {colorize('✘ Plugin no encontrado:', 'red')} '{args[1]}'\n")
    elif action == "create" and len(args) >= 2:
        plugin_type = args[2] if len(args) >= 3 else "attack"
        from bluesky.core.plugin_loader import create_plugin_template, ensure_plugins_directory
        code = create_plugin_template(args[1], plugin_type)
        plugins_dir = ensure_plugins_directory()
        plugin_file = plugins_dir / f"{args[1]}.py"
        plugin_file.write_text(code)
        print(f"\n  {colorize(f'✅ Plugin creado:', 'green')} {plugin_file}\n")
    else:
        print(f"\n  {colorize('Uso:', 'bold')}")
        print(f"    bluesky plugin              Listar plugins")
        print(f"    bluesky plugin list         Listar plugins")
        print(f"    bluesky plugin info <name>  Info de un plugin")
        print(f"    bluesky plugin create <name> [type]  Crear nuevo plugin\n")


def cmd_web(args: list):
    """Inicia el dashboard web."""
    port = 5000
    host = "127.0.0.1"
    debug = False
    open_browser = False

    i = 0
    while i < len(args):
        if args[i] in ("-p", "--port") and i + 1 < len(args):
            port = int(args[i + 1])
            i += 2
        elif args[i] in ("-H", "--host") and i + 1 < len(args):
            host = args[i + 1]
            i += 2
        elif args[i] == "--debug":
            debug = True
            i += 1
        elif args[i] in ("-o", "--open"):
            open_browser = True
            i += 1
        else:
            i += 1

    try:
        from bluesky.web.app import run_web_server
        run_web_server(
            port=port,
            host=host,
            debug=debug,
            open_browser=open_browser,
        )
    except ImportError as e:
        print(f"\n  {colorize('✘ Error al iniciar dashboard web:', 'red')}")
        print(f"  {e}")
        print(f"\n  Instala Flask: {colorize('pip install flask', 'cyan')}\n")
    except Exception as e:
        print(f"\n  {colorize('✘ Error:', 'red')} {e}\n")


def main():
    """Punto de entrada principal."""
    # Parsear --config global ANTES de determinar el comando
    config_path = None
    clean_args = []
    skip_next = False
    for i, arg in enumerate(sys.argv[1:]):
        if skip_next:
            skip_next = False
            continue
        if arg == "--config":
            config_path = sys.argv[i + 2] if i + 2 < len(sys.argv) else None
            skip_next = True
        else:
            clean_args.append(arg)

    # Cargar configuración
    from bluesky.utils.config import get_config
    cfg = get_config()
    if config_path:
        cfg.load(config_path)

    if not clean_args or clean_args[0] in ("-h", "--help", "help"):
        print_banner()
        print_help()
        return

    command = clean_args[0]
    args = clean_args[1:]

    # Comandos que no requieren banner
    no_banner = ["scan", "list", "status", "console", "web"]

    if command not in no_banner:
        print_banner()

    # Verificar Bluetooth activo (excepto para help/list/status)
    if command not in ("list", "help", "status"):
        from bluesky.utils.network import get_adapter_status
        bt_active, bt_msg = get_adapter_status()
        if not bt_active:
            print(f"  {colorize('⚠️', 'yellow')} {bt_msg}")
            print(f"  Algunos módulos pueden no funcionar correctamente.\n")

    # Routing de comandos
    commands = {
        "scan": lambda: cmd_scan(args),
        "list": lambda: cmd_list(),
        "info": lambda: print_module_info(args[0] if args else ""),
        "attack": lambda: cmd_attack(args),
        "services": lambda: cmd_services(args),
        "status": lambda: cmd_status(),
        "report": lambda: cmd_report(args),
        "session": lambda: cmd_session(args),
        "console": lambda: start_console(),
        "config": lambda: cmd_config(args),
        "plugin": lambda: cmd_plugin(args),
        "web": lambda: cmd_web(args),
        "help": lambda: (print_banner(), print_help()),
    }

    cmd = commands.get(command)
    if cmd:
        cmd()
    else:
        print(f"\n  {colorize('✘ Comando desconocido:', 'red')} '{command}'")
        print(f"  Usa '{colorize('bluesky help', 'cyan')}' para ver los comandos disponibles.\n")


if __name__ == "__main__":
    main()
