#!/usr/bin/env python3
"""
bluesky CLI - Bluetooth Security Auditing Framework
====================================================

Interfaz de línea de comandos construida sobre argparse.

Características:
  * Subcomandos con ayuda propia (`bluesky <cmd> --help`) y uso consistente
  * Exit codes: 0 ok · 1 error de ejecución · 2 error de uso
  * Salida --json en scan/list/info/status para scripting y automatización
  * --no-color y soporte de la convención NO_COLOR
  * Sugerencias de módulos con difflib al equivocarse (attack/info)
  * Renderizado unificado de resultados de módulos

Exit codes:
  0  operación correcta
  1  error de ejecución (módulo falló, target no encontrado, ...)
  2  error de uso (argumento inválido, JSON malformado, ...)
"""

import argparse
import difflib
import json
import os
import sys

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

# --------------------------------------------------------------- colores

_NO_COLOR = False
_JSON = False


def _c(text: str, color: str) -> str:
    """colorize() respetando --no-color y la variable NO_COLOR."""
    if _NO_COLOR:
        return text
    return colorize(text, color)


def _set_json_mode(enabled: bool) -> None:
    global _JSON
    _JSON = enabled


def _p(text: str = "") -> None:
    print(text)


def _set_color_mode(no_color: bool) -> None:
    global _NO_COLOR
    _NO_COLOR = no_color or bool(os.environ.get("NO_COLOR"))


def _json_out(data) -> None:
    print(json.dumps(data, indent=2, ensure_ascii=False, default=str))


def _suggest(name: str, candidates: list) -> str:
    """Devuelve '¿quisiste decir X?' si hay una sugerencia cercana."""
    matches = difflib.get_close_matches(name, candidates, n=1, cutoff=0.6)
    if matches:
        return f"\n  {_c('¿quisiste decir', 'dim')} {_c(matches[0], 'cyan')}{_c('?', 'dim')}"
    return ""


def _module_names(engine: ModuleEngine) -> list:
    return [m.get("name", "") for m in engine.list_modules()]


def _print_lines(value, indent: str = "  ") -> None:
    """Imprime un bloque de texto multilínea tolerante a tipos raros."""
    if not isinstance(value, str):
        value = str(value)
    for line in value.split("\n"):
        if line.strip():
            _p(f"{indent}{line.strip()}")


def _section(title: str) -> None:
    _p()
    _p(f"  {_c(title, 'bold')}")


# --------------------------------------------------------------- banner

def print_banner():
    """Banner compacto y profesional."""
    _p()
    _p(f"  {_c('bluesky', 'bold')} {_c(f'v{__version__}', 'dim')} {_c('·', 'faint')} {__description__}")
    _p(f"  {_c('Linux · Windows · Termux — úsalo solo en auditorías autorizadas', 'dim')}")
    _p()


def print_help():
    """Ayuda principal agrupada por secciones."""
    print_banner()
    _p(f"{_c('USO', 'bold')}")
    _p("  bluesky <COMANDO> [OPCIONES]")
    _p()
    _p(f"{_c('AUDITORÍA', 'bold')}")
    rows = [
        ("scan", "Escanear dispositivos cercanos (--ble | --classic, --export CSV)"),
        ("services <MAC>", "Enumerar servicios SDP de un dispositivo"),
        ("vuln <MAC>", "Análisis de vulnerabilidades (13+ checks)"),
        ("attack <mod> [target]", "Ejecutar un módulo de ataque"),
        ("auto [target]", "Autopilot: scan → vuln → attack → report"),
        ("spam <target|all>", "BTSpam: inundación Bluetooth (3 técnicas)"),
    ]
    for cmd, desc in rows:
        _p(f"  {_c(cmd.ljust(24), 'cyan')} {desc}")
    _p()
    _p(f"{_c('CATÁLOGO Y APRENDIZAJE', 'bold')}")
    rows = [
        ("list", "Listar módulos del catálogo"),
        ("info <módulo>", "Detalle de un módulo (CVE, hardware, uso)"),
        ("educate [módulo]", "Modo educativo: qué es, cómo funciona, mitigación"),
    ]
    for cmd, desc in rows:
        _p(f"  {_c(cmd.ljust(24), 'cyan')} {desc}")
    _p()
    _p(f"{_c('ENTORNO', 'bold')}")
    rows = [
        ("status", "Estado del hardware y backends Bluetooth"),
        ("session <list|save|load|summary>", "Gestionar sesiones de auditoría"),
        ("report", "Generar reporte de la sesión (--html | --json | --txt)"),
        ("config", "Ver o editar la configuración"),
        ("plugin", "Gestionar plugins"),
    ]
    for cmd, desc in rows:
        _p(f"  {_c(cmd.ljust(24), 'cyan')} {desc}")
    _p()
    _p(f"{_c('INTERFAZ', 'bold')}")
    rows = [
        ("console", "Consola interactiva estilo Metasploit (REPL)"),
        ("web", "Dashboard web (--port, --host, --open)"),
    ]
    for cmd, desc in rows:
        _p(f"  {_c(cmd.ljust(24), 'cyan')} {desc}")
    _p()
    _p(f"{_c('OPCIONES GLOBALES', 'bold')}")
    rows = [
        ("--config <archivo>", "Archivo de configuración personalizado"),
        ("--json", "Salida JSON (scan, list, info, status)"),
        ("--no-color", "Desactivar color (respeta NO_COLOR)"),
        ("--version", "Mostrar la versión y salir"),
    ]
    for flag, desc in rows:
        _p(f"  {_c(flag.ljust(24), 'cyan')} {desc}")
    _p()
    _p(f"{_c('EJEMPLOS', 'bold')}")
    for ex in [
        "bluesky scan --ble --timeout 12",
        "bluesky scan --export dispositivos.csv",
        "bluesky attack bluejacking AA:BB:CC:DD:EE:FF",
        "bluesky vuln AA:BB:CC:DD:EE:FF",
        "bluesky auto --mode detect",
        "bluesky spam all --method obex_spam --rate 20",
        "bluesky educate knob",
        "bluesky --json list",
    ]:
        _p(f"  {_c('$', 'faint')} {ex}")
    _p()


# --------------------------------------------------------------- scan

def cmd_scan(args: list):
    """Ejecuta un escaneo de dispositivos Bluetooth."""
    from bluesky.utils.config import get_config
    from bluesky.modules.scanners.device_scanner import DeviceScanner

    p = argparse.ArgumentParser(
        prog="bluesky scan",
        description="Escanear dispositivos Bluetooth cercanos (BR/EDR y/o BLE).",
    )
    p.add_argument("--ble", action="store_true", help="escanear solo dispositivos BLE")
    p.add_argument("--classic", action="store_true", help="escanear solo Bluetooth clásico")
    p.add_argument("--timeout", type=int, default=None, metavar="S",
                   help="duración del escaneo en segundos (default: valor de config)")
    p.add_argument("--export", metavar="ARCHIVO", default=None,
                   help="guardar los dispositivos descubiertos en ARCHIVO (.csv o .json)")
    p.add_argument("--json", action="store_true", help="salida JSON para scripting")
    ns = p.parse_args(args)

    scan_type = "all"
    if ns.ble and not ns.classic:
        scan_type = "ble"
    elif ns.classic and not ns.ble:
        scan_type = "classic"

    cfg = get_config()
    timeout = ns.timeout if ns.timeout is not None else cfg.get("scanner.scan_duration", 8)

    if ns.json:
        scanner = DeviceScanner(options={"type": scan_type, "timeout": str(timeout)})
        result = scanner.run()
        devices = result.get("data", {}).get("devices", []) if result.get("success") else []
        if ns.export:
            rc_export = _export_devices(ns.export, devices, quiet=True)
            if rc_export != 0:
                return rc_export
        _json_out({
            "success": result.get("success", False),
            "scan_type": scan_type,
            "timeout": timeout,
            "count": len(devices),
            "devices": devices,
        })
        return 0 if result.get("success") else 1

    _p()
    _p(separator(title=" Escaneo "))
    _p(f"  Tipo: {scan_type.upper()}  |  Timeout: {timeout}s")
    _p()

    scanner = DeviceScanner(options={"type": scan_type, "timeout": str(timeout)})
    result = scanner.run()

    if result.get("success"):
        devices = result.get("data", {}).get("devices", [])
        _p(f"  {_c('OK', 'green')} {len(devices)} dispositivo(s) encontrado(s)")
        _p()
        for i, dev in enumerate(devices, 1):
            if not isinstance(dev, dict):
                _p(f"  {i:2d}. {dev}")
                continue
            name = dev.get("name", "Unknown")
            mac = dev.get("mac", "N/A")
            dev_type = dev.get("type", "?")
            info = dev.get("info", {}) if isinstance(dev.get("info"), dict) else {}
            rssi = info.get("rssi", "")
            paired = info.get("paired", False)
            vendor = dev.get("vendor", "")

            ttype = _c(target_type_icon(dev_type), "reset")
            paired_str = f" {_c('(emparejado)', 'yellow')}" if paired else ""
            rssi_str = f" [{rssi} dBm]" if rssi else ""
            vendor_str = f" {_c('· ' + vendor, 'dim')}" if vendor else ""
            _p(f"  {i:2d}. {ttype} {_c(name, 'cyan')} {_c(mac, 'dim')}{vendor_str}{rssi_str}{paired_str}")
        if ns.export:
            rc_export = _export_devices(ns.export, devices)
            if rc_export != 0:
                return rc_export
    else:
        msg = result.get("data", {}).get("message") or result.get("error") or "No se encontraron dispositivos"
        _p(f"  {_c('AVISO', 'yellow')} {msg}")
    _p()
    return 0 if result.get("success") else 1


def _export_devices(path: str, devices: list, quiet: bool = False) -> int:
    """Guarda la lista de dispositivos en CSV o JSON. 0 ok · 1 error de escritura."""
    import io
    from pathlib import Path as _Path
    from bluesky.utils.csv_export import devices_to_csv

    try:
        out = _Path(path)
        if str(out).lower().endswith(".json"):
            payload = {"count": len(devices), "devices": devices}
            out.write_text(json.dumps(payload, indent=2, ensure_ascii=False, default=str),
                           encoding="utf-8")
        else:
            # CSV por defecto (cualquier otra extensión), con BOM para Excel.
            buf = io.StringIO()
            buf.write("\ufeff")  # BOM utf-8-sig
            buf.write(devices_to_csv(devices))
            out.write_text(buf.getvalue(), encoding="utf-8")
        if not quiet:
            _p(f"  {_c('OK', 'green')} {len(devices)} dispositivo(s) exportados a {_c(str(out), 'cyan')}")
        return 0
    except OSError as e:
        if not quiet:
            _p(f"  {_c('ERROR', 'red')} no se pudo escribir {path}: {e}")
        else:
            # Modo --json: stdout debe seguir siendo JSON limpio
            print(f"error: no se pudo escribir {path}: {e}", file=sys.stderr)
        return 1


# --------------------------------------------------------------- services

def cmd_services(args: list):
    """Enumera servicios SDP de un dispositivo."""
    from bluesky.modules.scanners.service_scanner import ServiceScanner

    p = argparse.ArgumentParser(
        prog="bluesky services",
        description="Enumerar servicios SDP de un dispositivo Bluetooth.",
    )
    p.add_argument("mac", help="dirección MAC del dispositivo")
    p.add_argument("--json", action="store_true", help="salida JSON para scripting")
    ns = p.parse_args(args)

    scanner = ServiceScanner(target=ns.mac)
    result = scanner.run()

    services = result.get("data", {}).get("services", []) if result.get("success") else []
    if ns.json:
        _json_out({
            "success": result.get("success", False),
            "target": ns.mac,
            "count": len(services),
            "services": services,
        })
        return 0 if result.get("success") else 1

    _p()
    _p(separator(title=f" Servicios de {ns.mac} "))
    if result.get("success"):
        _p(f"  {_c('OK', 'green')} {len(services)} servicio(s) encontrado(s)")
        for svc in services:
            if not isinstance(svc, dict):
                _p(f"  {svc}")
                continue
            name = svc.get("name", "Unknown")
            channel = svc.get("channel", "")
            risk = svc.get("risk", "low")
            icon = severity_icon(risk)
            ch = f" (canal {channel})" if channel else ""
            _p(f"  {icon} {_c(name, 'cyan')}{ch}")
            if risk == "high":
                _p(f"     {_c('Servicio de alto riesgo: posible superficie de ataque', 'yellow')}")
    else:
        error = result.get("error", "Error desconocido")
        _p(f"  {_c('ERROR', 'red')} {error}")
    _p()
    return 0 if result.get("success") else 1


# --------------------------------------------------------------- attack

def cmd_attack(args: list):
    """Ejecuta un módulo de ataque sobre un target."""
    p = argparse.ArgumentParser(
        prog="bluesky attack",
        description="Ejecutar un módulo de ataque del catálogo.",
        epilog="ejemplo: bluesky attack bluejacking AA:BB:CC:DD:EE:FF",
    )
    p.add_argument("module", help="nombre del módulo (ver 'bluesky list')")
    p.add_argument("target", nargs="?", default="", help="MAC del target (alternativa a --target)")
    p.add_argument("--target", dest="target_opt", metavar="MAC", help="MAC del target")
    p.add_argument("--options", metavar="JSON", help="opciones del módulo como JSON")
    p.add_argument("--json", action="store_true", help="salida JSON para scripting")
    ns = p.parse_args(args)

    options = {}
    if ns.options:
        try:
            options = json.loads(ns.options)
        except json.JSONDecodeError as e:
            p.error(f"--options no es JSON válido: {e}")

    engine = ModuleEngine()
    target = ns.target_opt or ns.target

    if not engine.get_module(ns.module):
        _p()
        _p(f"  {_c('ERROR', 'red')} Módulo no encontrado: '{ns.module}'"
           f"{_suggest(ns.module, _module_names(engine))}")
        _p(f"  Usa {_c('bluesky list', 'cyan')} para ver los módulos disponibles.")
        _p()
        return 2

    if not ns.json:
        _p()
        _p(separator(title=f" Ejecutando: {ns.module} "))
        if target:
            _p(f"  Target: {_c(target, 'cyan')}")
        if options:
            _p(f"  Opciones: {options}")
        _p()

    result = engine.run_module(ns.module, target=target, options=options)
    data = result.get("data", {}) if isinstance(result.get("data"), dict) else {}

    if ns.json:
        _json_out(result)
        return 0 if result.get("success") else 1

    if result.get("success"):
        _p(f"  {_c('OK', 'green')} Módulo ejecutado correctamente")
    else:
        _p(f"  {_c('AVISO', 'yellow')} Módulo completado con notas")

    for key in ("message", "warning", "summary", "risk", "info"):
        value = data.get(key)
        if isinstance(value, str) and len(value) > 5:
            _section(key.capitalize())
            _print_lines(value)

    vulns = data.get("vulnerabilities") or []
    if vulns:
        _section("Vulnerabilidades detectadas")
        for v in vulns:
            if not isinstance(v, dict):
                _p(f"    {v}")
                continue
            _p(f"    {severity_icon(v.get('severity', 'low'))} {_c(v.get('name', ''), 'yellow')}")
            if v.get("cve"):
                _p(f"       CVE: {_c(v['cve'], 'dim')}")
            if v.get("detail"):
                _p(f"       {v['detail']}")

    devices = data.get("devices") or []
    if devices:
        _section("Dispositivos")
        _p(format_device_list(devices))

    services = data.get("services") or []
    if services:
        _section("Servicios")
        _p(format_service_list(services))

    vuln_devices = data.get("vulnerable_devices") or []
    if vuln_devices:
        _section(f"{len(vuln_devices)} dispositivo(s) VULNERABLE(S)")
        for vd in vuln_devices:
            if isinstance(vd, dict):
                _p(f"    {_c('!', 'red')} {vd.get('name', '?')} ({vd.get('mac', 'N/A')})")

    error = result.get("error")
    if error and not result.get("success"):
        _p()
        _p(f"  {_c('ERROR', 'red')} {error}")
    _p()
    return 0 if result.get("success") else 1


# --------------------------------------------------------------- list / info

def cmd_list(args: list):
    """Lista los módulos del catálogo."""
    p = argparse.ArgumentParser(
        prog="bluesky list",
        description="Listar los módulos del catálogo (escáneres, ataques y exploits).",
    )
    p.add_argument("--json", action="store_true", help="salida JSON para scripting")
    ns = p.parse_args(args)

    engine = ModuleEngine()
    modules = engine.list_modules()

    if ns.json:
        _json_out({"count": len(modules), "modules": modules})
        return 0

    _p()
    _p(separator(title=" Módulos "))
    _p(f"  {_c(f'{len(modules)} módulo(s) cargado(s)', 'bold')}")
    _p()

    by_severity = {}
    for m in modules:
        by_severity.setdefault(m.get("severity", "low"), []).append(m)

    for severity in ("critical", "high", "medium", "low"):
        if severity not in by_severity:
            continue
        _p(f"  {severity_icon(severity)} {_c(severity.upper(), 'bold')}")
        for m in by_severity[severity]:
            name = str(m.get("name", "?"))
            desc = str(m.get("description", ""))[:66]
            ttype = _c(target_type_icon(m.get("target_type", "both")), "reset")
            cve = m.get("cve", "")
            cve_str = f" [{cve}]" if cve else ""
            _p(f"    {ttype} {_c(name.ljust(18), 'green')} {desc}{_c(cve_str, 'dim')}")
        _p()

    _p(f"  {_c('Tip:', 'dim')} {_c('bluesky info <módulo>', 'cyan')} {_c('para más detalles', 'dim')}")
    _p()
    return 0


def print_module_info(module_name: str, as_json: bool = False):
    """Muestra información detallada de un módulo."""
    engine = ModuleEngine()
    mod_cls = engine.get_module(module_name)

    if not mod_cls:
        _p()
        _p(f"  {_c('ERROR', 'red')} Módulo no encontrado: '{module_name}'"
           f"{_suggest(module_name, _module_names(engine))}")
        _p(f"  Usa {_c('bluesky list', 'cyan')} para ver los módulos disponibles.")
        _p()
        return 2

    info = mod_cls().get_info()
    payload = {
        "name": info.get("name", module_name),
        "description": info.get("description", ""),
        "target_type": info.get("target_type", "both"),
        "severity": info.get("severity", "low"),
        "cve": info.get("cve"),
        "requires_root": bool(info.get("requires_root")),
        "requires_hardware": info.get("requires_hardware", []),
        "version": info.get("version", "?"),
        "usage": f"bluesky attack {info.get('name', module_name)} <MAC>",
    }
    if as_json:
        _json_out(payload)
        return 0

    _p()
    _p(separator(title=f" {payload['name']} "))
    _p(f"  {_c(payload['description'], 'dim')}")
    _p()
    rows = [
        ("Tipo de target", f"{target_type_icon(payload['target_type'])} {payload['target_type'].upper()}"),
        ("Severidad", f"{severity_icon(payload['severity'])} {payload['severity'].title()}"),
        ("CVE", payload["cve"] or "N/A"),
        ("Requiere root", "sí" if payload["requires_root"] else "no"),
        ("Hardware", ", ".join(payload["requires_hardware"]) or "ninguno (solo adaptador interno)"),
        ("Versión", payload["version"]),
    ]
    for k, v in rows:
        _p(f"  {_c(k.ljust(18), 'dim')} {v}")
    _p()
    _p(f"  {_c('USO', 'bold')}")
    _p(f"    {_c(payload['usage'], 'cyan')}")
    _p()
    return 0


# --------------------------------------------------------------- vuln

def cmd_vuln(args: list):
    """Ejecuta VulnScanner: análisis de vulnerabilidades Bluetooth."""
    p = argparse.ArgumentParser(
        prog="bluesky vuln",
        description="Análisis de vulnerabilidades Bluetooth contra 13+ checks conocidos "
                    "(KNOB, BIAS, BLUFFS, BlueBorne, BlueFrag, SweynTooth, ...).",
        epilog="ejemplo: bluesky vuln AA:BB:CC:DD:EE:FF --options '{\"SCAN_TYPE\": \"quick\"}'",
    )
    p.add_argument("mac", help="dirección MAC del dispositivo")
    p.add_argument("--options", metavar="JSON", help="opciones del escáner como JSON")
    p.add_argument("--json", action="store_true", help="salida JSON para scripting")
    ns = p.parse_args(args)

    options = {}
    if ns.options:
        try:
            options = json.loads(ns.options)
        except json.JSONDecodeError as e:
            p.error(f"--options no es JSON válido: {e}")

    engine = ModuleEngine()

    if not ns.json:
        _p()
        _p(separator(title=" VulnScanner "))
        _p(f"  Target: {_c(ns.mac, 'cyan')}")
        if options:
            _p(f"  Opciones: {options}")
        _p()

    result = engine.run_module("vuln", target=ns.mac, options=options)
    data = result.get("data", {}) if isinstance(result.get("data"), dict) else {}

    if ns.json:
        _json_out(result)
        return 0 if result.get("success") else 1

    _p(f"  {_c('OK', 'green') if result.get('success') else _c('AVISO', 'yellow')} "
       f"Análisis {'completado' if result.get('success') else 'completado con notas'}")

    dev_info = data.get("device_info", {})
    if isinstance(dev_info, dict) and dev_info:
        _section("Dispositivo")
        _p(f"    Nombre:      {dev_info.get('name', 'Unknown')}")
        _p(f"    MAC:         {dev_info.get('mac', 'N/A')}")
        _p(f"    Clase:       {dev_info.get('class', 'Unknown')}")
        _p(f"    Fabricante:  {dev_info.get('manufacturer', 'Unknown')}")

    vulns = data.get("vulnerabilities") or []
    found = [v for v in vulns if isinstance(v, dict) and v.get("vulnerable", False)]
    if found:
        _section("Vulnerabilidades encontradas")
        for v in found:
            sev_color = "red" if v.get("severity") == "critical" else "yellow"
            _p(f"    {severity_icon(v.get('severity', 'low'))} "
               f"{_c(str(v.get('id', '?')).ljust(18), sev_color)} {str(v.get('name', ''))[:60]}")
            if v.get("cve"):
                _p(f"       CVE: {_c(v['cve'], 'dim')}")
            if v.get("evidence"):
                _p(f"       → {str(v['evidence'])[:80]}")
            if v.get("module"):
                hint = f"bluesky attack {v['module']} {ns.mac}"
                _p(f"       {_c(hint, 'cyan')}")
            _p()

    summary = data.get("summary")
    if summary and not found:
        _section("Resumen")
        _print_lines(summary)

    recs = data.get("recommendations") or []
    if recs:
        _section("Recomendaciones")
        for r in recs:
            _p(f"    {r}")
        _p()

    stats = data.get("stats", {})
    if isinstance(stats, dict) and stats:
        _section("Estadísticas")
        _p(f"    Checks: {stats.get('total_checks', 0)}  |  "
           f"Vulnerables: {stats.get('vulnerable', 0)}  |  "
           f"Críticas: {stats.get('critical', 0)}  |  "
           f"Altas: {stats.get('high', 0)}")
        _p()

    error = result.get("error")
    if error and not result.get("success"):
        _p(f"  {_c('ERROR', 'red')} {error}")
    _p()
    return 0 if result.get("success") else 1


# --------------------------------------------------------------- auto

def cmd_auto(args: list):
    """Ejecuta Autopilot: scan → vuln → attack → report."""
    p = argparse.ArgumentParser(
        prog="bluesky auto",
        description="Autopilot: pipeline automatizado escaneo → vulnerabilidades → "
                    "ataques → reporte.",
    )
    p.add_argument("target", nargs="?", default="", help="MAC concreta (opcional: por defecto escanea)")
    p.add_argument("--mode", choices=("detect", "attack", "full"), default="full",
                   help="modo de operación (default: full)")
    p.add_argument("--chain", metavar="CSV", help="cadena personalizada: mod1,mod2,mod3")
    p.add_argument("--timeout", type=int, metavar="S", help="timeout por módulo (default: 30)")
    p.add_argument("--json", action="store_true", help="salida JSON para scripting")
    ns = p.parse_args(args)

    options = {"MODE": ns.mode}
    if ns.chain:
        options["CHAIN"] = ns.chain
    if ns.timeout is not None:
        options["TIMEOUT"] = str(ns.timeout)

    engine = ModuleEngine()

    if not ns.json:
        _p()
        _p(separator(title=f" Autopilot — modo {ns.mode.upper()} "))
        if ns.target:
            _p(f"  Target: {_c(ns.target, 'cyan')}")
        _p()

    result = engine.run_module("autopilot", target=ns.target, options=options)
    data = result.get("data", {}) if isinstance(result.get("data"), dict) else {}

    if ns.json:
        _json_out(result)
        return 0 if result.get("success") else 1

    summary = data.get("summary", "")
    if summary:
        _print_lines(summary)

    stats = data.get("stats", {})
    if isinstance(stats, dict) and stats:
        _section("Estadísticas finales")
        _p(f"    Targets:           {stats.get('targets', 0)}")
        _p(f"    Ataques:           {stats.get('attacks_total', 0)}")
        _p(f"    Exitosos:          {stats.get('attacks_successful', 0)}")
        _p(f"    Vulns encontradas: {stats.get('vulnerabilities_found', 0)}")
        _p()

    report_path = data.get("report_path")
    if report_path:
        _p(f"  {_c('Reporte:', 'dim')} {_c(str(report_path), 'green')}")

    error = result.get("error")
    if error and not result.get("success"):
        _p(f"  {_c('ERROR', 'red')} {error}")
    _p()
    return 0 if result.get("success") else 1


# --------------------------------------------------------------- spam

def cmd_spam(args: list):
    """Ejecuta BTSpam contra un target o contra todos los dispositivos."""
    p = argparse.ArgumentParser(
        prog="bluesky spam",
        description="BTSpam: inundación Bluetooth con solicitudes de emparejamiento, "
                    "mensajes OBEX Push y conexiones RFCOMM.",
        epilog="usa 'bluesky spam all' para escanear y atacar todos los dispositivos",
    )
    p.add_argument("target", help="MAC del dispositivo o 'all' para atacar a todos")
    p.add_argument("--method", choices=("all", "pairing_flood", "obex_spam", "connection_flood"),
                   default="all", help="técnica de spam (default: all)")
    p.add_argument("--rate", type=int, default=10, metavar="N",
                   help="paquetes por segundo, 1-100 (default: 10)")
    p.add_argument("--count", type=int, default=50, metavar="N",
                   help="número de iteraciones, 0=infinito (default: 50)")
    p.add_argument("--duration", type=int, default=30, metavar="S",
                   help="duración máxima en segundos (default: 30)")
    p.add_argument("--delay", type=int, default=100, metavar="MS",
                   help="delay entre ráfagas en ms (default: 100)")
    p.add_argument("--message", default="👽 bluesky Spam!", metavar="TXT",
                   help="mensaje para OBEX Push")
    p.add_argument("--json", action="store_true", help="salida JSON para scripting")
    ns = p.parse_args(args)

    if not 1 <= ns.rate <= 100:
        p.error("--rate debe estar entre 1 y 100")
    if ns.count < 0:
        p.error("--count no puede ser negativo")

    options = {
        "METHOD": ns.method,
        "RATE": str(ns.rate),
        "COUNT": str(ns.count),
        "DURATION": str(ns.duration),
        "DELAY": str(ns.delay),
        "MESSAGE": ns.message,
    }

    engine = ModuleEngine()

    if not ns.json:
        _p()
        title = " BTSpam — todos los dispositivos " if ns.target == "all" else " BTSpam "
        _p(separator(title=title))
        if ns.target == "all":
            _p(f"  {_c('Paso 1-2:', 'dim')} escaneando dispositivos Bluetooth...")
        else:
            _p(f"  Target: {_c(ns.target, 'cyan')}")
        _p(f"  {_c('Técnica:', 'dim')} {ns.method}  {_c('Rate:', 'dim')} {ns.rate}/s")
        _p()

    result = engine.run_module("btspam", target=ns.target, options=options)
    data = result.get("data", {}) if isinstance(result.get("data"), dict) else {}

    if ns.json:
        _json_out(result)
        return 0 if result.get("success") else 1

    _p(f"  {_c('OK', 'green') if result.get('success') else _c('AVISO', 'yellow')} "
       f"BTSpam {'ejecutado correctamente' if result.get('success') else 'completado con notas'}")

    for key in ("message", "warning", "summary"):
        value = data.get(key)
        if isinstance(value, str) and value.strip():
            _section(key.capitalize())
            _print_lines(value)

    devices = data.get("devices") or data.get("devices_found") or []
    if devices:
        _section("Dispositivos")
        for d in devices:
            if isinstance(d, dict):
                _p(f"    {_c(d.get('mac', '?'), 'cyan')} - {_c(d.get('name', 'Unknown'), 'dim')}")

    hit_detail = data.get("targets_hit_detail") or []
    if hit_detail:
        _section("Dispositivos impactados")
        for d in hit_detail:
            if isinstance(d, dict):
                _p(f"    {_c('OK', 'green')} {_c(d.get('mac', '?'), 'green')} - {d.get('name', '?')}")

    stats = data.get("stats", {})
    if isinstance(stats, dict) and stats:
        _section("Estadísticas")
        for k, v in stats.items():
            if k == "targets_hit":
                continue
            _p(f"    {k}: {v}")
        targets = stats.get("targets_hit") or []
        if targets:
            _p(f"    targets_hit: {', '.join(list(targets)[:5])}")

    error = result.get("error")
    if error and not result.get("success"):
        _p(f"  {_c('ERROR', 'red')} {error}")
    _p()
    return 0 if result.get("success") else 1


# --------------------------------------------------------------- status

def cmd_status(args: list):
    """Muestra el estado del hardware Bluetooth."""
    p = argparse.ArgumentParser(
        prog="bluesky status",
        description="Estado del adaptador, capacidades, entorno y backends Bluetooth.",
    )
    p.add_argument("--json", action="store_true", help="salida JSON para scripting")
    ns = p.parse_args(args)

    hw = HardwareDetector()
    adapter = hw.get_adapter_info()
    caps = hw.get_capabilities()
    bt_devices = hw.get_bluetooth_devices()
    from bluesky.utils.platform import get_os_name, get_available_backends
    backends = get_available_backends()
    available_backends = [k for k, v in backends.items() if v]

    if ns.json:
        _json_out({
            "adapter": adapter,
            "capabilities": caps,
            "devices": bt_devices,
            "os": get_os_name(),
            "python": sys.version.split()[0],
            "backends": available_backends,
        })
        return 0

    _p()
    _p(separator(title=" Estado del sistema "))

    _section("Adaptador Bluetooth")
    ok = adapter.get("available")
    _p(f"    {'Disponible:':14} {_c('sí', 'green') if ok else _c('no', 'red')}")
    if ok:
        _p(f"    {'Interfaz:':14} {adapter.get('interface', 'N/A')}")
        _p(f"    {'MAC:':14} {adapter.get('mac', 'N/A')}")
        _p(f"    {'Encendido:':14} {_c('sí', 'green') if adapter.get('powered') else _c('no', 'red')}")
        _p(f"    {'Tipo:':14} {adapter.get('type', 'N/A')}")

    _section("Capacidades")
    cap_rows = [
        ("BLE", "ble_support"), ("Classic", "classic_support"),
        ("Root/Admin", "is_root"), ("Termux", "is_termux"),
        ("Windows", "is_windows"), ("WSL", "is_wsl"),
        ("Bleak lib", "bleak_available"), ("CSR Dongle", "csr_dongle"),
    ]
    for label, key in cap_rows:
        val = caps.get(key)
        _p(f"    {label + ':':14} {_c('sí', 'green') if val else _c('no', 'dim')}")

    _section("Entorno")
    _p(f"    {'Sistema:':14} {get_os_name()}")
    _p(f"    {'Python:':14} {sys.version.split()[0]}")
    _p(f"    {'Plataforma:':14} {caps.get('platform', 'unknown').title()}")

    _section("Backends")
    if available_backends:
        for b in available_backends:
            _p(f"    {_c('sí', 'green')} {b}")
    else:
        _p(f"    {_c('sin backends Bluetooth disponibles', 'yellow')}")

    if bt_devices:
        _section("Adaptadores detectados")
        for dev in bt_devices:
            if isinstance(dev, dict):
                _p(f"    {dev.get('interface', '')}: {dev.get('name', 'Unknown')} "
                   f"({dev.get('mac', 'N/A')}) [{dev.get('platform', 'linux')}]")
    else:
        _p()
        _p(f"  {_c('No se detectaron adaptadores Bluetooth', 'yellow')}")
        _p("    Asegúrate de que Bluetooth esté encendido:")
        if caps.get("is_windows"):
            _p("    Windows: Configuración → Bluetooth y dispositivos → Activar")
        elif caps.get("is_termux"):
            _p("    Termux: termux-bluetooth-enable")
        else:
            _p("    Linux:   sudo hciconfig hci0 up  ·  systemctl start bluetooth")

    _p()
    return 0


# --------------------------------------------------------------- report

def cmd_report(args: list):
    """Genera un reporte de la sesión actual."""
    p = argparse.ArgumentParser(
        prog="bluesky report",
        description="Generar reporte de la sesión de auditoría actual.",
    )
    fmt = p.add_mutually_exclusive_group()
    fmt.add_argument("--html", action="store_true", help="reporte HTML")
    fmt.add_argument("--json", action="store_true", help="reporte JSON")
    fmt.add_argument("--txt", action="store_true", help="reporte texto (default)")
    p.add_argument("-o", "--output", metavar="FILE", help="archivo de salida")
    ns = p.parse_args(args)

    from bluesky.utils.config import get_config
    cfg = get_config()
    report_fmt = cfg.get("general.report_format", "txt")
    if ns.html:
        report_fmt = "html"
    elif ns.json:
        report_fmt = "json"

    session = Session()
    if not session.load():
        import datetime
        session.name = "default"
        session.targets = []
        session.results = []
        session.created_at = datetime.datetime.now().isoformat()
        _p(f"  {_c('Creando sesión por defecto...', 'dim')}")

    summary = session.summary()
    reporter = Reporter(summary)

    output_file = ns.output
    if not output_file:
        output_file = f"bluesky_report_{session.name}.{report_fmt}"

    _p()
    _p(separator(title=" Reporte "))
    _p(f"  Formato: {report_fmt.upper()}")
    _p(f"  Sesión:  {session.name}")
    _p(f"  Archivo: {output_file}")
    _p()

    if report_fmt == "html":
        reporter.to_html(output_file)
    elif report_fmt == "json":
        reporter.to_json(output_file)
    else:
        report_text = reporter.to_txt(output_file)
        for line in report_text.split("\n")[:20]:
            _p(f"  {line}")

    _p()
    _p(f"  {_c('OK', 'green')} Reporte guardado: {output_file}")
    _p()
    return 0


# --------------------------------------------------------------- session

def cmd_session(args: list):
    """Gestiona sesiones de auditoría."""
    p = argparse.ArgumentParser(
        prog="bluesky session",
        description="Gestionar sesiones de auditoría.",
    )
    sub = p.add_subparsers(dest="action")
    sub.add_parser("list", help="listar sesiones guardadas")
    sp_save = sub.add_parser("save", help="guardar sesión actual")
    sp_save.add_argument("name")
    sp_load = sub.add_parser("load", help="cargar una sesión")
    sp_load.add_argument("name")
    sub.add_parser("summary", help="resumen de la sesión actual")
    ns = p.parse_args(args)

    session = Session()

    if ns.action in (None, "list"):
        sessions = Session.list_sessions()
        if sessions:
            _p()
            _p(f"  {_c('Sesiones guardadas:', 'bold')}")
            for s in sessions:
                _p(f"    {_c('·', 'faint')} {s}")
            _p()
        else:
            _p()
            _p(f"  {_c('No hay sesiones guardadas', 'yellow')}")
            _p(f"  Crea una con {_c('bluesky session save <nombre>', 'cyan')}")
            _p()
        return 0

    if ns.action == "save":
        session.name = ns.name
        session._save()
        _p()
        _p(f"  {_c('OK', 'green')} Sesión guardada: {ns.name}")
        _p()
        return 0

    if ns.action == "load":
        if session.load(ns.name):
            summary = session.summary()
            _p()
            _p(f"  {_c('OK', 'green')} Sesión cargada: {ns.name}")
            _p(f"  Targets: {summary.get('total_targets', 0)}")
            _p(f"  Resultados: {summary.get('total_results', 0)}")
            _p(f"  Exitosos: {summary.get('successful_attacks', 0)}")
            _p()
            return 0
        _p()
        _p(f"  {_c('ERROR', 'red')} Sesión no encontrada: {ns.name}")
        _p()
        return 1

    # summary
    if session.load():
        summary = session.summary()
        _p()
        _p(separator(title=f" Sesión: {session.name} "))
        created = str(summary.get("created_at", "N/A"))
        _p(f"  Creada:  {created[:19]}")
        _p(f"  Targets: {summary.get('total_targets', 0)}")
        _p(f"  Tests:   {summary.get('total_results', 0)}")
        _p(f"  Éxitos:  {summary.get('successful_attacks', 0)}")
        _p(f"  Fallos:  {summary.get('failed_attacks', 0)}")
        _p()
        return 0
    _p()
    _p(f"  {_c('No hay sesión activa', 'yellow')}")
    _p(f"  Usa {_c('bluesky session save <nombre>', 'cyan')} para crear una.")
    _p()
    return 1


# --------------------------------------------------------------- config

def cmd_config(args: list):
    """Gestiona la configuración de bluesky."""
    p = argparse.ArgumentParser(
        prog="bluesky config",
        description="Ver o editar la configuración de bluesky.",
    )
    sub = p.add_subparsers(dest="action")
    sub.add_parser("show", help="mostrar la configuración (acción por defecto)")
    sp_set = sub.add_parser("set", help="cambiar un valor (CLAVE=VALOR)")
    sp_set.add_argument("key_value", metavar="CLAVE=VALOR", help="ej: general.timeout=60")
    sub.add_parser("save", help="persistir los cambios")
    sub.add_parser("reset", help="restaurar los valores por defecto")
    sp_fav = sub.add_parser("favorite", help="gestionar dispositivos favoritos")
    fav_sub = sp_fav.add_subparsers(dest="fav_action")
    fav_add = fav_sub.add_parser("add", help="añadir favorito")
    fav_add.add_argument("address", help="dirección MAC")
    fav_add.add_argument("name", nargs="?", default="", help="nombre opcional")
    fav_add.add_argument("type", nargs="?", default="auto", help="tipo: auto|classic|ble")
    fav_rm = fav_sub.add_parser("remove", help="eliminar favorito")
    fav_rm.add_argument("address", help="dirección MAC")
    ns = p.parse_args(args)

    from bluesky.utils.config import get_config, parse_key_value
    cfg = get_config()

    if ns.action in (None, "show"):
        _p()
        _p(separator(title=" Configuración "))
        _p(f"  Archivo: {_c(str(cfg._path or '(defaults)'), 'dim')}")
        _p(f"  Modificado: {_c('sí' if cfg.is_dirty() else 'no', 'dim')}")
        _p()

        def _print_section(data, indent: int = 2):
            for key, value in data.items():
                if isinstance(value, dict):
                    _p(f"  {' ' * indent}{_c(f'[{key}]', 'bold')}")
                    _print_section(value, indent + 2)
                elif isinstance(value, list):
                    if value:
                        _p(f"  {' ' * indent}{key}:")
                        for item in value:
                            _p(f"  {' ' * (indent + 2)}- {item}")
                    else:
                        _p(f"  {' ' * indent}{key}: []")
                else:
                    colored = _c(str(value), "cyan") if value else _c(str(value), "dim")
                    _p(f"  {' ' * indent}{key}: {colored}")

        _print_section(cfg.get_all())
        _p()
        _p(f"  {_c('Tip:', 'dim')} {_c('bluesky config set <clave>=<valor>', 'cyan')}"
           f" {_c('para cambiar valores', 'dim')}")
        _p(f"  {_c('Tip:', 'dim')} {_c('bluesky config save', 'cyan')}"
           f" {_c('para persistir cambios', 'dim')}")
        _p()
        return 0

    if ns.action == "set":
        try:
            key, value = parse_key_value(ns.key_value)
        except ValueError as e:
            _p()
            _p(f"  {_c('ERROR', 'red')} {e}")
            _p()
            return 2
        old = cfg.get(key)
        cfg.set(key, value)
        _p()
        _p(f"  {_c('OK', 'green')} Config actualizada: {key} = {value}")
        if old is not None:
            _p(f"  {_c(f'(anterior: {old})', 'dim')}")
        _p(f"  {_c('Cambios sin guardar. Usa bluesky config save para persistir.', 'yellow')}")
        _p()
        return 0

    if ns.action == "save":
        try:
            cfg.save()
            _p()
            _p(f"  {_c('OK', 'green')} Configuración guardada en: {cfg._path}")
            _p()
            return 0
        except Exception as e:
            _p()
            _p(f"  {_c('ERROR', 'red')} Guardando: {e}")
            _p()
            return 1

    if ns.action == "reset":
        cfg.reset_to_defaults()
        _p()
        _p(f"  {_c('OK', 'yellow')} Configuración reseteada a valores por defecto")
        _p()
        return 0

    # favorite
    if ns.fav_action == "add":
        cfg.add_favorite(ns.address, ns.name, ns.type)
        _p()
        _p(f"  {_c('OK', 'green')} Favorito añadido: {ns.address} ({ns.name})")
        _p()
        return 0
    if ns.fav_action == "remove":
        cfg.remove_favorite(ns.address)
        _p()
        _p(f"  {_c('OK', 'green')} Favorito eliminado: {ns.address}")
        _p()
        return 0
    sp_fav.print_help()
    return 2


# --------------------------------------------------------------- plugin

def cmd_plugin(args: list):
    """Gestiona los plugins de bluesky."""
    p = argparse.ArgumentParser(
        prog="bluesky plugin",
        description="Gestionar plugins del catálogo.",
    )
    sub = p.add_subparsers(dest="action")
    sub.add_parser("list", help="listar plugins (acción por defecto)")
    sp_info = sub.add_parser("info", help="detalle de un plugin")
    sp_info.add_argument("name")
    sp_create = sub.add_parser("create", help="crear un plugin nuevo a partir de plantilla")
    sp_create.add_argument("name")
    sp_create.add_argument("type", nargs="?", default="attack",
                           help="tipo: attack|scanner|exploit (default: attack)")
    ns = p.parse_args(args)

    engine = ModuleEngine(load_plugins=True)

    if ns.action in (None, "list"):
        plugins = engine.plugin_loader.list_plugins() if engine.plugin_loader else []
        loaded = sum(1 for pl in plugins if pl.loaded)
        _p()
        _p(separator(title=" Plugins "))
        _p(f"  {_c(f'{len(plugins)} plugin(s) descubierto(s)', 'bold')} · "
           f"{_c(f'{loaded} cargado(s)', 'bold')}")
        _p()
        for pl in plugins:
            status = _c("OK", "green") if pl.loaded else _c("FALLO", "red")
            _p(f"  [{status}] {_c(pl.name, 'cyan')} — {str(pl.description)[:50]}")
            _p(f"      {_c(f'{pl.plugin_type} · v{pl.version} · {pl.author}', 'dim')}")
            if pl.error:
                _p(f"      {_c(f'Error: {pl.error}', 'red')}")
            _p()
        return 0

    if ns.action == "info":
        if not engine.plugin_loader:
            _p()
            _p(f"  {_c('No hay sistema de plugins cargado', 'yellow')}")
            _p()
            return 1
        info = engine.plugin_loader.get_plugin_info(ns.name)
        if not info:
            _p()
            _p(f"  {_c('ERROR', 'red')} Plugin no encontrado: '{ns.name}'")
            _p()
            return 1
        _p()
        _p(separator(title=f" Plugin: {info.name} "))
        for k, v in (("Name", info.name), ("Version", info.version),
                     ("Type", info.plugin_type), ("Author", info.author),
                     ("Desc", info.description), ("Class", info.module_class),
                     ("Path", info.path)):
            _p(f"  {_c(k.ljust(10), 'dim')} {v}")
        loaded = _c("sí", "green") if info.loaded else _c("no", "red")
        _p(f"  {_c('Loaded'.ljust(10), 'dim')} {loaded}")
        if info.error:
            _p(f"  {_c('Error'.ljust(10), 'dim')} {_c(info.error, 'red')}")
        _p()
        return 0

    # create
    from bluesky.core.plugin_loader import create_plugin_template, ensure_plugins_directory
    code = create_plugin_template(ns.name, ns.type)
    plugins_dir = ensure_plugins_directory()
    plugin_file = plugins_dir / f"{ns.name}.py"
    plugin_file.write_text(code)
    _p()
    _p(f"  {_c('OK', 'green')} Plugin creado: {plugin_file}")
    _p()
    return 0


# --------------------------------------------------------------- web

def cmd_web(args: list):
    """Inicia el dashboard web."""
    p = argparse.ArgumentParser(
        prog="bluesky web",
        description="Iniciar el dashboard web (Flask).",
    )
    p.add_argument("-p", "--port", type=int, default=5000, metavar="PORT",
                   help="puerto (default: 5000)")
    p.add_argument("-H", "--host", default="127.0.0.1", metavar="HOST",
                   help="interfaz de escucha (default: 127.0.0.1)")
    p.add_argument("--debug", action="store_true", help="modo debug de Flask")
    p.add_argument("-o", "--open", dest="open_browser", action="store_true",
                   help="abrir el navegador al arrancar")
    ns = p.parse_args(args)

    if not 1 <= ns.port <= 65535:
        p.error("--port debe estar entre 1 y 65535")

    try:
        from bluesky.web.app import run_web_server
        run_web_server(
            port=ns.port,
            host=ns.host,
            debug=ns.debug,
            open_browser=ns.open_browser,
        )
        return 0
    except ImportError as e:
        _p()
        _p(f"  {_c('ERROR', 'red')} No se pudo iniciar el dashboard web: {e}")
        _p(f"  Instala Flask: {_c('pip install flask', 'cyan')}")
        _p()
        return 1
    except Exception as e:
        _p()
        _p(f"  {_c('ERROR', 'red')} {e}")
        _p()
        return 1


# --------------------------------------------------------------- educate

def cmd_educate(args: list):
    """Modo educativo: explica un módulo paso a paso (qué/cómo/impacto/mitigación)."""
    from bluesky.core.education import (
        get_education, covered_modules, format_education_plain,
        format_education_rich, EDU_DB,
    )

    if args:
        name = args[0]
        entry = get_education(name)
        if entry is None:
            _p(f"  {_c('ERROR', 'red')} Sin contenido educativo para '{name}'")
            _p(f"  Disponibles: {', '.join(covered_modules())}")
            return 2
    else:
        # Índice de contenidos
        _p()
        _p(f"  {_c('📚 MODO EDUCATIVO — contenidos', 'bold')}")
        _p()
        for m in covered_modules():
            _p(f"    {_c(m, 'cyan'):18} {EDU_DB[m]['title']}")
        _p()
        _p(f"  Uso: {_c('bluesky educate <módulo>', 'green')}")
        _p()
        return 0

    if not sys.stdout.isatty():
        print(format_education_plain(entry))
        return 0

    try:
        from rich.console import Console
        console = Console()
        format_education_rich(entry, console)
    except Exception:
        print(format_education_plain(entry))
    return 0


# --------------------------------------------------------------- main

def _split_globals(argv: list):
    """Extrae opciones globales de cualquier posición de argv.

    Devuelve (config, no_color, version, json, resto). Un --json global se
    re-inyecta tras el subcomando para que lo consuma su propio parser.
    """
    config_path = None
    no_color = False
    want_version = False
    json_flag = False
    rest = []
    i = 0
    while i < len(argv):
        arg = argv[i]
        if arg in ("-V", "--version"):
            want_version = True
            i += 1
        elif arg == "--config":
            if i + 1 >= len(argv):
                _p(f"  {_c('ERROR', 'red')} --config requiere la ruta al archivo")
                sys.exit(2)
            config_path = argv[i + 1]
            i += 2
        elif arg == "--no-color":
            no_color = True
            i += 1
        elif arg == "--json":
            json_flag = True
            i += 1
        else:
            rest.append(arg)
            i += 1
    if json_flag:
        if rest:
            rest.insert(1, "--json")
        else:
            rest.append("--json")
    return config_path, no_color, want_version, json_flag, rest


def main(argv=None):
    """Punto de entrada principal. Devuelve el exit code del proceso."""
    if argv is None:
        argv = sys.argv[1:]

    config_path, no_color, want_version, json_flag, clean_args = _split_globals(argv)
    _set_color_mode(no_color)
    _set_json_mode(json_flag)

    if want_version:
        _p(f"bluesky {__version__}")
        return 0

    # Cargar configuración
    from bluesky.utils.config import get_config
    cfg = get_config()
    if config_path:
        cfg.load(config_path)

    if not clean_args or clean_args[0] in ("-h", "--help", "help"):
        print_help()
        return 0

    command = clean_args[0]
    args = clean_args[1:]

    # Si se pide ayuda (-h/--help en cualquier posición), sin banner ni avisos
    wants_help = any(a in ("-h", "--help") for a in clean_args)

    # Comandos que no muestran banner
    no_banner = ["scan", "list", "status", "console", "web", "educate",
                 "info", "config", "session", "report", "plugin"]

    if command not in no_banner and not _JSON and not wants_help:
        print_banner()

    # Verificar Bluetooth activo (solo para comandos que lo usan)
    if (command not in ("list", "help", "status", "info", "educate", "config",
                        "plugin", "session", "report", "web")
            and not _JSON and not wants_help):
        from bluesky.utils.network import get_adapter_status
        bt_active, bt_msg = get_adapter_status()
        if not bt_active:
            _p(f"  {_c('AVISO', 'yellow')} {bt_msg}")
            _p("  Algunos módulos pueden no funcionar correctamente.")
            _p()

    # Routing de comandos
    commands = {
        "scan": lambda: cmd_scan(args),
        "list": lambda: cmd_list(args),
        "info": lambda: print_module_info(args[0] if args else ""),
        "vuln": lambda: cmd_vuln(args),
        "auto": lambda: cmd_auto(args),
        "attack": lambda: cmd_attack(args),
        "services": lambda: cmd_services(args),
        "status": lambda: cmd_status(args),
        "report": lambda: cmd_report(args),
        "session": lambda: cmd_session(args),
        "console": lambda: start_console(),
        "spam": lambda: cmd_spam(args),
        "config": lambda: cmd_config(args),
        "plugin": lambda: cmd_plugin(args),
        "web": lambda: cmd_web(args),
        "educate": lambda: cmd_educate(args),
        "help": lambda: print_help(),
    }

    cmd = commands.get(command)
    if cmd is None:
        suggestion = _suggest(command, list(commands.keys()))
        _p()
        _p(f"  {_c('ERROR', 'red')} Comando desconocido: '{command}'{suggestion}")
        _p(f"  Usa {_c('bluesky help', 'cyan')} para ver los comandos disponibles.")
        _p()
        return 2

    rc = cmd()
    if isinstance(rc, int):
        return rc
    return 0


if __name__ == "__main__":
    sys.exit(main())

