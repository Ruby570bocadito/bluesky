"""
Utility functions for formatting output (TUI helpers).

Punto único para:
  * Iconos de severidad/tipo de target (usados por CLI, consola, módulos)
  * Escape HTML de datos dinámicos (reportes) — usar SIEMPRE este helper,
    nunca html.escape directo disperso por el código
  * Colores ANSI
"""

import shutil
from html import escape as _html_escape


def terminal_width() -> int:
    """Obtiene el ancho de la terminal."""
    return shutil.get_terminal_size((80, 20)).columns


def separator(char: str = "─", title: str = "") -> str:
    """Crea un separador visual para la terminal.

    El título se normaliza con un espacio a cada lado, independientemente
    de que quien llame lo pase ya espaciado (" Escaneo ") o no ("Escaneo").
    """
    width = terminal_width()
    if title:
        title = f" {title.strip()} "
        half = (width - len(title)) // 2
        return f"{char * half}{title}{char * (width - len(title) - half)}"
    return char * width


def colorize(text: str, color: str) -> str:
    """Agrega color ANSI al texto. Si el color no es reconocido, retorna texto sin formato."""
    colors = {
        "red": "\033[91m",
        "green": "\033[92m",
        "yellow": "\033[93m",
        "blue": "\033[94m",
        "magenta": "\033[95m",
        "cyan": "\033[96m",
        "white": "\033[97m",
        "bold": "\033[1m",
        "dim": "\033[2m",
        "faint": "\033[2m",   # sinónimo de dim (la CLI lo usa)
        "reset": "\033[0m",
    }
    c = colors.get(color)
    if c is None:
        return text
    reset = colors["reset"]
    return f"{c}{text}{reset}"


# Logotipo ASCII compartido por el CLI (`bluesky ...`) y la consola
# interactiva (`bluesky console`). Fuente figlet 'slant'. ÚNICA fuente de
# verdad: si cambia el logo, cambia para ambas interfaces a la vez.
ASCII_LOGO = r"""
    __    __                __
   / /_  / /_  _____  _____/ /____  __
  / __ \/ / / / / _ \/ ___/ //_/ / / /
 / /_/ / / /_/ /  __(__  ) ,< / /_/ /
/_.___/_/\__,_/\___/____/_/|_|\__, /
                             /____/
""".strip("\n")


# Mapa canónico de severidad → icono. ÚNICA fuente de verdad del proyecto:
# usar severity_icon() en lugar de definir mapas locales (antes existían
# copias divergentes en vuln_scanner y bias con colores intercambiados).
SEVERITY_ICONS = {
    "critical": "🔴",
    "high": "🟠",
    "medium": "🟡",
    "low": "⚪",
    "info": "ℹ️",
}


def severity_icon(severity) -> str:
    """Retorna icono para nivel de severidad (tolera None/no-string)."""
    return SEVERITY_ICONS.get(str(severity or "").lower(), "⚪")


def esc(value) -> str:
    """Escape HTML de cualquier dato dinámico (None, str, int, dict...).

    Obligatorio para TODO dato que provenga de fuentes externas (nombres
    de dispositivos Bluetooth, MACs, IDs de vulnerabilidad, errores...)
    antes de interpolarse en HTML de reportes: un dispositivo con un
    nombre como '<img src=x onerror=alert(1)>' no debe ejecutar JS al
    abrir el reporte en un navegador.
    """
    return _html_escape(str(value) if value is not None else "", quote=True)


def target_type_icon(ttype) -> str:
    """Retorna icono para tipo de target (tolera None/no-string)."""
    icons = {
        "classic": "📡",
        "ble": "🔵",
        "both": "🔄",
    }
    return icons.get(str(ttype or "").lower(), "📡")


def format_device_list(devices: list) -> str:
    """Formatea lista de dispositivos para mostrar."""
    if not devices:
        return "  No se encontraron dispositivos"

    lines = []
    for i, dev in enumerate(devices, 1):
        if not isinstance(dev, dict):
            # Entrada malformada (p.ej. MAC como string de un JSON a mano)
            lines.append(f"  {i:2d}. {dev}")
            continue
        name = dev.get("name", "Unknown")
        mac = dev.get("mac", "N/A")
        rssi = dev.get("rssi", "")
        dtype = dev.get("type", "?")
        dtype_icon = target_type_icon(dtype)
        vendor = dev.get("vendor", "")
        vendor_str = f" {colorize('· ' + vendor, 'dim')}" if vendor else ""
        rssi_str = f" [{rssi} dBm]" if rssi else ""
        lines.append(f"  {i:2d}. {dtype_icon} {colorize(name, 'cyan')} {colorize(mac, 'dim')}{vendor_str}{rssi_str}")

    return "\n".join(lines)


def format_service_list(services: list) -> str:
    """Formatea lista de servicios SDP."""
    if not services:
        return "  No se encontraron servicios"

    lines = []
    for svc in services:
        if not isinstance(svc, dict):
            lines.append(f"  ⚠️  {svc}")
            continue
        name = svc.get("name", "Unknown")
        channel = svc.get("channel", "")
        risk = svc.get("risk", "low")
        channel_str = f" (ch.{channel})" if channel else ""
        risk_icon = severity_icon(risk)
        lines.append(f"  {risk_icon} {name}{channel_str}")

    return "\n".join(lines)
