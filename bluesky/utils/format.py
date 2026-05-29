"""
Utility functions for formatting output (TUI helpers).
"""

import shutil


def terminal_width() -> int:
    """Obtiene el ancho de la terminal."""
    return shutil.get_terminal_size((80, 20)).columns


def separator(char: str = "─", title: str = "") -> str:
    """Crea un separador visual para la terminal."""
    width = terminal_width()
    if title:
        title = f" {title} "
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
        "bold": "\033[1m",
        "dim": "\033[2m",
        "reset": "\033[0m",
        "white": "\033[97m",
    }
    c = colors.get(color)
    if c is None:
        return text
    reset = colors["reset"]
    return f"{c}{text}{reset}"


def severity_icon(severity: str) -> str:
    """Retorna icono para nivel de severidad."""
    icons = {
        "critical": "🔴",
        "high": "🟠",
        "medium": "🟡",
        "low": "⚪",
        "info": "ℹ️",
    }
    return icons.get(severity.lower(), "⚪")


def target_type_icon(ttype: str) -> str:
    """Retorna icono para tipo de target."""
    icons = {
        "classic": "📡",
        "ble": "🔵",
        "both": "🔄",
    }
    return icons.get(ttype.lower(), "📡")


def format_device_list(devices: list) -> str:
    """Formatea lista de dispositivos para mostrar."""
    if not devices:
        return "  No se encontraron dispositivos"

    lines = []
    for i, dev in enumerate(devices, 1):
        name = dev.get("name", "Unknown")
        mac = dev.get("mac", "N/A")
        rssi = dev.get("rssi", "")
        dtype = dev.get("type", "?")
        dtype_icon = target_type_icon(dtype)
        rssi_str = f" [{rssi} dBm]" if rssi else ""
        lines.append(f"  {i:2d}. {dtype_icon} {colorize(name, 'cyan')} {colorize(mac, 'dim')}{rssi_str}")

    return "\n".join(lines)


def format_service_list(services: list) -> str:
    """Formatea lista de servicios SDP."""
    if not services:
        return "  No se encontraron servicios"

    lines = []
    for svc in services:
        name = svc.get("name", "Unknown")
        channel = svc.get("channel", "")
        risk = svc.get("risk", "low")
        channel_str = f" (ch.{channel})" if channel else ""
        risk_icon = severity_icon(risk)
        lines.append(f"  {risk_icon} {name}{channel_str}")

    return "\n".join(lines)
