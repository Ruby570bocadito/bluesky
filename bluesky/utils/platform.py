"""
Platform detection - unified platform detection for Windows/Linux/Termux.
Centraliza toda la lógica de detección de SO para que los módulos
puedan adaptar su comportamiento según la plataforma.
"""

import os
import platform
import shutil
from typing import Dict


def get_platform() -> str:
    """
    Detecta la plataforma actual.
    
    Returns:
        'windows', 'linux', 'termux'
    """
    if _is_termux():
        return "termux"
    if platform.system().lower() == "windows":
        return "windows"
    return "linux"


def is_windows() -> bool:
    """¿Estamos en Windows nativo (no WSL)?"""
    return platform.system().lower() == "windows"


def is_linux() -> bool:
    """¿Estamos en Linux (no Termux)?"""
    return platform.system().lower() == "linux" and not _is_termux()


def is_termux() -> bool:
    """¿Estamos en Termux (Android)?"""
    return _is_termux()


def _is_termux() -> bool:
    return (
        "com.termux" in os.environ.get("HOME", "").lower() or
        os.path.exists("/data/data/com.termux") or
        os.environ.get("TERMUX_VERSION") is not None
    )


def is_wsl() -> bool:
    """¿Estamos corriendo dentro de WSL (Windows Subsystem for Linux)?"""
    if not is_linux():
        return False
    try:
        with open("/proc/version", "r") as f:
            content = f.read().lower()
        return "microsoft" in content or "wsl" in content
    except Exception:
        return False


def get_os_name() -> str:
    """Nombre legible del sistema operativo."""
    if is_termux():
        return "Termux (Android)"
    if is_windows():
        return f"Windows {platform.version()} ({platform.machine()})"
    if is_wsl():
        return f"WSL ({platform.release()})"
    return f"Linux ({platform.release()})"


def is_root() -> bool:
    """Verifica si tenemos permisos elevados."""
    if is_windows():
        try:
            import ctypes
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        except Exception:
            return False
    try:
        return os.geteuid() == 0
    except AttributeError:
        return False


def check_bleak() -> bool:
    """Verifica si la librería bleak (BLE cross-platform) está disponible."""
    try:
        import bleak
        return bool(bleak)  # referencia para evitar warning de import de sondeo
    except ImportError:
        return False


def check_pybluez() -> bool:
    """Verifica si PyBluez (Bluetooth Classic) está disponible."""
    try:
        import bluetooth
        return bool(bluetooth)  # referencia para evitar warning de import de sondeo
    except ImportError:
        return False


def check_command(cmd: str) -> bool:
    """Verifica si un comando existe en el PATH."""
    return shutil.which(cmd) is not None


def get_available_backends() -> Dict[str, bool]:
    """
    Retorna un diccionario con los backends disponibles.
    
    Returns:
        {
            "bleak": True/False,       # BLE cross-platform
            "pybluez": True/False,     # Bluetooth Classic
            "bluez": True/False,       # BlueZ tools (Linux)
            "windows_api": True/False, # Windows Bluetooth API
            "powershell": True/False,  # PowerShell (Windows)
        }
    """
    return {
        "bleak": check_bleak(),
        "pybluez": check_pybluez(),
        "bluez": check_command("bluetoothctl"),
        "windows_api": is_windows(),
        "powershell": is_windows() and check_command("powershell"),
        "termux_api": check_command("termux-bluetooth"),
    }
