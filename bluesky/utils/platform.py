"""
Platform detection - unified platform detection for Windows/Linux/Termux.
Centraliza toda la lógica de detección de SO para que los módulos
puedan adaptar su comportamiento según la plataforma.
"""

import os
import sys
import platform
import shutil
import subprocess
from typing import Dict, List, Optional, Tuple


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
            return "microsoft" in f.read().lower() or "wsl" in f.read().lower()
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
        return True
    except ImportError:
        return False


def check_pybluez() -> bool:
    """Verifica si PyBluez (Bluetooth Classic) está disponible."""
    try:
        import bluetooth
        return True
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


def best_backend_for_scan() -> str:
    """
    Determina el mejor backend disponible para escaneo Bluetooth.
    
    Returns:
        'bleak', 'bluez', 'windows_powershell', 'termux_api', o 'none'
    """
    backends = get_available_backends()
    
    if backends["bleak"]:
        return "bleak"       # Cross-platform BLE, funciona en todos lados
    if backends["bluez"]:
        return "bluez"       # Linux BlueZ (Classic + BLE)
    if backends["windows_api"]:
        return "windows_powershell"  # Windows via PowerShell
    if backends["termux_api"]:
        return "termux_api"  # Termux:API
    if backends["pybluez"]:
        return "pybluez"     # PyBluez fallback
    
    return "none"
