"""
Termux-specific utilities for running bluesky on Android.
Auto-detects Termux environment and adapts commands accordingly.

La detección de plataforma vive en bluesky.utils.platform; este módulo
reexporta is_termux() por compatibilidad y añade utilidades específicas
de Termux (root, Termux:API).
"""

import json
import shutil
import subprocess

from .platform import is_termux


def is_rooted() -> bool:
    """Verifica si Termux tiene acceso root."""
    try:
        result = subprocess.run(
            ["su", "-c", "id"],
            capture_output=True, text=True, timeout=5
        )
        return "uid=0" in result.stdout
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return False


def get_termux_bluetooth_api() -> bool:
    """Verifica si Termux:API está disponible para Bluetooth."""
    return shutil.which("termux-bluetooth") is not None


def get_termux_bluetooth_devices() -> list:
    """Obtiene dispositivos Bluetooth usando Termux:API."""
    devices = []
    try:
        result = subprocess.run(
            ["termux-bluetooth", "scan"],
            capture_output=True, text=True, timeout=15
        )
        data = json.loads(result.stdout)
        for dev in data:
            devices.append({
                "mac": dev.get("address", ""),
                "name": dev.get("name", "Unknown"),
                "rssi": dev.get("rssi", 0),
                "type": "classic",
            })
    except (FileNotFoundError, json.JSONDecodeError, subprocess.TimeoutExpired):
        pass
    return devices


def get_termux_bonded_devices() -> list:
    """Obtiene dispositivos emparejados via Termux:API."""
    devices = []
    try:
        result = subprocess.run(
            ["termux-bluetooth", "bonded"],
            capture_output=True, text=True, timeout=5
        )
        data = json.loads(result.stdout)
        for dev in data:
            devices.append({
                "mac": dev.get("address", ""),
                "name": dev.get("name", "Unknown"),
            })
    except (FileNotFoundError, json.JSONDecodeError, subprocess.TimeoutExpired):
        pass
    return devices


def get_capabilities() -> dict:
    """Retorna capacidades del entorno Termux."""
    return {
        "is_termux": is_termux(),
        "is_rooted": is_rooted(),
        "has_termux_api": get_termux_bluetooth_api(),
        "has_bluez": shutil.which("bluetoothctl") is not None,
        "has_hcitool": shutil.which("hcitool") is not None,
    }
