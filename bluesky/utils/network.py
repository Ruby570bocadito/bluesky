"""
Network utilities for Bluetooth operations.
Adaptado para funcionar en Windows, Linux y Termux.
"""

import re
import subprocess
from typing import Tuple

from .platform import is_windows, is_termux, is_wsl


def mac_valid(mac: str) -> bool:
    """Valida formato de dirección MAC.

    Acepta los formatos XX:XX:XX:XX:XX:XX y XX-XX-XX-XX-XX-XX (hex).
    Tolerante a None y tipos no-str: devuelve False en lugar de lanzar
    TypeError (lo que podría romper callers que no validan input).
    """
    if not isinstance(mac, str):
        return False
    pattern = r'^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$'
    return bool(re.match(pattern, mac))


def mac_normalize(mac: str) -> str:
    """Normaliza MAC a formato XX:XX:XX:XX:XX:XX."""
    mac = mac.replace("-", ":").replace(" ", "").upper()
    parts = mac.split(":")
    if len(parts) == 6 and all(len(p) == 2 for p in parts):
        return mac
    return ""


def _get_termux_adapter_status() -> Tuple[bool, str]:
    """Estado del Bluetooth en Termux."""
    try:
        from .termux_backend import is_termux_api_available, is_termux_bluetooth_enabled
        if is_termux_api_available():
            enabled = is_termux_bluetooth_enabled()
            if enabled:
                return True, "Bluetooth activo (Termux:API)"
            return False, "Bluetooth apagado en Android. Usa: termux-bluetooth-enable"
        # Fallback: BlueZ tools
        try:
            result = subprocess.run(
                ["bluetoothctl", "show"],
                capture_output=True, text=True, timeout=5
            )
            if "Powered: yes" in result.stdout:
                return True, "Bluetooth activo (BlueZ en Termux)"
            if "Powered: no" in result.stdout:
                return False, "Bluetooth apagado. Usa: bluetoothctl power on"
        except FileNotFoundError:
            pass
        return False, "No se detecta Bluetooth en Termux. Instala termux-api: pkg install termux-api"
    except Exception:
        return False, "Error verificando Bluetooth en Termux"


def _get_linux_adapter_status() -> Tuple[bool, str]:
    """Estado del Bluetooth en Linux (separado de Termux)."""
    try:
        result = subprocess.run(
            ["hciconfig"],
            capture_output=True, text=True, timeout=3
        )
        if "UP" in result.stdout:
            return True, "Bluetooth activo"
        elif "DOWN" in result.stdout:
            return False, "Bluetooth inactivo (usar: sudo hciconfig hci0 up)"
        else:
            return False, "No se detecta adaptador Bluetooth"
    except FileNotFoundError:
        if is_wsl():
            return False, "WSL no tiene acceso directo al Bluetooth. Usa la herramienta desde Windows nativo."
        return False, "hciconfig no encontrado (instalar bluez-utils: sudo apt install bluez)"
    except subprocess.TimeoutExpired:
        return False, "Timeout verificando Bluetooth"


def get_adapter_status() -> Tuple[bool, str]:
    """Verifica el estado del adaptador Bluetooth (cross-platform)."""
    if is_windows():
        return _get_windows_adapter_status()

    if is_termux():
        return _get_termux_adapter_status()

    return _get_linux_adapter_status()


def _get_windows_adapter_status() -> Tuple[bool, str]:
    """Estado del Bluetooth en Windows."""
    try:
        from .windows_backend import get_bluetooth_status
        status = get_bluetooth_status()
        if status.get("available"):
            return True, f"Bluetooth activo ({status.get('adapter_name', 'Adaptador')})"
        if status.get("adapter_present"):
            return False, "Bluetooth detectado pero apagado o deshabilitado"
        return False, "No se detecta adaptador Bluetooth en Windows"
    except Exception:
        pass

    # Fallback PowerShell directo
    ps_script = """
    $radio = Get-PnpDevice -Class Bluetooth | Where-Object { $_.FriendlyName -like '*Radio*' } | Select-Object -First 1
    if (-not $radio) { return 'NO_ADAPTER' }
    if ($radio.Status -eq 'OK') { return 'OK' }
    return 'OFF'
    """
    try:
        result = subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-Command", ps_script],
            capture_output=True, text=True, timeout=10
        )
        output = result.stdout.strip()
        if output == "OK":
            return True, "Bluetooth activo en Windows"
        elif output == "OFF":
            return False, "Bluetooth apagado en Windows"
        else:
            return False, "No se detecta adaptador Bluetooth en Windows"
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return False, "PowerShell no disponible en Windows"
