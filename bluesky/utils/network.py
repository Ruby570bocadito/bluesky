"""
Network utilities for Bluetooth operations.
Adaptado para funcionar en Windows, Linux y Termux.
"""

import re
import subprocess
from typing import Optional, Tuple

from .platform import is_windows, is_termux, is_wsl, check_command


def mac_valid(mac: str) -> bool:
    """Valida formato de dirección MAC."""
    pattern = r'^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$'
    return bool(re.match(pattern, mac))


def mac_normalize(mac: str) -> str:
    """Normaliza MAC a formato XX:XX:XX:XX:XX:XX."""
    mac = mac.replace("-", ":").replace(" ", "").upper()
    parts = mac.split(":")
    if len(parts) == 6 and all(len(p) == 2 for p in parts):
        return mac
    return ""


def get_local_mac() -> Optional[str]:
    """Obtiene la dirección MAC del adaptador Bluetooth local (cross-platform)."""
    if is_windows():
        return _get_windows_local_mac()
    if is_termux():
        return _get_termux_local_mac()
    # Linux
    try:
        result = subprocess.run(
            ["hciconfig"],
            capture_output=True, text=True, timeout=3
        )
        match = re.search(r'BD Address:\s*(\S+)', result.stdout)
        if match:
            return match.group(1)
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass
    return None


def _get_termux_local_mac() -> Optional[str]:
    """Obtiene MAC del adaptador Bluetooth en Termux."""
    try:
        from .termux_backend import get_status
        status = get_status()
        mac = status.get("adapter_mac", "")
        if mac and mac != "00:00:00:00:00:00":
            return mac
    except Exception:
        pass
    # Fallback: getprop
    try:
        result = subprocess.run(
            ["getprop", "persist.vendor.bt.bda"],
            capture_output=True, text=True, timeout=2
        )
        if result.returncode == 0 and result.stdout.strip():
            return result.stdout.strip().upper()
        result = subprocess.run(
            ["getprop", "vendor.bt.bda"],
            capture_output=True, text=True, timeout=2
        )
        if result.returncode == 0 and result.stdout.strip():
            return result.stdout.strip().upper()
    except FileNotFoundError:
        pass
    return None


def _get_windows_local_mac() -> Optional[str]:
    """Obtiene MAC del adaptador Bluetooth en Windows."""
    try:
        from .windows_backend import get_adapter_mac
        return get_adapter_mac()
    except Exception:
        pass

    # Fallback: buscar en el registro via PowerShell
    ps_script = """
    $path = 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\BTHPORT\\Parameters\\Radios'
    if (Test-Path $path) {
        $radios = Get-ChildItem $path
        foreach ($radio in $radios) {
            $props = Get-ItemProperty -Path $radio.PSPath
            if ($props.LocalAddress) {
                $mac = ($props.LocalAddress | ForEach-Object { '{0:X2}' -f $_ }) -join ':'
                return $mac
            }
        }
    }
    return ''
    """
    try:
        result = subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-Command", ps_script],
            capture_output=True, text=True, timeout=10
        )
        if result.returncode == 0 and result.stdout.strip():
            return result.stdout.strip()
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass
    return None


def _get_termux_adapter_status() -> Tuple[bool, str]:
    """Estado del Bluetooth en Termux."""
    try:
        from .termux_backend import get_status, is_termux_api_available, is_termux_bluetooth_enabled
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
        from .windows_backend import get_bluetooth_status, check_bluetooth_on_windows
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


def bt_service_status() -> Tuple[bool, str]:
    """Verifica si el servicio Bluetooth está activo (cross-platform)."""
    if is_windows():
        try:
            from .windows_backend import get_bluetooth_status
            status = get_bluetooth_status()
            if status.get("service_running"):
                return True, "Servicio Bluetooth activo"
            return False, "Servicio Bluetooth inactivo. Inicia 'BluetoothUserService' desde Services.msc"
        except Exception:
            return False, "No se pudo verificar el servicio Bluetooth"

    if is_termux():
        try:
            from .termux_backend import is_termux_api_available, is_termux_bluetooth_enabled
            if is_termux_api_available():
                enabled = is_termux_bluetooth_enabled()
                if enabled:
                    return True, "Bluetooth encendido (Termux:API)"
                return False, "Bluetooth apagado. Usa: termux-bluetooth-enable"
            return False, "Termux:API no instalado. Usa: pkg install termux-api"
        except Exception:
            return False, "No se pudo verificar Bluetooth en Termux"

    # Linux
    try:
        result = subprocess.run(
            ["systemctl", "is-active", "bluetooth"],
            capture_output=True, text=True, timeout=3
        )
        if result.stdout.strip() == "active":
            return True, "Servicio Bluetooth activo"
        return False, "Servicio Bluetooth inactivo (sudo systemctl start bluetooth)"
    except FileNotFoundError:
        return False, "systemctl no disponible (verificar Bluetooth manualmente)"
    except subprocess.TimeoutExpired:
        return False, "Timeout verificando servicio"
