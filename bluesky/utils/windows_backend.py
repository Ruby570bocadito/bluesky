"""
Windows Bluetooth Backend - Proporciona operaciones Bluetooth
en Windows nativo usando PowerShell, ctypes y bleak.

Windows no tiene BlueZ tools (bluetoothctl, hciconfig, etc.),
así que usamos:
  - PowerShell + WMI/CIM para enumerar adaptadores y dispositivos
  - bleak para BLE (cross-platform)
  - ctypes + socket AF_BTH para RFCOMM (Bluetooth Classic)
  - Windows Registry para información del hardware
"""

import os
import re
import sys
import json
import time
import subprocess
import platform
from typing import Dict, List, Optional, Tuple

from .platform import is_windows, check_bleak, check_command


# ─── PowerShell Scripts Embebidos ──────────────────────────────────────────

_PS_GET_ADAPTERS = """
$adapters = Get-PnpDevice -Class Bluetooth -ErrorAction SilentlyContinue
$result = @()
foreach ($adapter in $adapters) {
    $result += [PSCustomObject]@{
        Name        = $adapter.FriendlyName
        Status      = $adapter.Status
        Class       = $adapter.Class
        InstanceId  = $adapter.InstanceId
        IsPresent   = if ($adapter.Present) { $true } else { $false }
    }
}
if ($result.Count -eq 0) {
    # Fallback: buscar en Get-CimInstance
    $bt = Get-CimInstance -ClassName Win32_PnPEntity -ErrorAction SilentlyContinue |
          Where-Object { $_.PNPClass -eq 'Bluetooth' -or $_.Name -like '*bluetooth*' }
    foreach ($b in $bt) {
        $result += [PSCustomObject]@{
            Name        = $b.Name
            Status      = $b.Status
            Class       = $b.PNPClass
            InstanceId  = $b.DeviceID
            IsPresent   = $true
        }
    }
}
return $result | ConvertTo-Json -Compress
"""

_PS_GET_RADIO_INFO = """
# Obtener información del radio Bluetooth via Registry
$radioPath = 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\BTHPORT\\Parameters\\Radios'
$result = @()
if (Test-Path $radioPath) {
    $radios = Get-ChildItem -Path $radioPath -ErrorAction SilentlyContinue
    foreach ($radio in $radios) {
        $props = Get-ItemProperty -Path $radio.PSPath -ErrorAction SilentlyContinue
        $result += [PSCustomObject]@{
            Name         = $radio.PSChildName
            Address      = if ($props.LocalAddress) { '{0:X}:{1:X}:{2:X}:{3:X}:{4:X}:{5:X}' -f 
                           [int]$props.LocalAddress[0],[int]$props.LocalAddress[1],
                           [int]$props.LocalAddress[2],[int]$props.LocalAddress[3],
                           [int]$props.LocalAddress[4],[int]$props.LocalAddress[5] } else { 'Unknown' }
            Manufacturer = if ($props.ManufacturerName) { $props.ManufacturerName } else { 'Unknown' }
        }
    }
}
if ($result.Count -eq 0) {
    # Fallback: buscar en HKLM para información de chip
    $btPath = 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\BTHPORT\\Parameters'
    if (Test-Path $btPath) {
        $props = Get-ItemProperty -Path $btPath -ErrorAction SilentlyContinue
        $result += [PSCustomObject]@{
            Name         = 'Bluetooth Radio'
            Address      = 'Unknown'
            Manufacturer = if ($props.ManufacturerName) { $props.ManufacturerName } else { 'Generic' }
        }
    }
}
return $result | ConvertTo-Json -Compress
"""

_PS_GET_PAIRED_DEVICES = """
$devices = Get-WmiObject -Class Win32_BluetoothDevice -ErrorAction SilentlyContinue
$result = @()
if ($devices) {
    foreach ($d in $devices) {
        $result += [PSCustomObject]@{
            Name        = $d.Name
            MAC         = if ($d.DeviceID) { ($d.DeviceID -replace '.*_([^_]+)$','$1') -replace '(..)', '$1:' -replace ':$','' } else { 'Unknown' }
            Connected   = if ($d.Connected) { $true } else { $false }
            Paired      = if ($d.Paired) { $true } else { $false }
        }
    }
}
if ($result.Count -eq 0) {
    # Fallback: Get-PnpDevice
    $bt = Get-PnpDevice -Class Bluetooth -ErrorAction SilentlyContinue |
          Where-Object { $_.FriendlyName -and $_.Status -eq 'OK' -and $_.FriendlyName -notlike '*Radio*' -and $_.FriendlyName -notlike '*Adapter*' }
    foreach ($b in $bt) {
        $result += [PSCustomObject]@{
            Name      = $b.FriendlyName
            MAC       = ($b.InstanceId -replace '.*&(\\w+)','$1')
            Connected = $false
            Paired    = $true
        }
    }
}
return $result | ConvertTo-Json -Compress
"""

_PS_GET_BT_STATUS = """
$service = Get-Service -Name 'BluetoothUserService' -ErrorAction SilentlyContinue
$adapter = Get-PnpDevice -Class Bluetooth -ErrorAction SilentlyContinue |
           Where-Object { $_.FriendlyName -like '*Radio*' -or $_.FriendlyName -like '*Adapter*' } |
           Select-Object -First 1
$result = [PSCustomObject]@{
    ServiceRunning = if ($service.Status -eq 'Running') { $true } else { $false }
    AdapterPresent = if ($adapter) { $true } else { $false }
    AdapterOK      = if ($adapter.Status -eq 'OK') { $true } else { $false }
    AdapterName    = if ($adapter) { $adapter.FriendlyName } else { '' }
}
return $result | ConvertTo-Json -Compress
"""

_PS_SCAN_DEVICES = """
Add-Type -AssemblyName System.Runtime.WindowsRuntime
$asTaskGeneric = ([System.WindowsRuntimeSystemExtensions].GetMethods() | 
    Where-Object { $_.Name -eq 'AsTask' -and $_.GetParameters().Count -eq 1 -and 
    $_.GetParameters()[0].ParameterType.Name -eq 'IAsyncOperation`1' })[0]
Function Await($WinRtTask, $ResultType) {
    $asTask = $asTaskGeneric.MakeGenericMethod($ResultType)
    $netTask = $asTask.Invoke($null, @($WinRtTask))
    $netTask.Wait(-1) | Out-Null
    $netTask.Result
}
[Windows.Devices.Radios.Radio,Windows.System.Devices,ContentType=WindowsRuntime] | Out-Null
[Windows.Devices.Bluetooth.BluetoothAdapter,Windows.System.Devices,ContentType=WindowsRuntime] | Out-Null
$radios = Await ([Windows.Devices.Radios.Radio]::RequestAccessAsync()) ([Windows.Devices.Radios.RadioAccessStatus])
if ($radios -eq 'Allowed') {
    $btAdapter = Await ([Windows.Devices.Bluetooth.BluetoothAdapter]::GetDefaultAsync()) ([Windows.Devices.Bluetooth.BluetoothAdapter])
    if ($btAdapter) {
        $result = [PSCustomObject]@{
            Available = $true
            Address   = '{0:X}' -f $btAdapter.BluetoothAddress
        }
        return $result | ConvertTo-Json -Compress
    }
}
return '{"Available":false}' | ConvertTo-Json -Compress
"""


# ─── Funciones principales ─────────────────────────────────────────────────


def _run_powershell(script: str, timeout: int = 15) -> Optional[str]:
    """
    Ejecuta un script de PowerShell y retorna stdout.

    Args:
        script: Código PowerShell a ejecutar
        timeout: Timeout en segundos

    Returns:
        stdout del script o None si falla
    """
    if not check_command("powershell"):
        return None

    try:
        result = subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-Command", script],
            capture_output=True, text=True, timeout=timeout
        )
        if result.returncode == 0 and result.stdout.strip():
            return result.stdout.strip()
        return None
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return None


def _parse_json(data: Optional[str]) -> Optional[list]:
    """Parsea JSON de PowerShell (puede ser un objeto o array)."""
    if not data:
        return None
    try:
        parsed = json.loads(data)
        if isinstance(parsed, list):
            return parsed
        return [parsed]
    except (json.JSONDecodeError, TypeError):
        return None


# ─── API Pública ───────────────────────────────────────────────────────────


def list_adapters() -> List[Dict]:
    """
    Lista adaptadores Bluetooth disponibles en Windows.

    Returns:
        Lista de dicts con: name, status, instance_id, is_present
    """
    raw = _run_powershell(_PS_GET_ADAPTERS)
    parsed = _parse_json(raw)
    if parsed:
        return [{
            "name": a.get("Name", "Unknown"),
            "status": a.get("Status", "Unknown"),
            "instance_id": a.get("InstanceId", ""),
            "is_present": a.get("IsPresent", False),
            "interface": "windows_bt",
        } for a in parsed]
    return []


def get_radio_info() -> List[Dict]:
    """
    Obtiene información del radio Bluetooth desde el Registry.

    Returns:
        Lista con: name, address (MAC), manufacturer
    """
    raw = _run_powershell(_PS_GET_RADIO_INFO)
    parsed = _parse_json(raw)
    if parsed:
        return [{
            "name": r.get("Name", "Bluetooth Radio"),
            "mac": r.get("Address", "Unknown"),
            "manufacturer": r.get("Manufacturer", "Unknown"),
        } for r in parsed]
    return []


def list_paired_devices() -> List[Dict]:
    """
    Lista dispositivos Bluetooth emparejados en Windows.

    Returns:
        Lista de dicts con: name, mac, connected, paired
    """
    raw = _run_powershell(_PS_GET_PAIRED_DEVICES)
    parsed = _parse_json(raw)
    if parsed:
        return [{
            "name": d.get("Name", "Unknown"),
            "mac": d.get("MAC", ""),
            "connected": d.get("Connected", False),
            "paired": d.get("Paired", True),
            "type": "classic",
        } for d in parsed]
    return []


def get_bluetooth_status() -> Dict:
    """
    Estado del Bluetooth en Windows.

    Returns:
        Dict con: service_running, adapter_present, adapter_ok, adapter_name
    """
    raw = _run_powershell(_PS_GET_BT_STATUS)
    if raw:
        try:
            data = json.loads(raw)
            return {
                "service_running": data.get("ServiceRunning", False),
                "adapter_present": data.get("AdapterPresent", False),
                "adapter_ok": data.get("AdapterOK", False),
                "adapter_name": data.get("AdapterName", ""),
                "available": data.get("AdapterPresent", False) and data.get("AdapterOK", False),
            }
        except json.JSONDecodeError:
            pass
    return {
        "service_running": False,
        "adapter_present": False,
        "adapter_ok": False,
        "adapter_name": "",
        "available": False,
    }


def get_adapter_mac() -> Optional[str]:
    """
    Obtiene la dirección MAC del adaptador Bluetooth desde el Registry.

    Returns:
        MAC en formato XX:XX:XX:XX:XX:XX o None
    """
    radios = get_radio_info()
    for r in radios:
        mac = r.get("mac", "")
        if mac and mac != "Unknown":
            # Convertir formato Windows a XX:XX:XX:XX:XX:XX
            mac = mac.replace("-", ":").replace(" ", "").upper()
            # Si está en formato continuo (001122AABBCC), separar
            if len(mac) == 12 and ":" not in mac:
                mac = ":".join(mac[i:i+2] for i in range(0, 12, 2))
            return mac
        # Intentar desde paired devices (primer device)
        paired = list_paired_devices()
        for p in paired:
            pmac = p.get("mac", "")
            if pmac and pmac != "Unknown":
                return pmac
    return None


def get_local_mac() -> Optional[str]:
    """Obtiene la MAC del adaptador local (cross-platform wrapper)."""
    if is_windows():
        return get_adapter_mac()
    # En Linux, usar hciconfig
    try:
        result = subprocess.run(
            ["hciconfig"],
            capture_output=True, text=True, timeout=3
        )
        m = re.search(r'BD Address:\s*(\S+)', result.stdout)
        if m:
            return m.group(1)
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass
    return None


def check_bluetooth_on_windows() -> bool:
    """
    Verifica rápidamente si Bluetooth está encendido en Windows.
    Sin depender de bleak ni pybluez.
    """
    status = get_bluetooth_status()
    return status.get("available", False)


def enable_bluetooth_windows() -> bool:
    """
    Intenta encender Bluetooth en Windows via PowerShell.

    Returns:
        True si se pudo encender
    """
    ps_script = """
    $radio = Get-PnpDevice -Class Bluetooth | Where-Object { $_.FriendlyName -like '*Radio*' } | Select-Object -First 1
    if ($radio -and $radio.Status -ne 'OK') {
        Enable-PnpDevice -InstanceId $radio.InstanceId -Confirm:$false
    }
    $service = Get-Service -Name 'BluetoothUserService' -ErrorAction SilentlyContinue
    if ($service -and $service.Status -ne 'Running') {
        Start-Service -Name 'BluetoothUserService'
    }
    $radio2 = Get-PnpDevice -Class Bluetooth | Where-Object { $_.FriendlyName -like '*Radio*' } | Select-Object -First 1
    if ($radio2 -and $radio2.Status -eq 'OK') { return 'OK' }
    return 'FAIL'
    """
    raw = _run_powershell(ps_script)
    return raw and "OK" in raw
