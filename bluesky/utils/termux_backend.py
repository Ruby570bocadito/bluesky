"""
Termux Bluetooth Backend - Proporciona operaciones Bluetooth
en Termux (Android) usando Termux:API.

Termux no tiene BlueZ tools nativas (bluetoothctl, hciconfig, etc.)
aunque pueden instalarse via pkg. El backend principal usa:

  - termux-bluetooth-* (Termux:API) para operaciones nativas Android
  - bleak para BLE (cross-platform, funciona en Termux)
  - BlueZ tools (hcitool, bluetoothctl) si están instalados via pkg

Termux:API commands:
  termux-bluetooth-scan         → JSON array de dispositivos
  termux-bluetooth-enable       → Activa Bluetooth
  termux-bluetooth-disable      → Desactiva Bluetooth
  termux-bluetooth-pair <addr>  → Emparejar
  termux-bluetooth-unpair <addr>→ Desemparejar
  termux-bluetooth-connect <addr>→ Conectar
  termux-bluetooth-disconnect <addr>→ Desconectar
  termux-bluetooth-info <addr>  → Info del dispositivo

Referencia:
  https://wiki.termux.com/wiki/Termux:API
  https://github.com/termux/termux-api-package
"""

from __future__ import annotations

import os
import re
import sys
import json
import time
import shutil
import logging
import subprocess
from typing import Dict, List, Optional, Tuple
from pathlib import Path

from .platform import is_termux, check_bleak, check_command

log = logging.getLogger("bluesky.termux")


# ─── Verificaciones ──────────────────────────────────────────────────────────


def is_termux_api_available() -> bool:
    """
    Verifica si Termux:API está instalado y funcionando.

    Returns:
        True si termux-bluetooth está disponible.
    """
    return check_command("termux-bluetooth")


def is_termux_bluetooth_enabled() -> bool:
    """
    Verifica si Bluetooth está encendido en Termux.

    Intenta ejecutar 'termux-bluetooth-scan' con timeout corto;
    si falla, asume que BT está apagado.

    Returns:
        True si Bluetooth responde.
    """
    if not is_termux_api_available():
        return False
    try:
        result = subprocess.run(
            ["termux-bluetooth-scan", "--limit", "1"],
            capture_output=True, text=True, timeout=5
        )
        return result.returncode == 0
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return False


# ─── Ejecución de comandos Termux:API ────────────────────────────────────────


def _run_termux_api(cmd: str, *args, timeout: int = 15) -> Optional[str]:
    """
    Ejecuta un comando termux-bluetooth-* y retorna stdout.

    Args:
        cmd: Comando (ej: 'scan', 'enable', 'info')
        args: Argumentos adicionales (ej: dirección MAC)
        timeout: Timeout en segundos

    Returns:
        stdout del comando o None si falla
    """
    if not is_termux_api_available():
        log.warning("Termux:API no disponible. Instala: pkg install termux-api")
        return None

    full_cmd = [f"termux-bluetooth-{cmd}"] + list(args)
    try:
        result = subprocess.run(
            full_cmd,
            capture_output=True, text=True, timeout=timeout
        )
        if result.returncode == 0 and result.stdout.strip():
            return result.stdout.strip()
        if result.stderr:
            log.debug(f"termux-bluetooth-{cmd} stderr: {result.stderr.strip()}")
        return None
    except FileNotFoundError:
        log.error(f"termux-bluetooth-{cmd} no encontrado. "
                   "Instala: pkg install termux-api")
        return None
    except subprocess.TimeoutExpired:
        log.warning(f"termux-bluetooth-{cmd} timeout ({timeout}s)")
        return None


def _parse_json_output(data: Optional[str]) -> Optional[list]:
    """
    Parsea la salida JSON de Termux:API.

    Args:
        data: String JSON de la API

    Returns:
        Lista de dicts o None si falla
    """
    if not data:
        return None
    try:
        parsed = json.loads(data)
        if isinstance(parsed, list):
            return parsed
        return [parsed]
    except (json.JSONDecodeError, TypeError) as e:
        log.debug(f"Error parseando JSON Termux: {e}")
        return None


# ─── API Pública ─────────────────────────────────────────────────────────────


def list_adapters() -> List[Dict]:
    """
    Lista adaptadores Bluetooth en Termux.

    Termux:API no expone directamente los adaptadores; devolvemos
    la información disponible del sistema Android.

    Returns:
        Lista con info del adaptador BT del dispositivo
    """
    adapters = []

    # Verificar estado general
    if not is_termux_api_available():
        return adapters

    try:
        # Android Bluetooth adapter info via getprop
        props = {
            "bt_name": _getprop("bluetooth.name"),
            "bt_status": _getprop("bluetooth.status"),
            "bt_bda": _getprop("bluetooth.bda"),
            "bt_class": _getprop("bluetooth.device.class"),
        }

        adapter = {
            "name": props.get("bt_name") or "Bluetooth (Android)",
            "status": "OK" if is_termux_bluetooth_enabled() else "Disabled",
            "mac": _get_android_bt_mac(),
            "interface": "termux_api",
            "transport": "android",
        }
        adapters.append(adapter)
    except Exception as e:
        log.debug(f"Error obteniendo adaptador Termux: {e}")

    return adapters


def scan_devices(timeout: int = 10) -> List[Dict]:
    """
    Escanea dispositivos Bluetooth usando Termux:API.

    Args:
        timeout: Tiempo de escaneo en segundos

    Returns:
        Lista de dispositivos descubiertos
    """
    if not is_termux_api_available():
        log.warning("Termux:API no disponible para escaneo")
        return _scan_bluez_fallback(timeout)

    raw = _run_termux_api("scan", "--timeout", str(min(timeout, 30)),
                          timeout=timeout + 5)
    parsed = _parse_json_output(raw)

    if not parsed:
        # Fallback a BlueZ tools si están instaladas
        return _scan_bluez_fallback(timeout)

    devices = []
    for d in parsed:
        mac = d.get("address", d.get("mac", d.get("Address", "")))
        name = d.get("name", d.get("Name", d.get("device_name", "")))
        rssi = d.get("rssi", d.get("RSSI", d.get("signal_strength", 0)))
        bt_type = _classify_device_type(d)

        devices.append({
            "name": name or mac if mac else "Unknown",
            "address": mac.upper() if mac else "",
            "rssi": rssi if isinstance(rssi, (int, float)) else 0,
            "type": bt_type,
            "services": [],
            "paired": d.get("paired", d.get("Paired", False)),
            "bonded": d.get("bonded", d.get("Bonded", False)),
            "vendor": _guess_vendor_from_mac(mac) if mac else "",
        })

    return devices


def _scan_bluez_fallback(timeout: int = 10) -> List[Dict]:
    """
    Fallback: escaneo usando BlueZ tools (hcitool/bluetoothctl)
    instaladas via pkg en Termux.

    Args:
        timeout: Tiempo de escaneo

    Returns:
        Lista de dispositivos
    """
    devices = []

    if check_command("hcitool"):
        try:
            result = subprocess.run(
                ["hcitool", "scan", "--flush"],
                capture_output=True, text=True, timeout=timeout
            )
            if result.returncode == 0:
                for line in result.stdout.splitlines():
                    m = re.match(r'\s*(\S+)\s+(.+)$', line)
                    if m:
                        devices.append({
                            "name": m.group(2).strip(),
                            "address": m.group(1).upper(),
                            "rssi": 0,
                            "type": "classic",
                            "services": [],
                            "paired": False,
                            "bonded": False,
                            "vendor": _guess_vendor_from_mac(m.group(1)),
                        })
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass

    # BLE scan
    if check_command("hcitool") and not devices:
        try:
            result = subprocess.run(
                ["hcitool", "lescan", "--duplicates", "--timeout",
                 str(min(timeout, 5))],
                capture_output=True, text=True, timeout=timeout
            )
            if result.returncode == 0:
                seen = set()
                for line in result.stdout.splitlines():
                    m = re.match(r'\s*(\S+)\s+(.+)$', line)
                    if m and m.group(1) not in seen:
                        seen.add(m.group(1))
                        devices.append({
                            "name": m.group(2).strip() or "Unknown",
                            "address": m.group(1).upper(),
                            "rssi": 0,
                            "type": "ble",
                            "services": [],
                            "paired": False,
                            "bonded": False,
                            "vendor": _guess_vendor_from_mac(m.group(1)),
                        })
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass

    return devices


def get_device_info(address: str) -> Optional[Dict]:
    """
    Obtiene información detallada de un dispositivo Bluetooth.

    Args:
        address: Dirección MAC del dispositivo

    Returns:
        Dict con info del dispositivo o None
    """
    if not is_termux_api_available():
        return None

    raw = _run_termux_api("info", address, timeout=10)
    if not raw:
        return None

    try:
        data = json.loads(raw)
        return {
            "address": address.upper(),
            "name": data.get("name", data.get("Name", "Unknown")),
            "paired": data.get("paired", data.get("Paired", False)),
            "bonded": data.get("bonded", data.get("Bonded", False)),
            "type": data.get("type", data.get("Type", "classic")),
            "uuids": data.get("uuids", data.get("UUIDs", [])),
            "vendor": _guess_vendor_from_mac(address),
        }
    except json.JSONDecodeError:
        return {
            "address": address.upper(),
            "name": "Unknown",
            "raw": raw[:200],
        }


def enable_bluetooth() -> bool:
    """
    Activa Bluetooth en Termux via Termux:API.

    Returns:
        True si se activó correctamente
    """
    raw = _run_termux_api("enable", timeout=10)
    success = raw is not None
    if success:
        log.info("✅ Bluetooth activado vía Termux:API")
    else:
        log.error("❌ No se pudo activar Bluetooth")
    return success


def disable_bluetooth() -> bool:
    """
    Desactiva Bluetooth en Termux via Termux:API.

    Returns:
        True si se desactivó correctamente
    """
    raw = _run_termux_api("disable", timeout=10)
    success = raw is not None
    if success:
        log.info("✅ Bluetooth desactivado vía Termux:API")
    else:
        log.error("❌ No se pudo desactivar Bluetooth")
    return success


def pair_device(address: str) -> bool:
    """
    Empareja con un dispositivo Bluetooth.

    Args:
        address: Dirección MAC

    Returns:
        True si el emparejamiento fue exitoso
    """
    raw = _run_termux_api("pair", address, timeout=20)
    return raw is not None


def unpair_device(address: str) -> bool:
    """
    Desempareja un dispositivo Bluetooth.

    Args:
        address: Dirección MAC

    Returns:
        True si se desemparejó correctamente
    """
    raw = _run_termux_api("unpair", address, timeout=10)
    return raw is not None


def connect_device(address: str) -> bool:
    """
    Conecta a un dispositivo Bluetooth emparejado.

    Args:
        address: Dirección MAC

    Returns:
        True si la conexión fue exitosa
    """
    raw = _run_termux_api("connect", address, timeout=20)
    return raw is not None


def disconnect_device(address: str) -> bool:
    """
    Desconecta un dispositivo Bluetooth.

    Args:
        address: Dirección MAC

    Returns:
        True si se desconectó correctamente
    """
    raw = _run_termux_api("disconnect", address, timeout=10)
    return raw is not None


def get_status() -> Dict:
    """
    Estado completo del Bluetooth en Termux.

    Returns:
        Dict con: enabled, api_available, ble_available, adapter, paired_count
    """
    api_avail = is_termux_api_available()
    enabled = is_termux_bluetooth_enabled() if api_avail else False
    bleak_avail = check_bleak()

    # Obtener info del adaptador
    adapters = list_adapters()
    adapter_info = adapters[0] if adapters else {}

    # Contar dispositivos emparejados
    paired_count = 0
    try:
        # Los dispositivos emparejados se listan via BlueZ
        if check_command("bluetoothctl"):
            result = subprocess.run(
                ["bluetoothctl", "paired-devices"],
                capture_output=True, text=True, timeout=5
            )
            if result.returncode == 0:
                paired_count = len([l for l in result.stdout.splitlines()
                                   if l.strip()])
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass

    return {
        "platform": "termux",
        "api_available": api_avail,
        "bluetooth_enabled": enabled,
        "ble_available": bleak_avail,
        "adapter": adapter_info.get("name", "Bluetooth (Android)"),
        "adapter_mac": adapter_info.get("mac", ""),
        "paired_count": paired_count,
        "backend": "termux_api" if api_avail else ("bluez" if check_command("bluetoothctl") else "none"),
    }


# ─── Utilidades ──────────────────────────────────────────────────────────────


def _getprop(prop: str) -> Optional[str]:
    """Lee una propiedad del sistema Android via getprop."""
    try:
        result = subprocess.run(
            ["getprop", prop],
            capture_output=True, text=True, timeout=2
        )
        if result.returncode == 0 and result.stdout.strip():
            return result.stdout.strip()
    except FileNotFoundError:
        pass
    return None


def _get_android_bt_mac() -> str:
    """
    Obtiene la dirección MAC Bluetooth del dispositivo Android.

    Fuentes: varias props de Android, algunas requieren root.
    """
    # Intentar getprop
    for prop in [
        "persist.vendor.bt.bda",
        "vendor.bt.bda",
        "ro.bt.bda",
        "ro.boot.bt.bda",
        "bt.bda",
    ]:
        val = _getprop(prop)
        if val:
            return val.upper()

    # Intentar leer de archivos del sistema
    for path in [
        "/data/misc/bluedroid/bt_config.conf",
        "/data/misc/bt_config.xml",
    ]:
        try:
            content = Path(path).read_text()
            # Buscar patrones "Address = XX:XX:XX:XX:XX:XX"
            m = re.search(r'(?:[Aa]ddress|MAC|BDA)\s*[:=]\s*([0-9A-Fa-f:]{17})',
                         content)
            if m:
                return m.group(1).upper()
        except (FileNotFoundError, PermissionError):
            continue

    return "00:00:00:00:00:00"


def _classify_device_type(device: Dict) -> str:
    """Clasifica el tipo de dispositivo Bluetooth."""
    # Intentar desde campos de Termux:API
    bt_type = device.get("type", "").lower()
    if bt_type in ("ble", "le", "low_energy"):
        return "ble"
    if bt_type in ("classic", "br/edr", "edr"):
        return "classic"

    # Por nombre
    name = device.get("name", device.get("Name", "")).lower()
    ble_keywords = ["ble", "le-", "smart", "low energy", "ibeacon"]
    if any(kw in name for kw in ble_keywords):
        return "ble"

    return "classic"


def _guess_vendor_from_mac(mac: str) -> str:
    """
    Adivina el fabricante a partir del prefijo OUI de la MAC.

    Args:
        mac: Dirección MAC (XX:XX:XX:XX:XX:XX)

    Returns:
        Nombre del fabricante o "Unknown"
    """
    if not mac or len(mac) < 8:
        return "Unknown"

    # Limpiar MAC
    mac = mac.replace("-", ":").upper()
    prefix = mac[:8]

    # OUI database básica
    oui_db: Dict[str, str] = {
        "00:0A:AD": "HTC",
        "00:1A:7D": "Samsung",
        "00:23:76": "Samsung",
        "00:25:00": "Samsung",
        "00:26:37": "LG Electronics",
        "04:02:1E": "Google",
        "04:CB:1D": "Huawei",
        "08:00:46": "Sony",
        "08:74:02": "Xiaomi",
        "0C:9D:92": "OnePlus",
        "10:83:44": "Google",
        "14:3D:2E": "LG Electronics",
        "18:3E:2A": "Motorola",
        "18:87:96": "Samsung",
        "1C:9E:46": "LG Electronics",
        "20:17:C9": "Sony",
        "20:5E:4B": "Huawei",
        "20:F4:1B": "Google",
        "24:0A:C4": "Samsung",
        "24:46:C8": "Xiaomi",
        "28:6C:07": "Samsung",
        "2C:54:2D": "HTC",
        "30:07:4D": "Samsung",
        "30:3A:64": "Google",
        "34:23:87": "LG Electronics",
        "38:2C:4A": "Xiaomi",
        "38:4B:21": "Samsung",
        "3C:5A:37": "Huawei",
        "40:9F:38": "Motorola",
        "4C:AA:16": "Samsung",
        "50:1A:A5": "Sony",
        "54:0B:E0": "Huawei",
        "54:0B:F8": "Sony",
        "54:8D:5A": "LG Electronics",
        "58:68:7B": "Samsung",
        "5C:B9:01": "Xiaomi",
        "60:A4:D0": "Samsung",
        "64:66:B3": "Huawei",
        "68:54:1A": "Samsung",
        "6C:0E:0D": "OnePlus",
        "70:BF:92": "Motorola",
        "74:A7:05": "LG Electronics",
        "78:67:D7": "Samsung",
        "84:DB:2F": "Xiaomi",
        "88:32:9B": "Google",
        "88:35:4C": "Samsung",
        "8C:45:00": "Samsung",
        "8C:8C:AA": "Samsung",
        "90:18:AE": "Google",
        "94:A1:B1": "Huawei",
        "94:CB:CD": "Samsung",
        "98:0C:82": "LG Electronics",
        "98:2B:C4": "Sony",
        "9C:20:7E": "Motorola",
        "9C:2A:70": "Samsung",
        "9C:57:AD": "Samsung",
        "A0:1D:48": "Samsung",
        "A0:7C:2F": "Sony",
        "A4:77:33": "Samsung",
        "A4:9B:4F": "Huawei",
        "A4:C3:F0": "LG Electronics",
        "A8:2B:B5": "Samsung",
        "AC:57:75": "LG Electronics",
        "AC:84:C6": "Samsung",
        "B0:1B:7D": "Samsung",
        "B0:4B:CF": "Xiaomi",
        "B4:0B:44": "Huawei",
        "B4:52:7D": "Samsung",
        "B8:09:8A": "Sony",
        "B8:6C:E8": "Samsung",
        "BC:76:70": "Google",
        "C0:21:0D": "Samsung",
        "C0:78:9F": "LG Electronics",
        "C4:17:FE": "Samsung",
        "C4:43:8F": "Huawei",
        "C8:94:02": "Huawei",
        "CC:3D:82": "Google",
        "D0:2A:42": "Samsung",
        "D0:53:49": "Motorola",
        "D4:67:E7": "Samsung",
        "D8:0B:9A": "Huawei",
        "D8:1C:79": "Samsung",
        "D8:55:A3": "LG Electronics",
        "DC:0D:30": "Samsung",
        "DC:40:5F": "Sony",
        "E0:2C:12": "OnePlus",
        "E0:A0:30": "LG Electronics",
        "E4:4E:2D": "Motorola",
        "E8:50:8B": "Samsung",
        "EC:14:0E": "Huawei",
        "EC:1F:72": "Motorola",
        "F0:03:8C": "Samsung",
        "F0:1D:BC": "Google",
        "F0:7B:CB": "Samsung",
        "F4:4E:FD": "Sony",
        "F4:8C:50": "Huawei",
        "F4:F5:D8": "Samsung",
        "F8:2F:5C": "Huawei",
        "FC:61:3D": "Xiaomi",
        "FC:6E:1B": "Samsung",
    }

    return oui_db.get(prefix, "Unknown")
