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

import re
import json
import logging
import subprocess
from typing import Dict, List, Optional
from pathlib import Path

from .platform import check_bleak, check_command
from .oui import lookup_vendor

log = logging.getLogger("bluesky.termux")


# ─── Validación de MAC ──────────────────────────────────────────────────────

# Validación MAC delegada al helper canónico en utils.network.
# Antes teníamos un _MAC_RE duplicado aquí; ahora reusamos mac_valid.
# Lazy import para evitar circular import al inicio del módulo.
def _is_valid_mac(address: str) -> bool:
    """Valida que una dirección tenga formato MAC Bluetooth.

    Delega en bluesky.utils.network.mac_valid (fuente única de verdad).
    """
    from .network import mac_valid
    return mac_valid(address)


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
    if not _is_valid_mac(address):
        log.warning("MAC inválida en get_device_info: %r", address)
        return None
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
    if not _is_valid_mac(address):
        log.warning("MAC inválida en pair_device: %r", address)
        return False
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
    if not _is_valid_mac(address):
        log.warning("MAC inválida en unpair_device: %r", address)
        return False
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
    if not _is_valid_mac(address):
        log.warning("MAC inválida en connect_device: %r", address)
        return False
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
    if not _is_valid_mac(address):
        log.warning("MAC inválida en disconnect_device: %r", address)
        return False
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

    Delega en la base OUI compartida del proyecto
    (bluesky.utils.oui), que extiende la mini-DB que vivía aquí.

    Args:
        mac: Dirección MAC (XX:XX:XX:XX:XX:XX)

    Returns:
        Nombre del fabricante o "Unknown"
    """
    return lookup_vendor(mac, default="Unknown")
