"""
HardwareDetector - Detecta adaptadores Bluetooth disponibles
y verifica requisitos de hardware para ataques específicos.
Soporta Windows, Linux, Termux y WSL.
"""

import os
import re
import shutil
import subprocess
import logging
from typing import Dict, List, Optional, Tuple

from bluesky.utils.platform import (
    is_windows, is_termux, is_wsl, is_root as platform_is_root,
    get_platform, get_os_name, check_bleak, check_command,
)

log = logging.getLogger("bluesky.hardware")


class HardwareDetector:
    """Detecta y verifica hardware Bluetooth disponible (cross-platform)."""

    @staticmethod
    def is_termux() -> bool:
        """Detecta si estamos corriendo en Termux (Android)."""
        return is_termux()

    @staticmethod
    def is_root() -> bool:
        """Verifica si tenemos permisos root/admin."""
        return platform_is_root()

    @staticmethod
    def is_wsl() -> bool:
        """Detecta si estamos en WSL."""
        return is_wsl()

    @staticmethod
    def is_windows() -> bool:
        """Detecta si estamos en Windows nativo."""
        return is_windows()

    @staticmethod
    def get_bluetooth_devices() -> List[Dict]:
        """Detecta todos los dispositivos Bluetooth disponibles (cross-platform)."""
        if is_windows():
            return HardwareDetector._get_windows_devices()
        if is_termux():
            return HardwareDetector._get_termux_devices()
        return HardwareDetector._get_linux_devices()

    @staticmethod
    def _get_windows_devices() -> List[Dict]:
        """Detecta dispositivos Bluetooth en Windows."""
        devices = []

        # 1. Via PowerShell backend
        try:
            from bluesky.utils.windows_backend import list_adapters, get_radio_info
            adapters = list_adapters()
            for a in adapters:
                devices.append({
                    "interface": a.get("instance_id", "windows_bt"),
                    "mac": "",
                    "name": a.get("name", "Bluetooth Adapter"),
                    "type": "classic",
                    "status": a.get("status", ""),
                    "present": a.get("is_present", False),
                    "platform": "windows",
                })

            # Agregar info del radio (MAC)
            radios = get_radio_info()
            for i, r in enumerate(radios):
                if i < len(devices):
                    devices[i]["mac"] = r.get("mac", "")
                    if r.get("manufacturer") and devices[i]["name"] == "Bluetooth Adapter":
                        devices[i]["name"] = f"{r['manufacturer']} Bluetooth"

        except Exception:
            pass

        # 2. Fallback: PowerShell directo
        if not devices:
            ps_script = """
            $bt = Get-PnpDevice -Class Bluetooth -ErrorAction SilentlyContinue
            $result = @()
            foreach ($b in $bt) {
                $result += [PSCustomObject]@{
                    Name = $b.FriendlyName
                    Status = $b.Status
                    InstanceId = $b.InstanceId
                }
            }
            return $result | ConvertTo-Json -Compress
            """
            try:
                result = subprocess.run(
                    ["powershell", "-NoProfile", "-NonInteractive", "-Command", ps_script],
                    capture_output=True, text=True, timeout=10
                )
                if result.returncode == 0 and result.stdout.strip():
                    import json
                    parsed = json.loads(result.stdout)
                    if isinstance(parsed, list):
                        for a in parsed:
                            devices.append({
                                "interface": a.get("InstanceId", "windows_bt"),
                                "mac": "",
                                "name": a.get("Name", "Bluetooth Adapter"),
                                "type": "classic",
                                "status": a.get("Status", ""),
                                "platform": "windows",
                            })
            except Exception:
                pass

        return devices

    @staticmethod
    def _get_linux_devices() -> List[Dict]:
        """Detecta dispositivos Bluetooth en Linux/Termux."""
        devices = []

        # 1. Detectar vía hciconfig (Linux Bluetooth stack)
        try:
            result = subprocess.run(
                ["hciconfig", "-a"],
                capture_output=True, text=True, timeout=5
            )
            if result.returncode == 0:
                current = {}
                for line in result.stdout.split("\n"):
                    m = re.match(r'^(\w+):\s+', line)
                    if m:
                        if current:
                            devices.append(current)
                        current = {"interface": m.group(1)}
                    elif "BD Address" in line and current:
                        m2 = re.search(r'BD Address: (\S+)', line)
                        if m2:
                            current["mac"] = m2.group(1)
                    elif "Name" in line and current:
                        m2 = re.search(r"Name: '(.+)'", line)
                        if m2:
                            current["name"] = m2.group(1)
                    elif "Features" in line and current:
                        current["type"] = "classic"
                if current:
                    devices.append(current)
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass

        # 2. Detectar vía bluetoothctl (BlueZ moderno)
        if not devices:
            try:
                result = subprocess.run(
                    ["bluetoothctl", "list"],
                    capture_output=True, text=True, timeout=5
                )
                for line in result.stdout.split("\n"):
                    m = re.search(r'Controller (\S+)', line)
                    if m:
                        devices.append({
                            "interface": "hci0",
                            "mac": m.group(1),
                            "type": "classic",
                            "name": "Bluetooth Controller",
                        })
            except (FileNotFoundError, subprocess.TimeoutExpired):
                pass

        # 3. Fallback: detectar si existe /dev/hci o interfaz BT
        if not devices:
            if os.path.exists("/dev/hci0") or os.path.exists("/sys/class/bluetooth/hci0"):
                devices.append({
                    "interface": "hci0",
                    "mac": "unknown",
                    "type": "classic",
                    "name": "Built-in Bluetooth",
                })

        return devices

    @staticmethod
    def _get_termux_devices() -> List[Dict]:
        """Detecta adaptadores Bluetooth en Termux (Android) via Termux:API."""
        devices = []

        # 1. Via Termux:API
        try:
            from bluesky.utils.termux_backend import list_adapters as ta_list_adapters
            adapters = ta_list_adapters()
            for a in adapters:
                devices.append({
                    "interface": a.get("interface", "termux_bt"),
                    "mac": a.get("mac", ""),
                    "name": a.get("name", "Bluetooth (Android)"),
                    "type": "ble_classic",
                    "status": a.get("status", ""),
                    "platform": "termux",
                })
        except Exception as e:
            log.debug(f"Error con Termux:API para adaptadores: {e}")

        # 2. Fallback: BlueZ tools (hcitool/bluetoothctl via pkg)
        if not devices:
            try:
                result = subprocess.run(
                    ["bluetoothctl", "list"],
                    capture_output=True, text=True, timeout=5
                )
                for line in result.stdout.split("\n"):
                    m = re.search(r'Controller (\S+)', line)
                    if m:
                        mac = m.group(1)
                        devices.append({
                            "interface": "hci0",
                            "mac": mac,
                            "type": "ble_classic",
                            "name": f"Bluetooth ({mac})",
                            "platform": "termux_bluez",
                        })
            except (FileNotFoundError, subprocess.TimeoutExpired):
                pass

        # 3. Fallback extremo: verificar que estamos en Android con BT
        if not devices:
            try:
                # Verificar via getprop
                result = subprocess.run(
                    ["getprop", "bluetooth.status"],
                    capture_output=True, text=True, timeout=2
                )
                if result.returncode == 0 and result.stdout.strip():
                    devices.append({
                        "interface": "android_bt",
                        "mac": "unknown",
                        "name": "Android Bluetooth",
                        "type": "ble_classic",
                        "status": result.stdout.strip(),
                        "platform": "termux",
                    })
            except FileNotFoundError:
                pass

        return devices

    @staticmethod
    def get_adapter_info() -> Dict:
        """Obtiene información detallada del adaptador Bluetooth principal."""
        if is_windows():
            return HardwareDetector._get_windows_adapter_info()
        if is_termux():
            return HardwareDetector._get_termux_adapter_info()
        return HardwareDetector._get_linux_adapter_info()

    @staticmethod
    def _get_windows_adapter_info() -> Dict:
        """Información del adaptador Bluetooth en Windows."""
        info = {
            "available": False,
            "interface": "windows_bt",
            "mac": "",
            "name": "",
            "chipset": "",
            "features": [],
            "powered": False,
            "type": "unknown",
        }

        try:
            from bluesky.utils.windows_backend import (
                get_bluetooth_status, get_radio_info, list_paired_devices
            )
            status = get_bluetooth_status()
            info["available"] = status.get("available", False)
            info["powered"] = status.get("adapter_ok", False)
            info["name"] = status.get("adapter_name", "")
            info["service_active"] = status.get("service_running", False)

            # Obtener MAC
            radios = get_radio_info()
            for r in radios:
                mac = r.get("mac", "")
                if mac and mac != "Unknown":
                    info["mac"] = mac
                    break

            # Detectar capacidades vía presencia de BLE
            info["type"] = "ble_classic"  # Windows soporta ambos
            info["features"] = ["BR/EDR", "BLE"]

        except Exception:
            pass

        return info

    @staticmethod
    def _get_termux_adapter_info() -> Dict:
        """Información del adaptador Bluetooth en Termux (Android)."""
        info = {
            "available": False,
            "interface": "termux_bt",
            "mac": "",
            "name": "",
            "chipset": "",
            "features": [],
            "powered": False,
            "type": "unknown",
        }

        try:
            from bluesky.utils.termux_backend import get_status, list_adapters
            status = get_status()
            info["available"] = status.get("bluetooth_enabled", False)
            info["powered"] = status.get("bluetooth_enabled", False)
            info["name"] = status.get("adapter", "Android Bluetooth")
            info["backend"] = status.get("backend", "none")
            info["mac"] = status.get("adapter_mac", "")
            info["type"] = "ble_classic" if info["available"] else "unknown"
            info["features"] = ["BR/EDR", "BLE"]
            info["service_active"] = status.get("api_available", False)

            # Si el backend dice que no hay API, intentar con BlueZ tools
            if not info["available"]:
                try:
                    result = subprocess.run(
                        ["bluetoothctl", "show"],
                        capture_output=True, text=True, timeout=5
                    )
                    if "Powered: yes" in result.stdout:
                        info["available"] = True
                        info["powered"] = True
                        info["backend"] = "bluez"
                except FileNotFoundError:
                    pass

        except Exception as e:
            log.debug(f"Error obteniendo info adaptador Termux: {e}")

        return info

    @staticmethod
    def _get_linux_adapter_info() -> Dict:
        """Información del adaptador Bluetooth en Linux."""
        info = {
            "available": False,
            "interface": "",
            "mac": "",
            "name": "",
            "chipset": "",
            "features": [],
            "powered": False,
            "type": "unknown",
        }

        try:
            result = subprocess.run(
                ["hciconfig", "-a"],
                capture_output=True, text=True, timeout=5
            )
            if result.returncode == 0:
                output = result.stdout
                m = re.search(r'(\w+):\s+.*BD Address:\s+(\S+)', output)
                if m:
                    info["interface"] = m.group(1)
                    info["mac"] = m.group(2)
                    info["available"] = True
                    iface = m.group(1)
                    rest = output.split(iface + ":")[1][:50] if iface in output else ""
                    info["powered"] = "UP" in rest

                m2 = re.search(r"Name: '(.+)'", output)
                if m2:
                    info["name"] = m2.group(1)

                if "LESC" in output:
                    info["features"].append("LE Secure Connections")
                    info["type"] = "ble_classic"
                if "BR/EDR" in output:
                    info["features"].append("BR/EDR")
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass

        # Verificar si bluetooth service está activo
        try:
            result = subprocess.run(
                ["systemctl", "is-active", "bluetooth"],
                capture_output=True, text=True, timeout=3
            )
            info["service_active"] = result.stdout.strip() == "active"
        except (FileNotFoundError, subprocess.TimeoutExpired):
            info["service_active"] = False

        return info

    @staticmethod
    def check_hardware_requirement(requirement: str) -> Tuple[bool, str]:
        """
        Verifica si se cumple un requisito de hardware específico.
        
        Args:
            requirement: Nombre del requisito
            (ej: 'csr_dongle', 'ubertooth', 'nrf52840', 'internal_bt', 'bleak')
        
        Returns:
            Tuple[bool, str]: (disponible, mensaje)
        """
        requirements = {
            "csr_dongle": {
                "description": "Dongle CSR 4.0+ para ataques LMP/HCI",
                "check": lambda: _check_usb_vendor(["0a12", "0a5c"]),
            },
            "ubluetooth_dongle": {
                "description": "Dongle TP-Link UB500 o similar para DarkFirmware",
                "check": lambda: _check_usb_vendor(["2357"]) or _check_usb_product(["rtl8761"]),
            },
            "ubertooth": {
                "description": "Ubertooth One para sniffing BLE/Classic",
                "check": lambda: _check_usb_vendor(["1d50"]) and _check_usb_product(["6002"]),
            },
            "nrf52840": {
                "description": "nRF52840 para ataques BLE avanzados",
                "check": lambda: shutil.which("nrfjprog") is not None,
            },
            "internal_bt": {
                "description": "Bluetooth interno del dispositivo",
                "check": lambda: len(HardwareDetector.get_bluetooth_devices()) > 0,
            },
            "root": {
                "description": "Acceso root/admin para ataques a bajo nivel",
                "check": lambda: HardwareDetector.is_root(),
            },
            "bleak": {
                "description": "Librería bleak para BLE (cross-platform)",
                "check": lambda: check_bleak(),
            },
            "windows_native": {
                "description": "Windows nativo (no WSL)",
                "check": lambda: is_windows(),
            },
        }

        req = requirements.get(requirement)
        if not req:
            return False, f"Requisito de hardware desconocido: {requirement}"

        try:
            available = req["check"]()
            if available:
                return True, f"✅ {req['description']}: Disponible"
            return False, f"❌ {req['description']}: No disponible"
        except Exception as e:
            return False, f"❌ {req['description']}: Error al verificar ({e})"

    @staticmethod
    def get_capabilities() -> Dict[str, bool]:
        """Retorna un resumen de capacidades del hardware actual."""
        bt_devices = HardwareDetector.get_bluetooth_devices()
        adapter = HardwareDetector.get_adapter_info()
        is_root = HardwareDetector.is_root()
        platform_name = get_platform()

        return {
            "platform": platform_name,
            "bluetooth_available": len(bt_devices) > 0,
            "adapter_powered": adapter.get("powered", False),
            "ble_support": check_bleak() or "ble" in adapter.get("type", ""),
            "classic_support": "classic" in adapter.get("type", "") or adapter.get("type") != "unknown",
            "is_root": is_root,
            "is_termux": is_termux(),
            "is_windows": is_windows(),
            "is_wsl": is_wsl(),
            "csr_dongle": _check_usb_vendor(["0a12", "0a5c"]),
            "bleak_available": check_bleak(),
            "interface": adapter.get("interface", ""),
            "mac": adapter.get("mac", ""),
            "adapters": len(bt_devices),
        }


def _check_usb_vendor(vendor_ids: List[str]) -> bool:
    """Verifica si hay un dispositivo USB con vendor ID específico (Windows o Linux)."""
    if is_windows():
        return _check_usb_vendor_windows(vendor_ids)
    return _check_usb_vendor_linux(vendor_ids)


def _check_usb_vendor_linux(vendor_ids: List[str]) -> bool:
    """Verifica vendor ID en Linux via lsusb."""
    try:
        result = subprocess.run(
            ["lsusb"],
            capture_output=True, text=True, timeout=3
        )
        for vid in vendor_ids:
            if vid.lower() in result.stdout.lower():
                return True
        return False
    except FileNotFoundError:
        return False


def _check_usb_vendor_windows(vendor_ids: List[str]) -> bool:
    """Verifica vendor ID en Windows via PowerShell."""
    try:
        # Convertir vendor IDs a formato Windows (ej: 0a12 -> USB\VID_0A12)
        patterns = [f"VID_{vid.upper()}" for vid in vendor_ids]
        ps_script = f"""
        $devices = Get-PnpDevice -ErrorAction SilentlyContinue | Where-Object {{
            $_.InstanceId -match '{"|".join(patterns)}'
        }}
        if ($devices) {{ return 'FOUND' }}
        return 'NOT_FOUND'
        """
        result = subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-Command", ps_script],
            capture_output=True, text=True, timeout=10
        )
        return "FOUND" in result.stdout
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return False


def _check_usb_product(product_name: str) -> bool:
    """Verifica si hay un dispositivo USB con nombre de producto específico."""
    if is_windows():
        return _check_usb_product_windows(product_name)
    return _check_usb_product_linux(product_name)


def _check_usb_product_linux(product_name: str) -> bool:
    """Verifica producto en Linux via lsusb."""
    try:
        result = subprocess.run(
            ["lsusb"],
            capture_output=True, text=True, timeout=3
        )
        return product_name.lower() in result.stdout.lower()
    except FileNotFoundError:
        return False


def _check_usb_product_windows(product_name: str) -> bool:
    """Verifica producto en Windows via PowerShell."""
    try:
        ps_script = f"""
        $devices = Get-PnpDevice -ErrorAction SilentlyContinue |
                    Where-Object {{ $_.FriendlyName -match '{product_name}' }}
        if ($devices) {{ return 'FOUND' }}
        return 'NOT_FOUND'
        """
        result = subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-Command", ps_script],
            capture_output=True, text=True, timeout=10
        )
        return "FOUND" in result.stdout
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return False
