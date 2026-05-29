"""
Device Scanner - Escaneo de dispositivos Bluetooth Classic y BLE.
Soporta Windows (PowerShell, bleak), Linux (BlueZ tools) y Termux.
"""

import subprocess
import re
import time
from typing import List, Optional

from bluesky.core.engine import BaseModule
from bluesky.utils.platform import is_windows, is_termux, check_bleak, check_command


class DeviceScanner(BaseModule):
    """Escáner universal de dispositivos Bluetooth (Classic + BLE)."""

    name = "scan"
    description = "Escáner de dispositivos Bluetooth - Descubre dispositivos Classic y BLE cercanos"
    author = "Bluesky Project"
    version = "0.1.0"
    cve = ""
    requires_hardware = []
    requires_root = False
    target_type = "both"
    severity = "low"

    def run(self):
        """Ejecuta escaneo de dispositivos (cross-platform)."""
        scan_type = self.options.get("type", "all")  # all | classic | ble
        timeout = int(self.options.get("timeout", 8))
        self.result["data"]["scan_type"] = scan_type
        self.result["data"]["scan_time"] = timeout

        devices = []
        scan_start = time.time()

        if is_windows():
            devices = self._scan_windows(scan_type, timeout)
        else:
            # Linux / Termux
            if scan_type in ("all", "classic"):
                classic = self._scan_classic(timeout)
                devices.extend(classic)

            if scan_type in ("all", "ble"):
                ble = self._scan_ble(timeout)
                existing_macs = {d["mac"] for d in devices}
                for d in ble:
                    if d["mac"] not in existing_macs:
                        devices.append(d)
                        existing_macs.add(d["mac"])

        scan_duration = time.time() - scan_start

        # Obtener info detallada
        for dev in devices:
            if "info" not in dev or not dev["info"]:
                dev["info"] = self._get_device_info(dev["mac"])

        self.result["data"]["devices"] = devices
        self.result["data"]["total"] = len(devices)
        self.result["data"]["scan_duration"] = f"{scan_duration:.1f}s"
        self.result["success"] = len(devices) > 0

        if not devices:
            self.result["data"]["message"] = (
                "No se encontraron dispositivos Bluetooth.\n"
                "Asegúrate de que Bluetooth esté encendido y visible."
            )

        return self.result

    # ─── Windows Backend ───────────────────────────────────

    def _scan_windows(self, scan_type: str, timeout: int) -> List[dict]:
        """Escanea dispositivos Bluetooth en Windows nativo."""
        devices = []

        # BLE via bleak (si está disponible)
        if scan_type in ("all", "ble") and check_bleak():
            try:
                ble_devices = self._scan_ble_windows_bleak(timeout)
                devices.extend(ble_devices)
            except Exception:
                pass

        # Classic via PowerShell
        if scan_type in ("all", "classic"):
            try:
                classic = self._scan_classic_windows(timeout)
                existing = {d["mac"] for d in devices if d.get("mac")}
                for d in classic:
                    if d["mac"] not in existing:
                        devices.append(d)
                        existing.add(d["mac"])
            except Exception:
                pass

        return devices

    def _scan_ble_windows_bleak(self, timeout: int) -> List[dict]:
        """Escanea BLE en Windows usando bleak."""
        devices = []
        try:
            import asyncio
            from bleak import BleakScanner

            async def scan():
                return await BleakScanner.discover(timeout=timeout)

            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            found = loop.run_until_complete(scan())
            loop.close()

            for dev in found:
                name = dev.name or "Unknown"
                mac = dev.address or ""
                if mac:
                    devices.append({
                        "mac": mac,
                        "name": name,
                        "type": "ble",
                        "rssi": dev.rssi or 0,
                    })
        except ImportError:
            pass  # bleak no instalado
        except Exception as e:
            self.result["data"]["ble_error"] = str(e)

        return devices

    def _scan_classic_windows(self, timeout: int) -> List[dict]:
        """Escanea dispositivos Classic en Windows via PowerShell."""
        devices = []

        # Intentar 1: Get-WmiObject Win32_BluetoothDevice (no requiere scan activo)
        ps_script = """
        $devices = @()
        # Método 1: WMI
        try {
            $bt = Get-WmiObject -Class Win32_BluetoothDevice -ErrorAction SilentlyContinue
            foreach ($d in $bt) {
                $mac = if ($d.DeviceID) {
                    ($d.DeviceID -replace '.*_([^_]+)$','$1') -replace '(..)','$1:' -replace ':$',''
                } else { '' }
                $devices += [PSCustomObject]@{ Name = $d.Name; MAC = $mac; Type = 'classic'; RSSI = 0 }
            }
        } catch {}

        # Método 2: Get-PnpDevice (dispositivos emparejados)
        if ($devices.Count -eq 0) {
            $btDevices = Get-PnpDevice -Class Bluetooth -ErrorAction SilentlyContinue |
                         Where-Object { $_.FriendlyName -notlike '*Radio*' -and $_.FriendlyName -notlike '*Adapter*' }
            foreach ($d in $btDevices) {
                $mac = if ($d.InstanceId -match '([0-9A-Fa-f]{12})$') { 
                    $matches[1] -replace '(..)','$1:' -replace ':$',''
                } else { '' }
                $devices += [PSCustomObject]@{ Name = $d.FriendlyName; MAC = $mac; Type = 'classic'; RSSI = 0 }
            }
        }

        return $devices | ConvertTo-Json -Compress
        """
        try:
            result = subprocess.run(
                ["powershell", "-NoProfile", "-NonInteractive", "-Command", ps_script],
                capture_output=True, text=True, timeout=timeout + 5
            )
            if result.returncode == 0 and result.stdout.strip():
                import json
                parsed = json.loads(result.stdout)
                if isinstance(parsed, list):
                    for d in parsed:
                        mac = d.get("MAC", "").strip()
                        if mac:
                            devices.append({
                                "mac": mac,
                                "name": d.get("Name", "Unknown"),
                                "type": "classic",
                                "rssi": d.get("RSSI", 0),
                            })
        except Exception:
            pass

        # Intentar 2: Windows.Devices.Bluetooth (scan activo)
        if not devices:
            devices = self._scan_classic_windows_winrt(timeout)

        return devices

    def _scan_classic_windows_winrt(self, timeout: int) -> List[dict]:
        """Escanea Classic en Windows via WinRT (Windows 10+)."""
        ps_script = f"""
        Add-Type -AssemblyName System.Runtime.WindowsRuntime
        $asTaskGeneric = ([System.WindowsRuntimeSystemExtensions].GetMethods() | 
            Where-Object {{ $_.Name -eq 'AsTask' -and $_.GetParameters().Count -eq 1 -and 
            $_.GetParameters()[0].ParameterType.Name -eq 'IAsyncOperation`1' }})[0]
        Function Await($WinRtTask, $ResultType) {{
            $asTask = $asTaskGeneric.MakeGenericMethod($ResultType)
            $netTask = $asTask.Invoke($null, @($WinRtTask))
            $netTask.Wait(-1) | Out-Null
            $netTask.Result
        }}
        [Windows.Devices.Bluetooth.BluetoothDevice,Windows.System.Devices,ContentType=WindowsRuntime] | Out-Null
        [Windows.Devices.Enumeration.DeviceInformation,Windows.System.Devices,ContentType=WindowsRuntime] | Out-Null

        $selector = [Windows.Devices.Bluetooth.BluetoothDevice]::GetDeviceSelector()
        $devices = Await ([Windows.Devices.Enumeration.DeviceInformation]::FindAllAsync($selector)) ([Windows.Devices.Enumeration.DeviceInformationCollection])

        $result = @()
        foreach ($d in $devices) {{
            $result += [PSCustomObject]@{{
                Name = $d.Name
                Id   = $d.Id
            }}
        }}
        return $result | ConvertTo-Json -Compress
        """
        try:
            result = subprocess.run(
                ["powershell", "-NoProfile", "-NonInteractive", "-Command", ps_script],
                capture_output=True, text=True, timeout=timeout + 10
            )
            if result.returncode == 0 and result.stdout.strip():
                import json
                parsed = json.loads(result.stdout)
                if isinstance(parsed, list):
                    for d in parsed:
                        name = d.get("Name", "Unknown")
                        dev_id = d.get("Id", "")
                        # Extraer MAC del Id si es posible
                        mac_match = re.search(r'([0-9A-Fa-f]{12})', dev_id)
                        mac = ""
                        if mac_match:
                            raw = mac_match.group(1)
                            mac = ":".join(raw[i:i+2] for i in range(0, 12, 2))
                        if mac:
                            devices.append({
                                "mac": mac,
                                "name": name,
                                "type": "classic",
                                "rssi": 0,
                            })
        except Exception:
            pass

        return devices

    # ─── Linux Backend (existente) ──────────────────────────

    def _scan_classic(self, timeout: int) -> List[dict]:
        """Escanea dispositivos Bluetooth Classic (Linux/Termux)."""
        devices = []

        # Método 1: bluetoothctl
        try:
            result = subprocess.run(
                ["bluetoothctl", "--timeout", str(timeout), "scan", "on"],
                capture_output=True, text=True, timeout=timeout + 3
            )
            for line in result.stdout.split("\n"):
                if "Device" in line:
                    parts = line.split("Device", 1)[1].strip().split(" ", 1)
                    if len(parts) >= 1:
                        mac = parts[0].strip()
                        name = parts[1].strip() if len(parts) > 1 else "Unknown"
                        if not any(d["mac"] == mac for d in devices):
                            devices.append({
                                "mac": mac,
                                "name": name,
                                "type": "classic",
                                "rssi": 0,
                            })
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass

        # Método 2: hcitool scan (fallback)
        if not devices:
            try:
                result = subprocess.run(
                    ["hcitool", "scan"],
                    capture_output=True, text=True, timeout=timeout + 2
                )
                for line in result.stdout.split("\n")[1:]:
                    if line.strip():
                        parts = line.strip().split(None, 1)
                        if len(parts) >= 1:
                            mac = parts[0]
                            name = parts[1] if len(parts) > 1 else "Unknown"
                            if not any(d["mac"] == mac for d in devices):
                                devices.append({
                                    "mac": mac,
                                    "name": name,
                                    "type": "classic",
                                    "rssi": 0,
                                })
            except (FileNotFoundError, subprocess.TimeoutExpired):
                pass

        return devices

    def _scan_ble(self, timeout: int) -> List[dict]:
        """Escanea dispositivos BLE (Linux/Termux)."""
        devices = []

        # Método 1: hcitool lescan
        try:
            result = subprocess.run(
                ["hcitool", "lescan", "--duplicates"],
                capture_output=True, text=True, timeout=timeout + 2
            )
            for line in result.stdout.split("\n")[1:]:
                if line.strip() and "LE Scan" not in line:
                    parts = line.strip().split(None, 1)
                    if len(parts) >= 1:
                        mac = parts[0]
                        name = parts[1] if len(parts) > 1 else "Unknown"
                        if not any(d["mac"] == mac for d in devices):
                            devices.append({
                                "mac": mac,
                                "name": name,
                                "type": "ble",
                                "rssi": 0,
                            })
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass

        # Método 2: bluetoothctl scan (incluye BLE)
        if not devices:
            try:
                result = subprocess.run(
                    ["bluetoothctl", "--timeout", str(timeout), "scan", "on"],
                    capture_output=True, text=True, timeout=timeout + 3
                )
                for line in result.stdout.split("\n"):
                    if "Device" in line:
                        parts = line.split("Device", 1)[1].strip().split(" ", 1)
                        if len(parts) >= 1:
                            mac = parts[0].strip()
                            name = parts[1].strip() if len(parts) > 1 else "Unknown"
                            if not any(d["mac"] == mac for d in devices):
                                devices.append({
                                    "mac": mac,
                                    "name": name,
                                    "type": "ble",
                                    "rssi": 0,
                                })
            except (FileNotFoundError, subprocess.TimeoutExpired):
                pass

        return devices

    def _get_device_info(self, mac: str) -> dict:
        """Obtiene información adicional del dispositivo (cross-platform)."""
        info = {"services": []}

        if is_windows():
            return self._get_device_info_windows(mac)

        # Linux / Termux
        try:
            result = subprocess.run(
                ["bluetoothctl", "info", mac],
                capture_output=True, text=True, timeout=5
            )
            for line in result.stdout.split("\n"):
                if "RSSI" in line:
                    try:
                        info["rssi"] = int(re.search(r'RSSI:\s*(-?\d+)', line).group(1))
                    except Exception:
                        pass
                elif "Paired" in line:
                    info["paired"] = "yes" in line.lower()
                elif "Trusted" in line:
                    info["trusted"] = "yes" in line.lower()
                elif "Blocked" in line:
                    info["blocked"] = "yes" in line.lower()
        except Exception:
            pass

        return info

    def _get_device_info_windows(self, mac: str) -> dict:
        """Obtiene información de dispositivo en Windows."""
        info = {"rssi": 0, "paired": False}

        ps_script = f"""
        $bt = Get-WmiObject -Class Win32_BluetoothDevice -ErrorAction SilentlyContinue |
              Where-Object {{ $_.DeviceID -like '*{mac.replace(":", "").upper()}*' -or 
                             $_.DeviceID -like '*{mac.replace(":", "").lower()}*' }}
        if ($bt) {{
            $result = [PSCustomObject]@{{
                Connected = $bt.Connected
                Paired = $bt.Paired
                Name = $bt.Name
            }}
            return $result | ConvertTo-Json -Compress
        }}
        return '{{}}'
        """
        try:
            result = subprocess.run(
                ["powershell", "-NoProfile", "-NonInteractive", "-Command", ps_script],
                capture_output=True, text=True, timeout=5
            )
            if result.stdout.strip():
                import json
                data = json.loads(result.stdout)
                if data:
                    info["paired"] = data.get("Paired", False)
                    info["connected"] = data.get("Connected", False)
        except Exception:
            pass

        return info
