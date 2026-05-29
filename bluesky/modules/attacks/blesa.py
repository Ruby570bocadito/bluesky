"""
BLESA - Bluetooth Low Energy Spoofing Attack (CVE-2020-9770).
Detecta dispositivos BLE vulnerables a suplantación durante reconexión.
"""

import subprocess
import time
from typing import Optional

from bluesky.core.engine import BaseModule


class Blesa(BaseModule):
    """BLESA - Escanea y verifica vulnerabilidad BLESA en dispositivos BLE."""

    name = "blesa"
    description = "BLESA (CVE-2020-9770): Detecta dispositivos BLE vulnerables a spoofing durante reconexión"
    author = "Bluesky Project"
    version = "0.1.0"
    cve = "CVE-2020-9770, CVE-2020-10556"
    cve_url = "https://www.purdue.edu/newsroom/releases/2020/Q3/purdue-university-and-researchers-at-cisco,-the-university-of-texas,-iowa-state,-take-first-step-against-bluetooth-vulnerability.html"
    exploit_links = []
    references = [
        "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-9770",
        "https://www.cisa.gov/news-events/ics-advisories/icsa-20-231-01",
    ]
    requires_hardware = []
    requires_root = False
    target_type = "ble"
    severity = "high"

    def run(self):
        """Ejecuta el escáner BLESA."""
        target = self.target

        if not target:
            return self._scan_ble_devices()

        self.result["data"]["target"] = target

        try:
            # Fase 1: Escanear servicios BLE
            ble_info = self._scan_ble(target)
            self.result["data"]["ble_info"] = ble_info

            # Fase 2: Análisis de seguridad BLE
            security = self._analyze_security(target)
            self.result["data"]["security_analysis"] = security

            # Fase 3: Verificar reconexión
            reconnect = self._check_reconnect_behavior(target)
            self.result["data"]["reconnect_behavior"] = reconnect

            # Determinar vulnerabilidad
            vulns = []

            # Si no tiene bonding o permite reconexión sin autenticación
            if not security.get("bonding_required", True):
                vulns.append({
                    "name": "BLESA - No bonding required",
                    "severity": "high",
                    "detail": "Dispositivo no requiere bonding - vulnerable a spoofing"
                })

            if security.get("pairing_mode") == "just_works":
                vulns.append({
                    "name": "Just Works pairing - No MITM protection",
                    "severity": "medium",
                    "detail": "Usa 'Just Works' pairing - no protege contra MitM"
                })

            if reconnect.get("no_auth_reconnect", False):
                vulns.append({
                    "name": "BLESA - Reconexión sin autenticación",
                    "severity": "critical",
                    "detail": "No requiere reautenticación en reconexión - CVE-2020-9770"
                })

            self.result["data"]["vulnerabilities"] = vulns

            if vulns:
                self.result["success"] = True
                self.result["data"]["summary"] = f"Dispositivo potencialmente vulnerable: {len(vulns)} issues"
            else:
                self.result["success"] = True
                self.result["data"]["summary"] = "No se detectaron vulnerabilidades BLESA"

        except Exception as e:
            self.result["error"] = str(e)
            self.result["success"] = False

        return self.result

    def _scan_ble_devices(self) -> dict:
        """Escanea dispositivos BLE cercanos."""
        devices = []

        try:
            # Usar hcitool para escanear BLE
            result = subprocess.run(
                ["hcitool", "lescan", "--duplicates"],
                capture_output=True, text=True, timeout=12
            )
            for line in result.stdout.split("\n")[1:]:  # Skip header
                if line.strip() and not "LE Scan" in line:
                    parts = line.strip().split(None, 1)
                    if len(parts) == 2:
                        mac, name = parts
                        devices.append({"mac": mac, "name": name})
                    elif len(parts) == 1:
                        devices.append({"mac": parts[0], "name": "Unknown"})
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass

        # También intentar con bluetoothctl
        if not devices:
            try:
                result = subprocess.run(
                    ["bluetoothctl", "--timeout", "8", "scan", "on"],
                    capture_output=True, text=True, timeout=10
                )
                for line in result.stdout.split("\n"):
                    if "Device" in line:
                        parts = line.split("Device", 1)[1].strip().split(" ", 1)
                        if len(parts) >= 1:
                            mac = parts[0].strip()
                            name = parts[1].strip() if len(parts) > 1 else "Unknown"
                            devices.append({"mac": mac, "name": name})
            except (FileNotFoundError, subprocess.TimeoutExpired):
                pass

        self.result["data"]["devices"] = devices
        self.result["data"]["device_count"] = len(devices)

        if not devices:
            self.result["data"]["message"] = "No se encontraron dispositivos BLE cercanos"
        else:
            self.result["data"]["message"] = (
                f"Se encontraron {len(devices)} dispositivos BLE.\n"
                "Usa: bluesky attack blesa <MAC> para analizar uno específico"
            )

        self.result["success"] = len(devices) > 0
        return self.result

    def _scan_ble(self, mac: str) -> dict:
        """Escanea servicios BLE de un dispositivo."""
        info = {
            "services": [],
            "characteristics": [],
        }

        # Usar gatttool para leer servicios primarios
        try:
            result = subprocess.run(
                ["gatttool", "-b", mac, "--primary"],
                capture_output=True, text=True, timeout=15
            )
            for line in result.stdout.strip().split("\n"):
                if line.strip():
                    info["services"].append(line.strip())
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass

        # Usar bluetoothctl para info
        try:
            result = subprocess.run(
                ["bluetoothctl", "info", mac],
                capture_output=True, text=True, timeout=8
            )
            for line in result.stdout.split("\n"):
                if "UUID" in line:
                    info["services"].append(line.strip())
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass

        return info

    def _analyze_security(self, mac: str) -> dict:
        """Analiza la configuración de seguridad BLE."""
        security = {
            "pairing_mode": "unknown",
            "bonding_required": True,
            "encryption_required": True,
            "mitm_protection": False,
        }

        # Verificar si podemos leer servicios sin autenticación
        try:
            result = subprocess.run(
                ["gatttool", "-b", mac, "--char-read", "-a", "0x0001"],
                capture_output=True, text=True, timeout=10
            )
            # Si podemos leer datos sin auth, el dispositivo es inseguro
            if "read failed" not in result.stderr.lower():
                security["pairing_mode"] = "just_works"
                security["bonding_required"] = False
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass

        # Verificar características de seguridad
        try:
            result = subprocess.run(
                ["gatttool", "-b", mac, "--characteristics"],
                capture_output=True, text=True, timeout=15
            )
            output = result.stdout.lower()
            if "authenticate" in output:
                security["bonding_required"] = True
                security["mitm_protection"] = "mitm" in output
            if "encrypt" in output:
                security["encryption_required"] = True
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass

        return security

    def _check_reconnect_behavior(self, mac: str) -> dict:
        """Verifica si el dispositivo requiere autenticación en reconexión."""
        behavior = {
            "no_auth_reconnect": False,
            "bonding_required": True,
        }

        # Intentar reconexión rápida después de desconectar
        try:
            # Desconectar si estaba conectado
            subprocess.run(
                ["bluetoothctl", "disconnect", mac],
                capture_output=True, text=True, timeout=3
            )
            time.sleep(1)

            # Intentar conectar sin bonding previo
            result = subprocess.run(
                ["bluetoothctl", "connect", mac],
                capture_output=True, text=True, timeout=8
            )
            output = result.stdout.lower()

            if "connection successful" in output or "connected" in output:
                behavior["no_auth_reconnect"] = True
                behavior["bonding_required"] = False
            elif "authentication failed" in output:
                behavior["bonding_required"] = True
            elif "device not found" in output:
                behavior["bonding_required"] = True

        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass

        return behavior
