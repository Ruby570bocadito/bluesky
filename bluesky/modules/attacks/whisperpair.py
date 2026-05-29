"""
WhisperPair Scanner (CVE-2025-36911) - Detecta dispositivos vulnerables
al secuestro de Google Fast Pair.
"""

import subprocess
import re
from typing import Optional

from bluesky.core.engine import BaseModule


# Lista de dispositivos conocidos vulnerables a WhisperPair
VULNERABLE_DEVICES = {
    # Sony
    "WF-1000XM5": "Sony",
    "WF-1000XM4": "Sony",
    "WF-1000XM6": "Sony",
    "WH-1000XM4": "Sony",
    "WH-1000XM5": "Sony",
    "WH-1000XM6": "Sony",
    "WH-CH720N": "Sony",
    # JBL
    "TUNE BEAM": "JBL",
    "TUNE 130NC": "JBL",
    "LIVE PRO 2": "JBL",
    # Jabra
    "Elite 8 Active": "Jabra",
    "Elite 7 Pro": "Jabra",
    "Elite 85t": "Jabra",
    # Marshall
    "MOTIF II A.N.C.": "Marshall",
    "Monitor II": "Marshall",
    # Xiaomi
    "Redmi Buds 5 Pro": "Xiaomi",
    "Redmi Buds 4 Pro": "Xiaomi",
    # Nothing
    "Ear (a)": "Nothing",
    "Ear (2)": "Nothing",
    "Ear (1)": "Nothing",
    # OnePlus
    "Nord Buds 3 Pro": "OnePlus",
    "Nord Buds 2": "OnePlus",
    "Buds Pro 2": "OnePlus",
    # Soundcore (Anker)
    "Liberty 4 NC": "Soundcore",
    "Liberty 3 Pro": "Soundcore",
    "Space A40": "Soundcore",
    # Google
    "Pixel Buds Pro 2": "Google",
    "Pixel Buds Pro": "Google",
    "Pixel Buds A-Series": "Google",
    # Logitech
    "Zone True Wireless": "Logitech",
}


class Whisperpair(BaseModule):
    """WhisperPair Scanner - Detecta dispositivos vulnerables a CVE-2025-36911 (Google Fast Pair Hijacking)."""

    name = "whisperpair"
    description = "WhisperPair (CVE-2025-36911): Detecta dispositivos vulnerables al secuestro de Google Fast Pair y tracking de ubicación"
    author = "Bluesky Project"
    version = "0.1.0"
    cve = "CVE-2025-36911"
    cve_url = "https://nvd.nist.gov/vuln/detail/CVE-2025-36911"
    exploit_links = []
    references = [
        "https://nvd.nist.gov/vuln/detail/CVE-2025-36911",
        "https://github.com/nccgroup/WhisperPair",
    ]
    requires_hardware = []
    requires_root = False
    target_type = "both"
    severity = "critical"

    def run(self):
        """Ejecuta el escáner WhisperPair."""
        target = self.target

        self.result["data"]["scan_date"] = __import__('datetime').datetime.now().isoformat()

        if target:
            # Análisis de dispositivo específico
            return self._analyze_device(target)
        else:
            # Escaneo general
            return self._scan_environment()

    def _scan_environment(self) -> dict:
        """Escanea el entorno en busca de dispositivos vulnerables."""
        self.result["data"]["scan_type"] = "environment"

        # Obtener dispositivos BLE/Classic cercanos
        devices = self._discover_devices()
        self.result["data"]["devices_found"] = devices

        vulnerable = []
        for dev in devices:
            match = self._check_vulnerable(dev.get("name", ""), dev.get("mac", ""))
            if match:
                vulnerable.append({**dev, **match})

        self.result["data"]["vulnerable_devices"] = vulnerable
        self.result["data"]["total_found"] = len(devices)
        self.result["data"]["vulnerable_count"] = len(vulnerable)

        # Generar advertencias
        if vulnerable:
            self.result["success"] = True
            self.result["data"]["warning"] = (
                f"⚠️  Se encontraron {len(vulnerable)} dispositivos potencialmente vulnerables a WhisperPair.\n"
                "Estos dispositivos podrían ser secuestrados para escucha de micrófono "
                "y rastreo de ubicación vía Google Find Hub."
            )
        else:
            self.result["success"] = True
            self.result["data"]["message"] = (
                f"No se detectaron dispositivos vulnerables conocidos "
                f"entre {len(devices)} dispositivos encontrados."
            )

        return self.result

    def _analyze_device(self, mac: str) -> dict:
        """Analiza un dispositivo específico."""
        self.result["data"]["scan_type"] = "targeted"
        self.result["data"]["target"] = mac

        # Obtener información del dispositivo
        device_info = self._get_device_info(mac)
        self.result["data"]["device_info"] = device_info

        device_name = device_info.get("name", "")
        check = self._check_vulnerable(device_name, mac)

        if check:
            self.result["data"]["vulnerability"] = check
            self.result["success"] = True
            self.result["data"]["risk"] = (
                f"🔴 {device_name} está en la lista de dispositivos vulnerables conocidos a WhisperPair.\n"
                f"Fabricante: {check.get('manufacturer', 'Unknown')}\n"
                f"Riesgo: Secuestro de conexión, escucha de micrófono, rastreo de ubicación\n"
                f"Acción: Actualizar firmware del dispositivo (no basta con actualizar el móvil)"
            )
        else:
            self.result["success"] = True
            self.result["data"]["risk"] = (
                f"✅ {device_name or mac} no está en la lista de dispositivos vulnerables conocidos.\n"
                "Esto no garantiza inmunidad. Verifica con el fabricante si hay actualizaciones."
            )

        # Verificar Google Fast Pair
        fast_pair = self._check_fast_pair(device_info)
        self.result["data"]["fast_pair_status"] = fast_pair

        return self.result

    def _discover_devices(self) -> list:
        """Descubre dispositivos Bluetooth cercanos."""
        devices = []

        # Método 1: bluetoothctl
        try:
            result = subprocess.run(
                ["bluetoothctl", "--timeout", "8", "scan", "on"],
                capture_output=True, text=True, timeout=10
            )
            for line in result.stdout.split("\n"):
                if "Device" in line:
                    parts = line.split("Device", 1)[1].strip().split(" ", 1)
                    if len(parts) >= 1:
                        devices.append({
                            "mac": parts[0].strip(),
                            "name": parts[1].strip() if len(parts) > 1 else "Unknown"
                        })
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass

        # Método 2: hcitool scan (Classic)
        if not devices:
            try:
                result = subprocess.run(
                    ["hcitool", "scan"],
                    capture_output=True, text=True, timeout=10
                )
                for line in result.stdout.split("\n")[1:]:
                    if line.strip():
                        parts = line.strip().split(None, 1)
                        if len(parts) >= 1:
                            devices.append({
                                "mac": parts[0],
                                "name": parts[1] if len(parts) > 1 else "Unknown"
                            })
            except (FileNotFoundError, subprocess.TimeoutExpired):
                pass

        return devices

    def _get_device_info(self, mac: str) -> dict:
        """Obtiene información detallada de un dispositivo."""
        info = {"mac": mac, "name": "Unknown", "services": []}

        try:
            result = subprocess.run(
                ["bluetoothctl", "info", mac],
                capture_output=True, text=True, timeout=8
            )
            for line in result.stdout.split("\n"):
                if "Name" in line:
                    info["name"] = line.split(":")[-1].strip()
                elif "UUID" in line and "(" in line:
                    uuid = line.split("UUID:")[-1].strip() if "UUID:" in line else ""
                    svc_match = re.search(r'\((.+?)\)', line)
                    svc_name = svc_match.group(1) if svc_match else uuid
                    info["services"].append(svc_name)
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass

        # También intentar con sdptool
        try:
            result = subprocess.run(
                ["sdptool", "browse", mac],
                capture_output=True, text=True, timeout=10
            )
            if result.stdout:
                info["services"].append("(sdptool output available)")
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass

        return info

    def _check_vulnerable(self, device_name: str, mac: str = "") -> Optional[dict]:
        """Verifica si el nombre del dispositivo está en la lista de vulnerables."""
        if not device_name or device_name == "Unknown":
            return None

        device_lower = device_name.lower()

        for vuln_name, manufacturer in VULNERABLE_DEVICES.items():
            if vuln_name.lower() in device_lower:
                return {
                    "match": vuln_name,
                    "manufacturer": manufacturer,
                    "vulnerability": "WhisperPair (CVE-2025-36911)",
                    "risk": "Connection hijacking, microphone eavesdropping, location tracking",
                    "cve": "CVE-2025-36911",
                }

        # Verificar por fabricante
        for vuln_name, manufacturer in VULNERABLE_DEVICES.items():
            if manufacturer.lower() in device_lower:
                return {
                    "match": f"{manufacturer} device (posiblemente vulnerable)",
                    "manufacturer": manufacturer,
                    "vulnerability": "WhisperPair (CVE-2025-36911) - possible",
                    "risk": "Verificar con el fabricante si el modelo específico es vulnerable",
                    "cve": "CVE-2025-36911",
                    "uncertain": True,
                }

        return None

    def _check_fast_pair(self, device_info: dict) -> dict:
        """Verifica si el dispositivo usa Google Fast Pair."""
        status = {
            "fast_pair_detected": False,
            "note": "",
        }

        # Buscar indicadores de Fast Pair en servicios
        services = device_info.get("services", [])
        fast_pair_indicators = ["fast pair", "google", "fp"]

        for s in services:
            s_lower = s.lower()
            for indicator in fast_pair_indicators:
                if indicator in s_lower:
                    status["fast_pair_detected"] = True
                    status["note"] = f"Detectado servicio relacionado con Fast Pair: {s}"
                    break

        if not status["fast_pair_detected"]:
            status["note"] = "No se detectaron indicadores de Google Fast Pair"
            status["fast_pair_detected"] = None  # No podemos asegurar que no lo use

        return status
