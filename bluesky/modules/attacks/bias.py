"""
BIAS - Bluetooth Impersonation Attacks (CVE-2020-10135).
Requiere hardware específico para ataque activo (TP-Link UB500 con DarkFirmware).
El módulo de detección funciona con hardware básico.
"""

import subprocess
from typing import Optional

from bluesky.core.engine import BaseModule


class Bias(BaseModule):
    """BIAS - Escanea y detecta vulnerabilidad BIAS en dispositivos Bluetooth Classic."""

    name = "bias"
    description = "BIAS (CVE-2020-10135): Bluetooth Impersonation Attack - Suplanta identidad de dispositivos emparejados previamente"
    author = "Bluesky Project"
    version = "0.1.0"
    cve = "CVE-2020-10135"
    cve_url = "https://francozappa.github.io/about-bias/"
    exploit_links = [
        "https://github.com/francozappa/bias",
    ]
    references = [
        "https://francozappa.github.io/about-bias/",
        "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-10135",
    ]
    requires_hardware = ["ubluetooth_dongle"]
    requires_root = True
    target_type = "classic"
    severity = "critical"

    SEVERITY_MAP = {
        "critical": "🔴",
        "high": "🟠",
        "medium": "🟡",
        "low": "⚪",
    }

    def run(self):
        """Ejecuta el módulo BIAS."""
        target = self.target

        if not target:
            return self._scan_environment()

        self.result["data"]["target"] = target

        # Fase 1: Análisis de vulnerabilidad
        analysis = self._analyze_bias_vulnerability(target)
        self.result["data"]["analysis"] = analysis

        # Fase 2: Verificar dispositivos emparejados
        paired = self._check_paired_devices(target)
        self.result["data"]["paired_devices"] = paired

        # Fase 3: Evaluar riesgo BIAS
        risk = self._evaluate_bias_risk(analysis, paired)
        self.result["data"]["risk_assessment"] = risk

        if risk.get("vulnerable", False):
            self.result["success"] = True
            self.result["data"]["warning"] = (
                f"⚠️  Dispositivo potencialmente vulnerable a BIAS\n"
                f"   Riesgo: {risk.get('level', 'unknown')}\n"
                f"   Dispositivos emparejados: {paired.get('count', 0)}\n"
                f"   Para ataque completo: TP-Link UB500 + DarkFirmware"
            )
        else:
            self.result["success"] = True
            self.result["data"]["message"] = "Dispositivo no parece vulnerable a BIAS"

        return self.result

    def _scan_environment(self) -> dict:
        """Escanea el entorno para dispositivos y analiza riesgo BIAS."""
        devices = []
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
        except Exception:
            pass

        # Listar dispositivos emparejados actualmente
        paired = self._list_paired_all()

        self.result["data"]["devices_nearby"] = devices
        self.result["data"]["paired_total"] = len(paired)
        self.result["data"]["paired_list"] = paired

        self.result["data"]["bias_info"] = (
            "BIAS afecta a TODOS los dispositivos Bluetooth Classic (BR/EDR)\n"
            "con versiones 4.0 hasta 5.2. El ataque funciona porque el\n"
            "estándar Bluetooth NO requiere autenticación durante reconexión\n"
            "con dispositivos previamente emparejados.\n\n"
            "🔴 Riesgo: Cualquier dispositivo con el que hayas emparejado\n"
            "   antes puede ser suplantado por un atacante.\n\n"
            "📌 Mitigación: Bluetooth 5.3+. Eliminar emparejamientos viejos.\n"
            "   Mantener firmware actualizado.\n"
        )
        self.result["data"]["total_devices"] = len(devices)
        self.result["success"] = True
        return self.result

    def _analyze_bias_vulnerability(self, mac: str) -> dict:
        """Analiza si un dispositivo específico es vulnerable a BIAS."""
        analysis = {
            "vulnerable": False,
            "confidence": "low",
            "details": [],
        }

        # BIAS afecta a todas las implementaciones BT Classic pre-5.3
        # Detectar tipo de dispositivo y versión
        try:
            info = subprocess.run(
                ["bluetoothctl", "info", mac],
                capture_output=True, text=True, timeout=8
            )
            output = info.stdout.lower()

            # Detectar si es Classic o BLE
            if "le" in output:
                analysis["details"].append("Dispositivo BLE - BIAS solo afecta Classic BR/EDR")

            # Verificar servicios (Classic tiene L2CAP, RFCOMM, etc.)
            sdp = subprocess.run(
                ["sdptool", "browse", mac],
                capture_output=True, text=True, timeout=10
            )
            if sdp.stdout and len(sdp.stdout) > 50:
                # Tiene servicios Classic - podría ser vulnerable
                analysis["details"].append("Servicios Bluetooth Classic detectados")
                analysis["vulnerable"] = True
                analysis["confidence"] = "medium"
            else:
                analysis["details"].append("No se detectaron servicios Classic")

        except Exception:
            pass

        # Verificar si está emparejado actualmente
        try:
            paired = subprocess.run(
                ["bluetoothctl", "paired-devices"],
                capture_output=True, text=True, timeout=5
            )
            if mac in paired.stdout:
                analysis["details"].append("Dispositivo actualmente emparejado - riesgo BIAS elevado")
                analysis["vulnerable"] = True
                analysis["confidence"] = "high"
        except Exception:
            pass

        return analysis

    def _check_paired_devices(self, mac: str) -> dict:
        """Verifica los dispositivos emparejados con el target."""
        paired = {"count": 0, "devices": []}

        try:
            result = subprocess.run(
                ["bluetoothctl", "paired-devices"],
                capture_output=True, text=True, timeout=5
            )
            for line in result.stdout.split("\n"):
                if "Device" in line:
                    parts = line.split("Device", 1)[1].strip().split(" ", 1)
                    if len(parts) >= 1:
                        paired["devices"].append({
                            "mac": parts[0].strip(),
                            "name": parts[1].strip() if len(parts) > 1 else "Unknown"
                        })
            paired["count"] = len(paired["devices"])
        except Exception:
            pass

        return paired

    def _list_paired_all(self) -> list:
        """Lista todos los dispositivos emparejados."""
        devices = []
        try:
            result = subprocess.run(
                ["bluetoothctl", "paired-devices"],
                capture_output=True, text=True, timeout=5
            )
            for line in result.stdout.split("\n"):
                if "Device" in line:
                    parts = line.split("Device", 1)[1].strip().split(" ", 1)
                    if len(parts) >= 1:
                        devices.append({
                            "mac": parts[0].strip(),
                            "name": parts[1].strip() if len(parts) > 1 else "Unknown"
                        })
        except Exception:
            pass
        return devices

    def _evaluate_bias_risk(self, analysis: dict, paired: dict) -> dict:
        """Evalúa el nivel de riesgo BIAS."""
        risk = {
            "vulnerable": analysis.get("vulnerable", False),
            "level": "low",
            "factors": [],
        }

        if analysis.get("confidence") == "high":
            risk["level"] = "critical"
            risk["factors"].append("Dispositivo emparejado - ataque BIAS viable")

        if analysis.get("confidence") == "medium":
            risk["level"] = "high"
            risk["factors"].append("Dispositivo Classic detectado - posiblemente vulnerable")

        if paired.get("count", 0) > 0:
            risk["factors"].append(f"{paired['count']} dispositivo(s) emparejado(s)")
            if risk["level"] == "low":
                risk["level"] = "medium"

        risk["recommendations"] = [
            "Eliminar emparejamientos que no uses",
            "Desactivar Bluetooth cuando no lo necesites",
            "Actualizar firmware del dispositivo si está disponible",
            "Dispositivos BT 5.3+ no son vulnerables a BIAS",
        ]

        return risk
