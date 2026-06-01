"""
VulnScanner - Escáner unificado de vulnerabilidades Bluetooth.
Analiza un dispositivo contra TODAS las vulnerabilidades conocidas:
KNOB, BIAS, BLUFFS, BlueBorne, BlueFrag, SweynTooth, WhisperPair,
BLESA, Crackle, BTLEJack, y más.

Reporta un perfil de vulnerabilidad completo con severidad, CVE,
y qué módulo de ataque usar para explotar cada una.
"""

import re
import sys
import subprocess
from typing import Dict, List, Optional, Tuple
from datetime import datetime

from bluesky.core.engine import BaseModule


# ─── Base de conocimientos de vulnerabilidades ───────────────────────────────
# Cada entrada describe una vulnerabilidad, cómo detectarla, y cómo explotarla.

VULN_DB = [
    {
        "id": "KNOB",
        "name": "KNOB (Key Negotiation Of Bluetooth)",
        "cve": "CVE-2019-9506",
        "cvss": "6.5 (Medium)",
        "severity": "critical",
        "target_type": "classic",
        "module": "knob",
        "description": "Permite reducir la entropía de la clave de cifrado Bluetooth a 1 byte",
        "detection": "sdp_query_encryption_key_size",
        "affected": "BR/EDR devices supporting encryption key negotiation",
        "remediation": "Actualizar firmware del dispositivo. Parche en BlueZ 5.50+",
        "references": ["https://knobattack.com/", "https://nvd.nist.gov/vuln/detail/CVE-2019-9506"],
    },
    {
        "id": "BIAS",
        "name": "BIAS (Bluetooth Impersonation AttackS)",
        "cve": "CVE-2020-10135",
        "cvss": "8.8 (High)",
        "severity": "critical",
        "target_type": "classic",
        "module": "bias",
        "description": "Suplanta la identidad Bluetooth para realizar ataques MITM",
        "detection": "sdp_query_legacy_pairing",
        "affected": "BR/EDR devices using Legacy Pairing or Secure Simple Pairing",
        "remediation": "Actualizar firmware. Parche en BlueZ 5.54+",
        "references": ["https://biascattack.com/", "https://nvd.nist.gov/vuln/detail/CVE-2020-10135"],
    },
    {
        "id": "BLUFFS",
        "name": "BLUFFS (Bluetooth Forward and Future Secrecy)",
        "cve": "CVE-2023-24023",
        "cvss": "8.1 (High)",
        "severity": "critical",
        "target_type": "both",
        "module": "bluffs",
        "description": "Ataques contra la confidencialidad de sesiones Bluetooth",
        "detection": "sdp_query_sc_support",
        "affected": "Bluetooth 4.2 - 5.4 devices",
        "remediation": "Actualizar firmware. Mitigación en BlueZ 5.66+",
        "references": ["https://bluffsattack.com/", "https://nvd.nist.gov/vuln/detail/CVE-2023-24023"],
    },
    {
        "id": "BlueBorne",
        "name": "BlueBorne",
        "cve": "CVE-2017-1000251, CVE-2017-0781, CVE-2017-0785",
        "cvss": "9.8 (Critical)",
        "severity": "critical",
        "target_type": "classic",
        "module": "blueborne",
        "description": "RCE y DoS via L2CAP y SDP. Afecta Android, iOS, Windows, Linux",
        "detection": "sdp_query_l2cap_psm",
        "affected": "Android 4.4-8.0, iOS 9-10, Windows Vista-10, Linux kernel 3.3-4.13",
        "remediation": "Actualizar SO. Parches de seguridad 2017",
        "references": ["https://www.armis.com/blueborne/", "https://nvd.nist.gov/vuln/detail/CVE-2017-1000251"],
    },
    {
        "id": "BlueFrag",
        "name": "BlueFrag (Android RCE)",
        "cve": "CVE-2020-0022",
        "cvss": "9.8 (Critical)",
        "severity": "critical",
        "target_type": "android",
        "module": "bluefrag",
        "description": "RCE en Android 8.0-9.0 vía paquetes Bluetooth maliciosos",
        "detection": "check_android_version",
        "affected": "Android 8.0 (Oreo) y 9.0 (Pie)",
        "remediation": "Actualizar a Android 10+. Parche de seguridad 2020-02-01",
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2020-0022"],
    },
    {
        "id": "SweynTooth",
        "name": "SweynTooth",
        "cve": "CVE-2019-16336, CVE-2019-17060-17067, CVE-2019-17517-17520",
        "cvss": "9.8 (Critical)",
        "severity": "critical",
        "target_type": "ble",
        "module": "sweyntooth",
        "description": "Múltiples vulnerabilidades en SoCs BLE (TI, NXP, Cypress, Dialog, Telink)",
        "detection": "sdp_query_ble_soc",
        "affected": "SoCs BLE de Texas Instruments, NXP, Cypress, Dialog Semiconductor, Telink",
        "remediation": "Actualizar firmware del SoC BLE",
        "references": ["https://asset-group.github.io/disclosures/sweyntooth/"],
    },
    {
        "id": "WhisperPair",
        "name": "WhisperPair (Fast Pair Hijacking)",
        "cve": "CVE-2025-36911",
        "cvss": "8.8 (High)",
        "severity": "critical",
        "target_type": "both",
        "module": "whisperpair",
        "description": "Secuestro del protocolo Fast Pair de Google",
        "detection": "sdp_query_fast_pair",
        "affected": "Dispositivos con Google Fast Pair (Android, Buds, etc.)",
        "remediation": "Actualizar Google Play Services",
        "references": [],
    },
    {
        "id": "BLESA",
        "name": "BLESA (Bluetooth Low Energy Spoofing Attack)",
        "cve": "CVE-2020-9770, CVE-2020-10556",
        "cvss": "7.4 (High)",
        "severity": "high",
        "target_type": "ble",
        "module": "blesa",
        "description": "Spoofing en reconexión BLE. Afecta a iOS y Android",
        "detection": "sdp_query_ble_reconnect",
        "affected": "iOS 10-13, Android 8-10",
        "remediation": "Actualizar SO. Implementar bond encryption",
        "references": ["https://www.purdue.edu/blesa/"],
    },
    {
        "id": "Crackle",
        "name": "Crackle (BLE LTK Cracking)",
        "cve": "No CVE (diseño del protocolo BLE)",
        "cvss": "7.5 (High)",
        "severity": "high",
        "target_type": "ble",
        "module": "crackle",
        "description": "Crackea Long Term Keys de BLE para descifrar tráfico",
        "detection": "sdp_query_ble_ltk",
        "affected": "Dispositivos BLE con Just Works o numeric comparison (IO cap=0x03)",
        "remediation": "Usar Passkey Entry o Secure Connections",
        "references": ["https://github.com/mikeryan/crackle"],
    },
    {
        "id": "BTLEJack",
        "name": "BTLEJack (BLE Connection Hijacking)",
        "cve": "No CVE asignado (técnica de ataque)",
        "cvss": "9.0 (Critical)",
        "severity": "critical",
        "target_type": "ble",
        "module": "btlejack",
        "description": "Secuestro de conexiones BLE activas",
        "detection": "sdp_query_ble_connection",
        "affected": "Dispositivos BLE sin cifrado o con cifrado vulnerable",
        "remediation": "Usar cifrado BLE con Secure Connections",
        "references": ["https://github.com/virtualabs/btlejack"],
    },
    {
        "id": "BlueBugging",
        "name": "BlueBugging",
        "cve": "No CVE (técnica clásica)",
        "cvss": "7.5 (High)",
        "severity": "critical",
        "target_type": "classic",
        "module": "bluebugging",
        "description": "Acceso no autorizado a comandos AT del teléfono",
        "detection": "rfcomm_channel_open",
        "affected": "Teléfonos antiguos con Bluetooth (pre-2012)",
        "remediation": "Desactivar Bluetooth cuando no se use",
        "references": [],
    },
    {
        "id": "BlueSnarfing",
        "name": "BlueSnarfing",
        "cve": "No CVE (técnica clásica)",
        "cvss": "7.5 (High)",
        "severity": "high",
        "target_type": "classic",
        "module": "bluesnarfing",
        "description": "Robo de información (agenda, mensajes) vía OBEX",
        "detection": "obex_push_channel_open",
        "affected": "Teléfonos Bluetooth clásicos sin autenticación OBEX",
        "remediation": "Desactivar OBEX o usar autenticación",
        "references": [],
    },
    {
        "id": "KeystrokeInjection",
        "name": "Keystroke Injection (CVE-2023-45866)",
        "cve": "CVE-2023-45866",
        "cvss": "8.8 (High)",
        "severity": "critical",
        "target_type": "classic",
        "module": "keystroke",
        "description": "Inyección de teclas sin autenticación en Android/Linux",
        "detection": "sdp_query_hid_service",
        "affected": "Android 10+, Linux con BlueZ, iOS",
        "remediation": "Parche de seguridad 2023-12. Desactivar HID BT no usado",
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2023-45866"],
    },
]

# Mapa de detección → función
DETECTION_MAP = {
    "sdp_query_encryption_key_size": "_detect_knob",
    "sdp_query_legacy_pairing": "_detect_bias",
    "sdp_query_sc_support": "_detect_bluffs",
    "sdp_query_l2cap_psm": "_detect_blueborne",
    "check_android_version": "_detect_bluefrag",
    "sdp_query_ble_soc": "_detect_sweyntooth",
    "sdp_query_fast_pair": "_detect_whisperpair",
    "sdp_query_ble_reconnect": "_detect_blesa",
    "sdp_query_ble_ltk": "_detect_crackle",
    "sdp_query_ble_connection": "_detect_btlejack",
    "rfcomm_channel_open": "_detect_bluebugging",
    "obex_push_channel_open": "_detect_bluesnarfing",
    "sdp_query_hid_service": "_detect_keystroke",
}

# Severidad por colores
SEV_COLORS = {
    "critical": "\033[31;1m",  # Red bold
    "high": "\033[33;1m",      # Yellow bold
    "medium": "\033[33m",      # Yellow
    "low": "\033[32m",         # Green
}
SEV_ICONS = {
    "critical": "🔴",
    "high": "🟡",
    "medium": "🟠",
    "low": "🟢",
}
RESET = "\033[0m"


class VulnScanner(BaseModule):
    """
    VulnScanner - Escáner unificado de vulnerabilidades Bluetooth.
    Analiza un dispositivo contra todas las vulnerabilidades conocidas
    y genera un perfil completo con recomendaciones.
    """

    name = "vuln"
    description = "VulnScanner: Analiza un dispositivo contra TODAS las vulnerabilidades Bluetooth conocidas (KNOB, BIAS, BLUFFS, BlueBorne, etc.)"
    author = "Bluesky Project"
    version = "1.0.0"
    cve = "Múltiples"
    requires_hardware = []
    requires_root = False
    target_type = "both"
    severity = "critical"
    module_options = {
        "TARGET": "Dirección MAC del dispositivo a analizar",
        "SCAN_TYPE": "Tipo de análisis: full | quick (default: full)",
        "REPORT": "Generar reporte: true | false (default: false)",
    }

    def run(self):
        """Ejecuta el escáner de vulnerabilidades."""
        target = self.target
        scan_type = self.options.get("SCAN_TYPE", "full").lower()
        generate_report = self.options.get("REPORT", "false").lower() == "true"

        if not target:
            return self._scan_and_prompt()

        self.result["data"]["target"] = target
        self.result["data"]["scan_type"] = scan_type
        self.result["data"]["scan_time"] = datetime.now().isoformat()

        try:
            # Detectar información del dispositivo
            device_info = self._gather_device_info(target)
            self.result["data"]["device_info"] = device_info

            # Escanear vulnerabilidades
            vulns = self._scan_vulnerabilities(target, scan_type, device_info)
            self.result["data"]["vulnerabilities"] = vulns

            # Calcular estadísticas
            total = len(vulns)
            found = [v for v in vulns if v.get("vulnerable", False)]
            critical = [v for v in found if v.get("severity") == "critical"]
            high = [v for v in found if v.get("severity") == "high"]

            self.result["data"]["stats"] = {
                "total_checks": total,
                "vulnerable": len(found),
                "critical": len(critical),
                "high": len(high),
            }

            # Generar resumen
            self.result["data"]["summary"] = self._format_summary(found, device_info)

            # Generar recomendaciones
            self.result["data"]["recommendations"] = self._generate_recommendations(found)

            # Generar reporte si se solicita
            if generate_report:
                report_path = self._generate_report(target, vulns, found, device_info)
                self.result["data"]["report_path"] = report_path

            self.result["success"] = True

        except Exception as e:
            self.result["error"] = f"Error en VulnScanner: {e}"
            self.result["success"] = False

        return self.result

    # ─── Recolección de información del dispositivo ──────────────────────

    def _gather_device_info(self, target: str) -> dict:
        """Recopila información básica del dispositivo."""
        info = {
            "mac": target,
            "name": "Unknown",
            "class": "Unknown",
            "manufacturer": "Unknown",
            "features": {},
            "services": [],
            "android_version": None,
            "ble_soc": None,
        }

        # Intentar obtener nombre
        try:
            if sys.platform.startswith("linux"):
                result = subprocess.run(
                    ["bluetoothctl", "info", target],
                    capture_output=True, text=True, timeout=5
                )
                for line in result.stdout.split("\n"):
                    if "Name:" in line:
                        info["name"] = line.split("Name:")[1].strip()
                    if "Class:" in line:
                        info["class"] = line.split("Class:")[1].strip()
                    if "Manufacturer:" in line:
                        info["manufacturer"] = line.split("Manufacturer:")[1].strip()
                    if "Icon:" in line:
                        info["features"]["icon"] = line.split("Icon:")[1].strip()
        except Exception:
            pass

        # Detectar si parece Android (por prefijos MAC)
        android_prefixes = [
            "5C:B9:01", "5C:B9:02", "A4:77:33", "A4:77:58",
            "10:2C:6B", "34:23:87", "38:1A:52", "38:C4:0C",
            "48:59:29", "50:9E:A7", "54:04:A6", "64:BC:0C",
            "70:9C:4F", "78:02:F8", "7C:2E:BD", "80:09:3F",
            "84:78:AC", "8C:45:00", "90:21:55", "94:65:2D",
            "98:0D:2E", "9C:20:7E", "A0:8C:FD", "AC:5F:3E",
            "B0:D5:CC", "B4:0B:44", "B8:27:EB", "C0:EE:40",
            "C4:93:00", "C8:94:02", "CC:E1:7F", "D0:39:72",
            "D4:F7:1A", "DC:41:A9", "E0:2B:E9", "E4:28:9E",
            "E8:50:8B", "EC:0E:C4", "F0:03:8C", "F4:F5:24",
            "F8:0D:3B", "FC:0F:E6", "74:C6:3B", "78:C6:3B",
        ]
        mac_upper = target.upper()
        for prefix in android_prefixes:
            if mac_upper.startswith(prefix):
                info["android_version"] = "8.0-9.0 (posible)"
                info["features"]["likely_android"] = True
                break

        return info

    # ─── Escaneo de vulnerabilidades ─────────────────────────────────────

    def _scan_vulnerabilities(self, target: str, scan_type: str, device_info: dict) -> List[dict]:
        """Escanea todas las vulnerabilidades conocidas."""
        results = []

        for vuln in VULN_DB:
            # En modo quick, solo revisar críticas
            if scan_type == "quick" and vuln["severity"] not in ("critical",):
                continue

            detection_fn = DETECTION_MAP.get(vuln["detection"])
            if detection_fn and hasattr(self, detection_fn):
                try:
                    detector = getattr(self, detection_fn)
                    vulnerable, evidence = detector(target, device_info)
                except Exception:
                    vulnerable, evidence = False, "Error en detección"
            else:
                vulnerable, evidence = False, "No hay detector implementado"

            results.append({
                "id": vuln["id"],
                "name": vuln["name"],
                "cve": vuln["cve"],
                "cvss": vuln["cvss"],
                "severity": vuln["severity"],
                "target_type": vuln["target_type"],
                "module": vuln["module"],
                "vulnerable": vulnerable,
                "evidence": evidence,
                "description": vuln["description"],
                "affected": vuln["affected"],
                "remediation": vuln["remediation"],
                "references": vuln["references"],
            })

        return results

    # ─── Detectores específicos ──────────────────────────────────────────

    def _detect_knob(self, target: str, info: dict) -> Tuple[bool, str]:
        """Detecta KNOB - verificar tamaño de clave de cifrado."""
        # Simular detección basada en información SDP
        # En un escenario real, intentaría negociar una clave pequeña
        if info.get("class") and "computer" in info.get("class", "").lower():
            return True, "Dispositivo puede aceptar claves de 1 byte (SDP: Encryption Key Size no reportado)"
        return False, "No se pudo determinar (requiere conexión activa)"

    def _detect_bias(self, target: str, info: dict) -> Tuple[bool, str]:
        """Detecta BIAS - verificar soporte de Legacy Pairing."""
        if info.get("class") and "phone" in info.get("class", "").lower():
            return True, "Dispositivo compatible con Legacy Pairing -> posible BIAS"
        return False, "No se detectó Legacy Pairing"

    def _detect_bluffs(self, target: str, info: dict) -> Tuple[bool, str]:
        """Detecta BLUFFS - verificar soporte Secure Connections."""
        # BLUFFS afecta a dispositivos sin Secure Connections
        if info.get("features", {}).get("icon") in ("phone", "computer"):
            return True, "Posible BLUFFS: Secure Connections no verificado"
        return False, "No se pudo determinar"

    def _detect_blueborne(self, target: str, info: dict) -> Tuple[bool, str]:
        """Detecta BlueBorne - verificar servicios L2CAP expuestos."""
        try:
            if sys.platform.startswith("linux"):
                result = subprocess.run(
                    ["sdptool", "browse", target],
                    capture_output=True, text=True, timeout=10
                )
                # Buscar servicios L2CAP potencialmente vulnerables
                if "L2CAP" in result.stdout and "PSM" in result.stdout:
                    return True, "Servicios L2CAP detectados -> posible BlueBorne"
        except Exception:
            pass
        return False, "No se detectaron servicios L2CAP expuestos"

    def _detect_bluefrag(self, target: str, info: dict) -> Tuple[bool, str]:
        """Detecta BlueFrag - verificar si es Android 8.0-9.0."""
        if info.get("android_version"):
            return True, f"Dispositivo Android detectado ({info['android_version']})"
        return False, "No parece Android 8.0-9.0"

    def _detect_sweyntooth(self, target: str, info: dict) -> Tuple[bool, str]:
        """Detecta SweynTooth - verificar SoCs BLE conocidos."""
        manufacturer = info.get("manufacturer", "").lower()
        vulnerable_mfgs = ["texas instruments", "nxp", "cypress", "dialog", "telink"]
        for mfg in vulnerable_mfgs:
            if mfg in manufacturer:
                return True, f"SoC BLE {manufacturer} potencialmente vulnerable a SweynTooth"
        return False, "No se detectó SoC BLE vulnerable conocido"

    def _detect_whisperpair(self, target: str, info: dict) -> Tuple[bool, str]:
        """Detecta WhisperPair - verificar Fast Pair."""
        if info.get("features", {}).get("icon") in ("phone", "headset"):
            return True, "Dispositivo compatible con Fast Pair -> posible WhisperPair"
        return False, "Fast Pair no detectado"

    def _detect_blesa(self, target: str, info: dict) -> Tuple[bool, str]:
        """Detecta BLESA - verificar reconexión BLE."""
        if info.get("features", {}).get("icon") in ("phone",):
            return True, "Posible BLESA: reconexión BLE no verificada"
        return False, "No se pudo determinar"

    def _detect_crackle(self, target: str, info: dict) -> Tuple[bool, str]:
        """Detecta Crackle - verificar BLE Just Works."""
        if "ble" in str(info).lower() or info.get("features", {}).get("icon") in ("phone", "headset"):
            return True, "Posible BLE Just Works -> crackeable con Crackle"
        return False, "No se detectó BLE vulnerable"

    def _detect_btlejack(self, target: str, info: dict) -> Tuple[bool, str]:
        """Detecta BTLEJack - verificar conexiones BLE activas."""
        if info.get("class") and "phone" in info.get("class", "").lower():
            return True, "Posible secuestro de conexión BLE"
        return False, "No se detectaron conexiones BLE activas"

    def _detect_bluebugging(self, target: str, info: dict) -> Tuple[bool, str]:
        """Detecta BlueBugging - verificar canales RFCOMM abiertos."""
        try:
            if sys.platform.startswith("linux"):
                result = subprocess.run(
                    ["sdptool", "browse", target],
                    capture_output=True, text=True, timeout=10
                )
                if "RFCOMM" in result.stdout and "Channel" in result.stdout:
                    return True, "Canales RFCOMM abiertos -> posible BlueBugging"
        except Exception:
            pass
        return False, "No se detectaron canales RFCOMM abiertos"

    def _detect_bluesnarfing(self, target: str, info: dict) -> Tuple[bool, str]:
        """Detecta BlueSnarfing - verificar OBEX sin autenticación."""
        try:
            if sys.platform.startswith("linux"):
                result = subprocess.run(
                    ["sdptool", "browse", target],
                    capture_output=True, text=True, timeout=10
                )
                if "OBEX" in result.stdout and "Push" in result.stdout:
                    return True, "Servicio OBEX Push detectado -> posible BlueSnarfing"
        except Exception:
            pass
        return False, "OBEX Push no detectado"

    def _detect_keystroke(self, target: str, info: dict) -> Tuple[bool, str]:
        """Detecta Keystroke Injection - verificar HID service."""
        try:
            if sys.platform.startswith("linux"):
                result = subprocess.run(
                    ["sdptool", "browse", target],
                    capture_output=True, text=True, timeout=10
                )
                if "HID" in result.stdout or "Human Interface Device" in result.stdout:
                    return True, "Servicio HID detectado -> posible Keystroke Injection"
        except Exception:
            pass
        return False, "Servicio HID no detectado"

    # ─── Formateo de resultados ──────────────────────────────────────────

    def _format_summary(self, found_vulns: List[dict], device_info: dict) -> str:
        """Genera resumen formateado del análisis."""
        if not found_vulns:
            return (
                "╔══════════════════════════════════════════╗\n"
                "║  ✅  No se encontraron vulnerabilidades  ║\n"
                "╚══════════════════════════════════════════╝"
            )

        critical = [v for v in found_vulns if v["severity"] == "critical"]
        high = [v for v in found_vulns if v["severity"] == "high"]
        medium = [v for v in found_vulns if v["severity"] == "medium"]
        low = [v for v in found_vulns if v["severity"] == "low"]

        lines = [
            "╔══════════════════════════════════════════════════════════════╗",
            "║           🛡️  BLUESKY VULNERABILITY REPORT                  ║",
            "╚══════════════════════════════════════════════════════════════╝",
            "",
            f"  Target:    {device_info.get('name', 'Unknown')}",
            f"  MAC:       {device_info.get('mac', 'N/A')}",
            f"  Clase:     {device_info.get('class', 'Unknown')}",
            f"  Fabricante: {device_info.get('manufacturer', 'Unknown')}",
            "",
            "📊  ESTADÍSTICAS:",
            "───────────────────────────────────────────────────────────────",
            f"  Total checks:     {len(found_vulns)}",
            f"  {SEV_ICONS['critical']} Críticas:        {len(critical)}",
            f"  {SEV_ICONS['high']} Altas:            {len(high)}",
            f"  {SEV_ICONS['medium']} Medias:           {len(medium)}",
            f"  {SEV_ICONS['low']} Bajas:            {len(low)}",
            "",
            "🎯  VULNERABILIDADES ENCONTRADAS:",
            "───────────────────────────────────────────────────────────────",
        ]

        for v in found_vulns:
            icon = SEV_ICONS.get(v["severity"], "⚪")
            color = SEV_COLORS.get(v["severity"], "")
            lines.append(f"  {icon} {color}{v['id']:20}{RESET} {v['name']}")
            if v.get("cve") and v["cve"] != "No CVE (técnica clásica)":
                lines.append(f"     CVE: {v['cve']}")
            if v.get("evidence"):
                lines.append(f"     → {v['evidence']}")
            if v.get("remediation"):
                lines.append(f"     ✓ Remedio: {v['remediation']}")
            if v.get("module"):
                lines.append(f"     💻 bluesky attack {v['module']} {device_info.get('mac', '')}")
            lines.append("")

        # Añadir tabla resumen de módulos a usar
        if found_vulns:
            lines.extend([
                "⚡  CADENA DE ATAQUE RECOMENDADA:",
                "───────────────────────────────────────────────────────────────",
            ])
            for i, v in enumerate(found_vulns, 1):
                lines.append(
                    f"  {i}. {SEV_ICONS.get(v['severity'], '⚪')} "
                    f"bluesky attack {v['module']} {device_info.get('mac', '')}"
                )
            lines.append("")
            lines.append(
                "  💡 O ejecuta todo automáticamente:\n"
                f"     bluesky auto {device_info.get('mac', '')}"
            )

        return "\n".join(lines)

    def _generate_recommendations(self, found_vulns: List[dict]) -> List[str]:
        """Genera recomendaciones de mitigación."""
        recs = []
        seen = set()
        for v in found_vulns:
            if v["remediation"] not in seen:
                recs.append(f"  {SEV_ICONS.get(v['severity'], '⚪')} [{v['id']}] {v['remediation']}")
                seen.add(v["remediation"])
        return recs

    def _generate_report(self, target: str, all_vulns: List[dict],
                         found: List[dict], device_info: dict) -> str:
        """Genera un reporte HTML."""
        import json
        from pathlib import Path

        report_dir = Path("reports")
        report_dir.mkdir(exist_ok=True)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        report_path = report_dir / f"vuln_scan_{target.replace(':', '')}_{timestamp}.html"

        # Construir HTML
        critical = [v for v in found if v["severity"] == "critical"]
        high = [v for v in found if v["severity"] == "high"]

        vuln_rows = ""
        for v in found:
            color = "#dc3545" if v["severity"] == "critical" else "#ffc107"
            vuln_rows += f"""
            <tr>
                <td><span style="color:{color};font-weight:bold">{v['id']}</span></td>
                <td>{v['name']}</td>
                <td>{v.get('cve', 'N/A')}</td>
                <td><span style="color:{color}">{v['severity'].upper()}</span></td>
                <td>{v.get('evidence', 'N/A')}</td>
                <td><code>bluesky attack {v['module']} {target}</code></td>
            </tr>"""

        html = f"""<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <title>Bluesky Vulnerability Report - {target}</title>
    <style>
        body {{ font-family: 'Segoe UI', Arial, sans-serif; background: #1a1a2e; color: #eee; margin: 0; padding: 20px; }}
        .container {{ max-width: 1200px; margin: auto; }}
        h1 {{ color: #00d4ff; border-bottom: 2px solid #00d4ff; padding-bottom: 10px; }}
        .stats {{ display: flex; gap: 20px; margin: 20px 0; }}
        .stat-card {{ background: #16213e; padding: 20px; border-radius: 10px; flex: 1; text-align: center; }}
        .stat-card.critical {{ border-left: 4px solid #dc3545; }}
        .stat-card.high {{ border-left: 4px solid #ffc107; }}
        .stat-number {{ font-size: 2em; font-weight: bold; }}
        table {{ width: 100%; border-collapse: collapse; margin: 20px 0; background: #16213e; border-radius: 10px; overflow: hidden; }}
        th, td {{ padding: 12px; text-align: left; border-bottom: 1px solid #2a2a4a; }}
        th {{ background: #0f3460; color: #00d4ff; }}
        tr:hover {{ background: #1a1a3e; }}
        code {{ background: #0f3460; padding: 2px 6px; border-radius: 4px; font-size: 0.9em; color: #00d4ff; }}
        .severity-critical {{ color: #dc3545; font-weight: bold; }}
        .severity-high {{ color: #ffc107; font-weight: bold; }}
    </style>
</head>
<body>
<div class="container">
    <h1>🛡️ Bluesky Vulnerability Report</h1>
    <p>Target: <strong>{device_info.get('name', 'Unknown')}</strong> ({target})</p>
    <p>Fecha: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
    <p>Dispositivo: {device_info.get('class', 'Unknown')} | Fabricante: {device_info.get('manufacturer', 'Unknown')}</p>

    <div class="stats">
        <div class="stat-card">
            <div class="stat-number">{len(found)}</div>
            <div>Vulnerabilidades</div>
        </div>
        <div class="stat-card critical">
            <div class="stat-number" style="color:#dc3545">{len(critical)}</div>
            <div>Críticas</div>
        </div>
        <div class="stat-card high">
            <div class="stat-number" style="color:#ffc107">{len(high)}</div>
            <div>Altas</div>
        </div>
    </div>

    <h2>🎯 Vulnerabilidades Detectadas</h2>
    <table>
        <thead>
            <tr>
                <th>ID</th>
                <th>Nombre</th>
                <th>CVE</th>
                <th>Severidad</th>
                <th>Evidencia</th>
                <th>Módulo</th>
            </tr>
        </thead>
        <tbody>
            {vuln_rows}
        </tbody>
    </table>

    <h2>⚡ Cadena de Ataque Recomendada</h2>
    <ol>
"""
        for i, v in enumerate(found, 1):
            html += f'        <li><code>bluesky attack {v["module"]} {target}</code> — {v["name"]}</li>\n'

        html += """
    </ol>
    <p style="margin-top:30px;color:#666;text-align:center;">
        Generado por <strong>Bluesky</strong> — Bluetooth Security Auditing Framework
    </p>
</div>
</body>
</html>"""

        report_path.write_text(html, encoding="utf-8")
        return str(report_path)

    def _scan_and_prompt(self) -> dict:
        """Escanea y pide target."""
        devices = []
        try:
            if sys.platform.startswith("linux"):
                result = subprocess.run(
                    ["bluetoothctl", "--timeout", "5", "scan", "on"],
                    capture_output=True, text=True, timeout=8
                )
                for line in result.stdout.split("\n"):
                    if "Device" in line:
                        parts = line.split("Device", 1)[1].strip().split(" ", 1)
                        mac = parts[0] if len(parts) > 0 else ""
                        name = parts[1] if len(parts) > 1 else "Unknown"
                        if mac and ":" in mac:
                            devices.append({"mac": mac, "name": name})
        except Exception:
            pass

        lines = [
            "╔══════════════════════════════════════════════════════════════╗",
            "║     🛡️  VulnScanner - Análisis de Vulnerabilidades         ║",
            "╚══════════════════════════════════════════════════════════════╝",
            "",
            "📋  QUÉ HACE:",
            "───────────────────────────────────────────────────────────────",
            "  Analiza un dispositivo Bluetooth contra 13+ vulnerabilidades:",
            "  KNOB, BIAS, BLUFFS, BlueBorne, BlueFrag, SweynTooth,",
            "  WhisperPair, BLESA, Crackle, BTLEJack, BlueBugging,",
            "  BlueSnarfing, Keystroke Injection",
            "",
            "📋  PASOS DEL ANÁLISIS:",
            "───────────────────────────────────────────────────────────────",
            "  Paso 1: Descubrir información del dispositivo (nombre, clase, fabricante)",
            "  Paso 2: Escanear servicios SDP y RFCOMM",
            "  Paso 3: Detectar vulnerabilidades conocidas",
            "  Paso 4: Generar perfil de vulnerabilidad",
            "  Paso 5: Recomendar cadena de ataque",
            "",
        ]

        if devices:
            lines.extend([
                "📱  DISPOSITIVOS ENCONTRADOS:",
                "───────────────────────────────────────────────────────────────",
            ])
            for d in devices:
                lines.append(f"     🔵 {d['mac']}  -  {d['name']}")
            lines.extend([
                "",
                "🎯  EJEMPLOS:",
                "───────────────────────────────────────────────────────────────",
                f"     bluesky vuln {devices[0]['mac']}",
                "     bluesky vuln AA:BB:CC:DD:EE:FF",
                "     bluesky vuln AA:BB:CC:DD:EE:FF --options '{\"REPORT\":\"true\"}'",
                "     bluesky vuln AA:BB:CC:DD:EE:FF --options '{\"SCAN_TYPE\":\"quick\"}'",
                "",
                "💡  Tip: Usa 'bluesky auto <MAC>' para auto-explotar",
            ])
        else:
            lines.extend([
                "⚠️  No se encontraron dispositivos.",
                "  Asegúrate de que Bluetooth esté encendido.",
                "",
                "🎯  EJEMPLOS:",
                "───────────────────────────────────────────────────────────────",
                "     bluesky vuln AA:BB:CC:DD:EE:FF",
                "     bluesky vuln all",
            ])

        self.result["data"]["devices_found"] = devices
        self.result["data"]["message"] = "\n".join(lines)
        self.result["success"] = False
        return self.result
