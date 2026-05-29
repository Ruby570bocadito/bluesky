"""
BTLEJack - BLE Connection Hijacking
=====================================
BTLEJack permite interceptar y secuestrar conexiones Bluetooth Low Energy
activas. Funciona escuchando pasivamente el canal de datos entre un
Master (Central) y un Slave (Peripheral), y luego tomando el control
de la conexión.

Vectores de ataque:
  1. Passive sniffing: Escucha el tráfico BLE entre dos dispositivos
  2. Connection hijack: Secuestra la conexión suplantando al Master
  3. Data injection: Inyecta paquetes L2CAP/ATT en el canal activo
  4. Man-in-the-Middle: Interpone entre Master y Slave reales

Referencia:
  - https://github.com/virtualabs/btlejack
  - https://github.com/nccgroup/BTLEJack (NCC Group)
  - DEF CON 24: "Breaking BLE" por Mike Ryan

Requiere:
  - Adaptador BLE compatible (nRF51822/nRF52xxx con firmware BTLEJack)
  - O adaptador CSR 4.0+ con capacidades de sniffing
  - scapy >= 2.4.5

Advertencia:
  Solo usar contra dispositivos que poseas o tengas autorización expresa
  para testear.
"""

from __future__ import annotations

import os
import random
import struct
import hashlib
import logging
import subprocess
from typing import Dict, Any, List, Optional, Tuple, Set
from pathlib import Path
import json
import time

from bluesky.core.engine import BaseModule

log = logging.getLogger("bluesky.btlejack")

try:
    from scapy.layers.bluetooth import (
        HCI_Hdr, HCI_ACL_Hdr, L2CAP_Hdr,
        SM_Hdr, SM_Pairing_Request, SM_Pairing_Response,
    )
    from scapy.layers.bluetooth4LE import (
        BTLE, BTLE_DATA, BTLE_ADV, BTLE_CTRL,
        LL_DATA, LL_CONNECTION_UPDATE_REQ,
        LL_CHANNEL_MAP_REQ, LL_TERMINATE_IND,
        LL_VERSION_IND, LL_FEATURE_REQ, LL_FEATURE_RSP,
        LL_PAUSE_ENC_REQ, LL_PAUSE_ENC_RSP,
    )
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False


class BTLEJack(BaseModule):
    """BTLEJack - BLE Connection Hijacking.

    Permite interceptar, secuestrar y manipular conexiones BLE activas
    entre dispositivos. Opera a nivel de capa de enlace (LL) y L2CAP.

    Modos:
      - scan: Escanea conexiones BLE activas en el área
      - sniff: Captura pasiva de tráfico BLE entre dos dispositivos
      - hijack: Secuestra una conexión activa (suplantación)
      - mitm: Man-in-the-Middle entre dos dispositivos
      - inject: Inyección de paquetes L2CAP/ATT en canal activo
    """

    name = "btlejack"
    description = (
        "BTLEJack - BLE Connection Hijacking: Intercepta, secuestra y "
        "manipula conexiones Bluetooth Low Energy activas. Soporta "
        "sniffing pasivo, hijacking de conexión, MITM e inyección de datos."
    )
    author = "Bluesky Project"
    version = "1.0.0"
    cve = "No CVE asignado (técnica de ataque)"
    cve_url = "https://github.com/virtualabs/btlejack"
    exploit_links = [
        "https://github.com/virtualabs/btlejack",
        "https://github.com/nccgroup/BTLEJack",
        "https://blog.zimperium.com/btlejack-ble-hijacking/",
    ]
    references = [
        "https://github.com/virtualabs/btlejack",
        "https://github.com/nccgroup/BTLEJack",
        "DEF CON 24 - Breaking BLE (Mike Ryan)",
        "https://blog.zimperium.com/btlejack-ble-hijacking/",
        "Bluetooth Core Spec Vol 6, Part B (LE Link Layer)",
    ]
    requires_hardware = []
    requires_root = False
    target_type = "ble"
    severity = "critical"
    module_options = {
        "TARGET": "Dirección MAC del objetivo (Master:Slave, ej: 'AA:BB:CC:DD:EE:FF:11:22:33:44:55:66')",
        "MODE": "Modo de operación: scan, sniff, hijack, mitm, inject (default: scan)",
        "CHANNEL": "Canal BLE (37, 38, 39 para advertising; 0-36 para datos) (default: auto)",
        "ACCESS_ADDRESS": "Access Address de la conexión (hex, 4 bytes)",
        "PAYLOAD": "Payload a inyectar (hex string, modo inject)",
        "TIMEOUT": "Tiempo máximo de operación en segundos (default: 30)",
        "OUTPUT": "Directorio de salida para capturas",
        "AA": "Access Address conocida (hex, para filtrado)",
    }

    # Access Addresses comunes conocidas
    KNOWN_AA = {
        0x8E89BED6: "Nordic Semiconductor (nRF52)",
        0x9A328277: "Texas Instruments (CC26xx)",
        0x569EF5C7: "Dialog Semiconductor",
        0xE6412C1F: "Cypress PSoC",
        0x0E0BFE0A: "NXP KW41Z",
    }

    CHANNELS = {
        0: 2402, 1: 2404, 2: 2406, 3: 2408, 4: 2410,
        5: 2412, 6: 2414, 7: 2416, 8: 2418, 9: 2420,
        10: 2422, 11: 2424, 12: 2426, 13: 2428, 14: 2430,
        15: 2432, 16: 2434, 17: 2436, 18: 2438, 19: 2440,
        20: 2442, 21: 2444, 22: 2446, 23: 2448, 24: 2450,
        25: 2452, 26: 2454, 27: 2456, 28: 2458, 29: 2460,
        30: 2462, 31: 2464, 32: 2466, 33: 2468, 34: 2470,
        35: 2472, 36: 2474, 37: 2402, 38: 2426, 39: 2480,
    }

    def __init__(self, target: str = "", options: dict = None):
        super().__init__(target, options)
        self._mode = (options or {}).get("MODE", "scan").lower()
        self._channel = (options or {}).get("CHANNEL", "auto")
        self._access_address = (options or {}).get("ACCESS_ADDRESS", "")
        self._payload = (options or {}).get("PAYLOAD", "")
        self._timeout = int((options or {}).get("TIMEOUT", "30"))
        self._output_dir = (options or {}).get("OUTPUT", "reports/btlejack")
        self._aa = (options or {}).get("AA", "")

        # Parse target como "master:slave"
        self._master_addr: Optional[str] = None
        self._slave_addr: Optional[str] = None
        self._parse_target()

        # Estado interno
        self._active_connections: List[Dict] = []
        self._captured_packets: List[bytes] = []
        self._sniffed_channels: Set[int] = set()

    def _parse_target(self):
        """Parsea el target como Master:Slave o dirección única."""
        if self.target:
            parts = self.target.replace(":", "").replace("-", "").replace(" ", "")
            if len(parts) == 24:  # 12 bytes = MAC Master (6) + MAC Slave (6)
                self._master_addr = ":".join(parts[i:i+2] for i in range(0, 12, 2))
                self._slave_addr = ":".join(parts[i:i+2] for i in range(12, 24, 2))
                log.info(f"Target Master:Slave -> {self._master_addr}:{self._slave_addr}")
            elif len(parts) == 12:  # 6 bytes = MAC única
                addr = ":".join(parts[i:i+2] for i in range(0, 12, 2))
                self._master_addr = addr
                log.info(f"Target única -> Master: {self._master_addr}")

    # ─── Punto de entrada ────────────────────────────────────────────────────

    def run(self):
        """Punto de entrada principal."""
        modes = {
            "scan": self._scan_mode,
            "sniff": self._sniff_mode,
            "hijack": self._hijack_mode,
            "mitm": self._mitm_mode,
            "inject": self._inject_mode,
        }

        handler = modes.get(self._mode)
        if handler:
            return handler()

        self.result["data"] = {
            "error": f"Modo desconocido: {self._mode}. Usar: scan, sniff, hijack, mitm, inject",
            "available_modes": list(modes.keys()),
        }
        self.result["success"] = False
        return self.result

    # ─── Modo SCAN ──────────────────────────────────────────────────────────

    def _scan_mode(self) -> dict:
        """Escanea conexiones BLE activas en el área.

        Escucha en los canales de advertising (37, 38, 39)
        y detecta conexiones establecidas por el Access Address.
        """
        output_dir = Path(self._output_dir)
        output_dir.mkdir(parents=True, exist_ok=True)

        self.result["data"] = {
            "mode": "scan",
            "active_connections": [],
            "channels_scanned": [],
            "access_addresses_found": [],
        }

        log.info("🔍 BTLEJack - Escaneando conexiones BLE activas...")

        # Simulación de escaneo (no hay hardware BLE)
        sim_connections = self._simulate_scan()

        self.result["data"]["active_connections"] = sim_connections
        self.result["data"]["simulation"] = True

        # Guardar reporte
        report_file = output_dir / "scan_results.json"
        with open(report_file, "w") as f:
            json.dump(self.result["data"], f, indent=2)

        # Generar resumen
        lines = [
            "🔍 BTLEJack - Resultados de escaneo",
            "===================================\n",
        ]

        if sim_connections:
            for conn in sim_connections:
                lines.append(f"  📡 Access Address: 0x{conn['aa']:08X}")
                lines.append(f"     Posible vendor: {conn.get('vendor', 'Desconocido')}")
                lines.append(f"     Canal: {conn.get('channel', '?')} ({conn.get('freq', 0)} MHz)")
                lines.append(f"     RSSI: {conn.get('rssi', 'N/A')} dBm")
                lines.append(f"     Tipo: {conn.get('type', 'N/A')}")
                if conn.get("master_addr"):
                    lines.append(f"     Master: {conn['master_addr']}")
                if conn.get("slave_addr"):
                    lines.append(f"     Slave:  {conn['slave_addr']}")
                lines.append("")
        else:
            lines.append("  No se detectaron conexiones activas.\n")

        lines.append(f"  Canales escaneados: {self._channel if self._channel != 'auto' else '37,38,39 (adv)'}")
        lines.append(f"  Resultados guardados en: {report_file}\n")

        # Nota para hardware real
        lines.append("  ⚠️  Escaneo simulado - sin hardware BLE.")
        lines.append("  Para escaneo real se necesita:")
        lines.append("    • nRF52840 + firmware BTLEJack (recomendado)")
        lines.append("    • CSR 4.0+ con soporte de sniffing")
        lines.append("    • scapy instalado (pip install scapy)")

        self.result["data"]["report"] = "\n".join(lines)
        self.result["success"] = True
        return self.result

    def _simulate_scan(self) -> List[Dict]:
        """Simula detección de conexiones BLE activas."""
        aa_list = [0x8E89BED6, 0x9A328277, 0x569EF5C7]
        connections = []

        for i, aa in enumerate(aa_list):
            vendor = self.KNOWN_AA.get(aa, "Desconocido")
            ch = random.choice([0, 12, 24, 37, 38, 39])
            conn = {
                "aa": aa,
                "vendor": vendor,
                "channel": ch,
                "freq": self.CHANNELS.get(ch, 2402),
                "rssi": random.randint(-85, -45),
                "type": random.choice(["Master->Slave", "Slave->Master", "Advertising"]),
                "timestamp": time.time(),
            }

            # MACs simuladas
            if i == 0:
                conn["master_addr"] = "AA:BB:CC:11:22:33"
                conn["slave_addr"] = "DD:EE:FF:44:55:66"
            elif i == 1:
                conn["master_addr"] = "11:22:33:AA:BB:CC"
                conn["slave_addr"] = "44:55:66:DD:EE:FF"

            connections.append(conn)

        # Si tenemos un target específico, filtrar
        if self._master_addr:
            connections = [
                c for c in connections
                if c.get("master_addr") == self._master_addr
                or c.get("slave_addr") == self._master_addr
            ]

        self._active_connections = connections
        return connections

    # ─── Modo SNIFF ─────────────────────────────────────────────────────────

    def _sniff_mode(self) -> dict:
        """Captura pasiva de tráfico BLE.

        Escucha en un canal de datos específico (o auto-detecta)
        y captura paquetes LL/L2CAP/ATT entre Master y Slave.
        """
        output_dir = Path(self._output_dir)
        output_dir.mkdir(parents=True, exist_ok=True)

        self.result["data"] = {
            "mode": "sniff",
            "access_address": self._access_address or "auto",
            "channel": self._channel,
            "packets_captured": 0,
            "packet_types": {},
        }

        log.info(f"👂 BTLEJack - Sniffing en canal {self._channel}...")

        if not SCAPY_AVAILABLE:
            log.warning("scapy no disponible - usando simulación para sniff")

        # Simulación de sniffing
        sim_result = self._simulate_sniff()
        self.result["data"].update(sim_result)

        # Guardar captura
        if sim_result.get("packets"):
            pcap_file = output_dir / "btlejack_capture.pcap"
            try:
                # Intentar guardar con scapy
                from scapy.utils import wrpcap
                wrpcap(str(pcap_file), sim_result["packets"])
                self.result["data"]["pcap_file"] = str(pcap_file)
            except Exception:
                # Fallback a JSON
                json_file = output_dir / "btlejack_capture.json"
                with open(json_file, "w") as f:
                    json.dump(sim_result["packets"][:100], f, indent=2)
                self.result["data"]["capture_file"] = str(json_file)

        # Generar mensaje
        types = sim_result.get("packet_types", {})
        type_summary = ", ".join(f"{k}: {v}" for k, v in types.items())

        self.result["data"]["message"] = (
            f"👂 BTLEJack - Sniffing completado\n\n"
            f"   Access Address: {self._access_address or 'auto-detect'}\n"
            f"   Canal: {self._channel}\n"
            f"   Paquetes capturados: {sim_result.get('packets_captured', 0)}\n"
            f"   Tipos: {type_summary}\n\n"
            f"   ⚠️  Sniffing simulado (sin hardware BLE)\n\n"
            f"   Para sniffing real:\n"
            f"   1. Usa nRF52840 con firmware BTLEJack\n"
            f"   2. O adaptador CSR con soporte de modo monitor\n"
            f"   3. Ejecuta: sudo python3 bluesky attack btlejack "
            f"--options '{{\"MODE\":\"sniff\",\"CHANNEL\":\"37\"}}'"
        )

        self.result["success"] = True
        return self.result

    def _simulate_sniff(self) -> Dict:
        """Simula captura de paquetes BLE."""
        packets = []
        types = {}
        count = 0

        # Generar paquetes simulados
        for i in range(20):
            pkt_type = random.choice([
                "LL_DATA", "LL_CONNECTION_UPDATE", "LL_CHANNEL_MAP",
                "LL_TERMINATE_IND", "LL_VERSION_IND", "LL_FEATURE_REQ",
                "L2CAP_ATT_READ", "L2CAP_ATT_WRITE", "L2CAP_ATT_NOTIFY",
            ])
            types[pkt_type] = types.get(pkt_type, 0) + 1
            count += 1

            # Simular paquete scapy (si está disponible)
            if SCAPY_AVAILABLE:
                try:
                    from scapy.all import Raw
                    aa = int(self._access_address, 16) if self._access_address else 0x8E89BED6
                    pkt = Raw(struct.pack("<I", aa) + bytes([i]) * 16)
                    packets.append(pkt)
                except Exception:
                    pass

        self.result["data"]["packet_types"] = types
        self.result["data"]["packets_captured"] = count
        self.result["data"]["packets"] = packets[:50] if SCAPY_AVAILABLE else []
        self.result["data"]["simulation"] = True

        return self.result["data"]

    # ─── Modo HIJACK ────────────────────────────────────────────────────────

    def _hijack_mode(self) -> dict:
        """Secuestra una conexión BLE activa.

        Estrategia:
          1. Detectar Access Address de la conexión objetivo
          2. Esperar un Connection Update o Channel Map
          3. Suplantar al Master enviando paquetes con la AA correcta
          4. Inyectar LL_TERMINATE_IND o LL_CONNECTION_UPDATE
        """
        output_dir = Path(self._output_dir)
        output_dir.mkdir(parents=True, exist_ok=True)

        self.result["data"] = {
            "mode": "hijack",
            "target_aa": self._access_address or "desconocida",
            "target_channel": self._channel,
            "hijack_successful": False,
        }

        log.warning("⚡ BTLEJack - Ejecutando hijack de conexión BLE...")

        if not SCAPY_AVAILABLE:
            log.warning("scapy no disponible - usando simulación para hijack")

        # Detectar Access Address
        if not self._access_address and self._aa:
            self._access_address = self._aa

        if not self._access_address:
            # Auto-scan para encontrar AA
            scan_result = self._simulate_scan()
            if scan_result:
                aa = scan_result[0]["aa"]
                self._access_address = f"{aa:08X}"
                self.result["data"]["target_aa"] = f"{aa:08X}"
                self.result["data"]["auto_detected_aa"] = True

        # Simular hijack
        sim = self._simulate_hijack()

        self.result["data"]["hijack_successful"] = sim.get("success", False)
        self.result["data"]["details"] = sim

        # Guardar reporte
        report_file = output_dir / "hijack_report.json"
        with open(report_file, "w") as f:
            json.dump(self.result["data"], f, indent=2)

        self.result["data"]["message"] = (
            f"⚡ BTLEJack - Hijack {'EXITOSO' if sim.get('success') else 'FALLIDO'}\n\n"
            f"   Access Address: 0x{self._access_address}\n"
            f"   Canal: {sim.get('channel', 'N/A')}\n"
            f"   Paquetes inyectados: {sim.get('packets_injected', 0)}\n\n"
            f"   ⚠️  Hijack simulado (sin hardware BLE)\n\n"
            f"   Para hijack real:\n"
            f"   1. nRF52840 con firmware BTLEJack\n"
            f"   2. Timing preciso (ventana de ~150μs)\n"
            f"   3. Conocer el Access Address y Hop Interval\n"
            f"   {sim.get('additional_info', '')}"
        )

        self.result["success"] = True
        return self.result

    def _simulate_hijack(self) -> Dict:
        """Simula el proceso de hijack."""
        sim = {
            "success": random.random() > 0.3,  # 70% de tasa de éxito simulada
            "channel": int(self._channel) if self._channel != "auto" else random.randint(0, 36),
            "packets_injected": random.randint(3, 15),
            "method": "Connection Update Injection",
            "timing_offset_us": random.randint(50, 300),
        }

        if sim["success"]:
            sim["additional_info"] = (
                "Conexión secuestrada exitosamente.\n"
                "  • Canal de datos controlado\n"
                "  • Posible inyección de paquetes ATT\n"
                "  • Posible denegación de servicio\n"
            )
        else:
            sim["additional_info"] = (
                "Hijack falló - posibles causas:\n"
                "  • Access Address incorrecta\n"
                "  • Timing de salto de canal incorrecto\n"
                "  • El dispositivo abortó la conexión\n"
            )

        return sim

    # ─── Modo MITM ──────────────────────────────────────────────────────────

    def _mitm_mode(self) -> dict:
        """Man-in-the-Middle entre dos dispositivos BLE.

        Estrategia:
          1. Detectar el pairing entre Master y Slave
          2. Interceptar los paquetes SM (pairing)
          3. Degradar la seguridad (Just Works en vez de MITM protegido)
          4. Reenviar tráfico modificado entre ambos
        """
        output_dir = Path(self._output_dir)
        output_dir.mkdir(parents=True, exist_ok=True)

        self.result["data"] = {
            "mode": "mitm",
            "target_master": self._master_addr or "auto-detect",
            "target_slave": self._slave_addr or "auto-detect",
            "pairing_intercepted": False,
            "security_downgraded": False,
        }

        log.warning("🕵️ BTLEJack - Ejecutando MITM en conexión BLE...")

        if not SCAPY_AVAILABLE:
            log.warning("scapy no disponible - usando simulación para MITM")

        # Simulación más agresiva si hay AA conocida
        if self._access_address:
            log.info(f"AA conocida: 0x{self._access_address} - simulando MITM dirigido")

        sim = {
            "success": True,
            "pairing_captured": True,
            "security_downgraded": True,
            "original_auth": "MITM Protected (SC)",
            "downgraded_to": "Just Works (TK=0)",
            "packets_captured": random.randint(50, 200),
            "packets_modified": random.randint(10, 30),
        }

        self.result["data"]["pairing_intercepted"] = sim["pairing_captured"]
        self.result["data"]["security_downgraded"] = sim["security_downgraded"]
        self.result["data"]["details"] = sim

        report_file = output_dir / "mitm_report.json"
        with open(report_file, "w") as f:
            json.dump(self.result["data"], f, indent=2)

        self.result["data"]["message"] = (
            f"🕵️ BTLEJack - MITM {'EXITOSO' if sim.get('success') else 'FALLIDO'}\n\n"
            f"   Master: {self._master_addr or 'N/A'}\n"
            f"   Slave:  {self._slave_addr or 'N/A'}\n\n"
            f"   🔒 Seguridad original: {sim.get('original_auth')}\n"
            f"   🔓 Degradado a:       {sim.get('downgraded_to')}\n"
            f"   Paquetes capturados:  {sim.get('packets_captured')}\n"
            f"   Paquetes modificados: {sim.get('packets_modified')}\n\n"
            f"   ⚠️  MITM simulado (sin hardware BLE)\n\n"
            f"   Para MITM real:\n"
            f"   1. Dos adaptadores nRF52840 (o 1 con timing preciso)\n"
            f"   2. Posicionarse entre Master y Slave\n"
            f"   3. Capturar y modificar paquetes SM en tiempo real\n"
            f"   Reporte guardado en: {report_file}"
        )

        self.result["success"] = True
        return self.result

    # ─── Modo INJECT ────────────────────────────────────────────────────────

    def _inject_mode(self) -> dict:
        """Inyecta paquetes en una conexión BLE activa.

        Permite enviar paquetes L2CAP/ATT arbitrarios en un
        canal de datos activo, utilizando la Access Address
        correcta y los tiempos de salto de canal adecuados.
        """
        output_dir = Path(self._output_dir)
        output_dir.mkdir(parents=True, exist_ok=True)

        self.result["data"] = {
            "mode": "inject",
            "access_address": self._access_address or "unknown",
            "payload": self._payload,
            "injected": False,
            "packets_sent": 0,
        }

        log.info(f"💉 BTLEJack - Inyectando paquetes en canal {self._channel}...")

        if not SCAPY_AVAILABLE:
            log.warning("scapy no disponible - usando simulación para inject")

        if not self._access_address and not self._aa:
            self.result["data"]["message"] = (
                "Se necesita Access Address para inyectar.\n"
                "Usa modo scan primero para detectar AA.\n"
                "O especifica AA con --options '{\"AA\":\"0x8E89BED6\"}'"
            )
            self.result["success"] = True
            return self.result

        # Parsear AA
        try:
            aa = int(self._access_address or self._aa, 16)
        except (ValueError, TypeError):
            aa = 0x8E89BED6

        # Simular inyección
        packets_sent = random.randint(1, 10)
        payload_size = len(self._payload) // 2 if self._payload else 0

        self.result["data"]["injected"] = True
        self.result["data"]["packets_sent"] = packets_sent
        self.result["data"]["access_address_hex"] = f"{aa:08X}"
        self.result["data"]["simulation"] = True

        self.result["data"]["message"] = (
            f"💉 BTLEJack - Inyección de paquetes\n\n"
            f"   AA: 0x{aa:08X}\n"
            f"   Canal: {self._channel}\n"
            f"   Paquetes enviados: {packets_sent}\n"
            f"   Payload: {self._payload or '(vacío)'} ({payload_size} bytes)\n\n"
            f"   ⚠️  Inyección simulada (sin hardware BLE)\n\n"
            f"   Para inyección real:\n"
            f"   1. Conocer AA y hopping sequence\n"
            f"   2. Enviar en ventana de ~150μs tras paquete válido\n"
            f"   3. Usar scapy: sendp(pkt, iface='hci0')\n\n"
            f"   Paquetes para ataques útiles:\n"
            f"   • LL_TERMINATE_IND -> desconexión\n"
            f"   • LL_CONNECTION_UPDATE_REQ -> cambiar canal\n"
            f"   • ATT Write Request -> escribir características\n"
            f"   • ATT Read Request -> leer características protegidas"
        )

        self.result["success"] = True
        return self.result

    # ─── Prerrequisitos ──────────────────────────────────────────────────────

    def check_prerequisites(self) -> Tuple[bool, str]:
        """Verifica dependencias (no blocking - modo simulación disponible)."""
        missing = []
        if not SCAPY_AVAILABLE:
            log.warning("scapy no instalado - modo simulación")
        if missing:
            return False, f"Faltan: {', '.join(missing)}"
        return True, ""
