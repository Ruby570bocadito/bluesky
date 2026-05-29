"""
Service Scanner - Enumeración de servicios SDP en dispositivos Bluetooth Classic.
"""

import subprocess
import re
from typing import Optional

from bluesky.core.engine import BaseModule


class ServiceScanner(BaseModule):
    """Escáner de servicios Bluetooth - Enumera servicios SDP de dispositivos Classic."""

    name = "services"
    description = "Enumera servicios SDP (perfiles) disponibles en dispositivos Bluetooth Classic"
    author = "Bluesky Project"
    version = "0.1.0"
    cve = ""
    requires_hardware = []
    requires_root = False
    target_type = "classic"
    severity = "low"

    # Mapa de UUIDs de servicios Bluetooth conocidos
    KNOWN_SERVICES = {
        "0x1101": "Serial Port (SPP)",
        "0x1102": "LAN Access (LAP)",
        "0x1103": "Dial-up Networking (DUN)",
        "0x1104": "IrMC Sync",
        "0x1105": "OBEX Object Push (OPP)",
        "0x1106": "OBEX File Transfer (FTP)",
        "0x1107": "IrMC Sync Command",
        "0x1108": "Headset (HSP)",
        "0x1109": "Cordless Telephony",
        "0x110A": "Audio Source (A2DP)",
        "0x110B": "Audio Sink (A2DP)",
        "0x110C": "AV Remote Control (AVRCP)",
        "0x110D": "AV Remote Control Controller",
        "0x110E": "Video Source",
        "0x110F": "Video Sink",
        "0x1110": "Video Distribution",
        "0x1111": "Handsfree (HFP)",
        "0x1112": "Intercom",
        "0x1113": "Fax",
        "0x1114": "Headset Audio Gateway (AG)",
        "0x1115": "WAP",
        "0x1116": "WAP Client",
        "0x1117": "PAN (PANU)",
        "0x1118": "NAP",
        "0x1119": "GN",
        "0x111A": "Direct Print (BPP)",
        "0x111B": "Reference Print",
        "0x111C": "Basic Imaging (BIP)",
        "0x111D": "Imaging Responder",
        "0x111E": "Imaging Automatic Archive",
        "0x111F": "Imaging Reference Objects",
        "0x1120": "Handsfree Audio Gateway",
        "0x1121": "Personal Area Networking",
        "0x1122": "SIM Access (SAP)",
        "0x1123": "Phonebook Access (PBAP) PCE",
        "0x1124": "Phonebook Access (PBAP) PSE",
        "0x1125": "Phonebook Access (PBAP)",
        "0x1126": "Message Access (MAP) MSE",
        "0x1127": "Message Access (MAP) MCE",
        "0x1128": "HID Host",
        "0x1129": "HID Device",
        "0x112A": "HID Keyboard",
        "0x112B": "HID Pointing",
        "0x112C": "HID Combo",
        "0x112D": "HID Interrupt",
        "0x1130": "GNSS (GPS)",
        "0x1203": "Generic Audio",
        "0x1204": "Generic Telephony",
    }

    def run(self):
        """Ejecuta escaneo de servicios."""
        target = self.target

        if not target:
            self.result["error"] = "Se requiere una dirección MAC"
            return self.result

        self.result["data"]["target"] = target

        services = []
        raw_output = ""

        try:
            result = subprocess.run(
                ["sdptool", "browse", target],
                capture_output=True, text=True, timeout=20
            )
            raw_output = result.stdout

            if result.returncode == 0 and result.stdout.strip():
                current = {}
                for line in result.stdout.split("\n"):
                    if "Service Name" in line:
                        if current:
                            services.append(current)
                        current = {"name": line.split(":", 1)[-1].strip()}
                    elif "Service RecHandle" in line and current:
                        current["handle"] = line.split(":", 1)[-1].strip()
                    elif "Service Class" in line and current:
                        current["class"] = line.split(":", 1)[-1].strip()
                    elif "Protocol" in line and current:
                        proto_match = re.search(r'Protocol\s*(?:Descriptor\s*)?:\s*(.+)', line)
                        if proto_match:
                            current["protocol"] = proto_match.group(1).strip()
                    elif "Channel" in line and current:
                        ch_match = re.search(r'Channel\s*:\s*(\d+)', line)
                        if ch_match:
                            current["channel"] = int(ch_match.group(1))
                    elif "Language" in line and current:
                        pass  # Metadata, skip

                if current:
                    services.append(current)

                # Clasificar servicios
                for svc in services:
                    svc["type"] = self._classify_service(svc.get("name", ""))

                    # Marcar servicios de alto riesgo
                    high_risk = ["PBAP", "MAP", "OPP", "FTP", "SPP", "SAP"]
                    svc["risk"] = "high" if any(r in svc.get("name", "").upper() for r in high_risk) else "low"

        except (FileNotFoundError, subprocess.TimeoutExpired) as e:
            self.result["error"] = f"Error escaneando servicios: {e}"
            return self.result

        self.result["data"]["services"] = services
        self.result["data"]["total"] = len(services)
        self.result["data"]["raw_output"] = raw_output[:500] if raw_output else ""

        if services:
            self.result["success"] = True
            # Resumen de riesgos
            high_risk_services = [s for s in services if s.get("risk") == "high"]
            self.result["data"]["high_risk_services"] = high_risk_services
            self.result["data"]["risk_summary"] = (
                f"Se encontraron {len(services)} servicios.\n"
                f"{len(high_risk_services)} de alto riesgo: "
                f"{', '.join(s['name'] for s in high_risk_services)}"
            )
        else:
            self.result["data"]["message"] = "No se encontraron servicios SDP"

        return self.result

    def _classify_service(self, name: str) -> str:
        """Clasifica un servicio por su función."""
        name_upper = name.upper()
        if any(t in name_upper for t in ["AUDIO", "HEADSET", "HANDSFREE", "A2DP", "HSP", "HFP"]):
            return "audio"
        elif any(t in name_upper for t in ["PHONEBOOK", "PBAP", "CONTACT"]):
            return "contacts"
        elif any(t in name_upper for t in ["MESSAGE", "MAP", "SMS"]):
            return "messages"
        elif any(t in name_upper for t in ["FILE", "FTP", "OPP", "OBEX", "TRANSFER"]):
            return "file_transfer"
        elif any(t in name_upper for t in ["SERIAL", "SPP", "RFCOMM", "PORT"]):
            return "serial"
        elif any(t in name_upper for t in ["KEYBOARD", "HID", "MOUSE", "INPUT"]):
            return "hid"
        elif any(t in name_upper for t in ["NETWORK", "PAN", "NAP", "LAN"]):
            return "network"
        elif any(t in name_upper for t in ["SIM", "SAP"]):
            return "sim_access"
        elif any(t in name_upper for t in ["GPS", "GNSS", "LOCATION"]):
            return "location"
        elif any(t in name_upper for t in ["PRINT"]):
            return "printing"
        return "other"
