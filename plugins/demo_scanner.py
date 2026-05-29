#!/usr/bin/env python3
"""
Bluesky Plugin: demo_scanner
Escáner Bluetooth de demostración - descubre dispositivos simulados.
"""

from typing import Dict, Any, List, Optional

PLUGIN_INFO = {
    "name": "demo_scanner",
    "version": "1.0.0",
    "description": "Escáner Bluetooth de demostración (simulado)",
    "author": "Bluesky Team",
    "type": "scanner",
    "module": "DemoScanner",
    "requires": [],
}


class DemoScanner:
    """Plugin de escáner de demostración."""

    def __init__(self):
        self.name = "demo_scanner"
        self.description = "Escáner Bluetooth de demostración"

    def run(self, target: str = "", options: Dict[str, Any] = None) -> Dict[str, Any]:
        """Ejecuta escaneo simulado.

        Args:
            target: Dirección MAC o UUID del target.
            options: Opciones adicionales.

        Returns:
            Dict con resultado del escaneo.
        """
        options = options or {}
        timeout = int(options.get("timeout", 3))

        return {
            "success": True,
            "data": {
                "message": f"Demo scanner ejecutado (timeout={timeout}s)",
                "devices": [
                    {
                        "name": "Demo Device 1",
                        "mac": "AA:BB:CC:DD:EE:01",
                        "type": "classic",
                        "rssi": -45,
                    },
                    {
                        "name": "Demo Device 2",
                        "mac": "AA:BB:CC:DD:EE:02",
                        "type": "ble",
                        "rssi": -60,
                    },
                ],
                "target": target,
            }
        }

    def get_info(self) -> Dict[str, Any]:
        """Información del plugin."""
        return {
            "name": self.name,
            "description": self.description,
            "version": "1.0.0",
            "author": "Bluesky Team",
            "type": "scanner",
        }
