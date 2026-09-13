#!/usr/bin/env python3
"""
bluesky Plugin: oui_lookup
Consulta del fabricante (OUI) de una MAC usando la base offline de bluesky.
Plugin de ejemplo del sistema de extensión con funcionalidad 100% real:
usa la base OUI compartida (bluesky/utils/oui.py), sin hardware ni
datos fabricados.
"""

from typing import Dict, Any

from bluesky.utils.oui import lookup_vendor, normalize_mac

PLUGIN_INFO = {
    "name": "oui_lookup",
    "version": "1.0.0",
    "description": "Consulta de fabricante (OUI) por MAC — base offline real",
    "author": "Ruby570bocadito",
    "type": "scanner",
    "module": "OuiLookup",
    "requires": [],
}


class OuiLookup:
    """Consulta de fabricante por dirección MAC (base OUI offline real)."""

    def __init__(self):
        self.name = "oui_lookup"
        self.description = "Consulta de fabricante (OUI) por MAC"
        self._target = ""

    def set_target(self, target: str):
        """Fija el target (usado por el engine al instanciar el plugin)."""
        self._target = target or ""

    def run(self, target: str = "", options: Dict[str, Any] = None) -> Dict[str, Any]:
        """Consulta el fabricante de la MAC indicada en TARGET.

        Args:
            target: Dirección MAC a consultar (formatos : - . aceptados).
            options: Opciones adicionales (no requeridas).

        Returns:
            Dict con resultado {success, data, error}.
        """
        options = options or {}
        mac = target or self._target or str(options.get("TARGET", "")).strip()

        if not mac:
            return {
                "success": False,
                "data": {},
                "error": "oui_lookup requiere una MAC (TARGET)",
            }

        normalized = normalize_mac(mac)
        if not normalized:
            return {
                "success": False,
                "data": {"input": mac},
                "error": f"MAC no válida: {mac!r}",
            }

        vendor = lookup_vendor(normalized)
        known = bool(vendor)

        return {
            "success": True,
            "data": {
                "message": (
                    f"{normalized} → "
                    f"{vendor if known else 'Fabricante desconocido (OUI no en la base)'}"
                ),
                "mac": normalized,
                "vendor": vendor,
                "known_oui": known,
            },
            "error": None,
        }

    def get_info(self) -> Dict[str, Any]:
        """Información del plugin."""
        return {
            "name": self.name,
            "description": self.description,
            "version": "1.0.0",
            "author": "Ruby570bocadito",
            "type": "scanner",
        }
