"""
Session - Gestión de sesiones de auditoría Bluetooth.
Permite guardar/cargar el estado de una auditoría.
"""

import json
import re
from datetime import datetime
from pathlib import Path
from typing import List


# Patrón seguro para nombres de sesión: solo alfanuméricos, guion, guion bajo y punto.
# Sin barras, sin "..", sin caracteres nulos. Evita path traversal y nombres hostiles.
_SAFE_SESSION_NAME = re.compile(r"^[A-Za-z0-9._-]+$")


def _sanitize_session_name(name: str) -> str:
    """Valida y normaliza un nombre de sesión.

    Bloquea path traversal (../), separadores de ruta (/, \\), bytes nulos y
    cualquier carácter no whitelisted. Si el nombre no es seguro, lo sustituye
    por uno seguro derivado del original (sustituyendo caracteres inválidos).

    Args:
        name: Nombre crudo proporcionado por el usuario/CLI.

    Returns:
        Nombre seguro listo para usarse como nombre de archivo.
    """
    if not isinstance(name, str):
        return "default"
    # Quitar bytes nulos siempre (defensa en profundidad aunque el regex ya los peta)
    name = name.replace("\x00", "")
    # Rechazar explícitamente cualquier separador de ruta o intento de traversal
    if "/" in name or "\\" in name or ".." in name or name in ("", ".", ".."):
        # Sustituir caracteres no whitelisted por '_' en lugar de fallar,
        # para no romper la UX con sesiones nombradas por el usuario con espacios
        # u otros caracteres legítimos pero no whitelisted.
        safe = re.sub(r"[^A-Za-z0-9._-]", "_", name).strip("._")
        return safe or "default"
    # Cumple el whitelist
    if _SAFE_SESSION_NAME.match(name):
        return name
    # Fallback: sustituir cualquier cosa no whitelisted
    safe = re.sub(r"[^A-Za-z0-9._-]", "_", name).strip("._")
    return safe or "default"


class Session:
    """Gestiona una sesión de auditoría Bluetooth."""

    def __init__(self, name: str = "default", base_dir: str = None):
        # El nombre se sanea ANTES de construir el path: sin esto, un
        # name='../../../tmp/evil' permitiría escribir JSON fuera del
        # directorio de sesiones (path traversal).
        self.name = _sanitize_session_name(name)
        self.created_at = datetime.now().isoformat()
        self.updated_at = self.created_at
        self.targets: List[dict] = []
        self.results: List[dict] = []
        self.notes: str = ""
        self.config: dict = {}

        if base_dir:
            self.base_dir = Path(base_dir)
        else:
            self.base_dir = Path.home() / ".bluesky" / "sessions"

        self.base_dir.mkdir(parents=True, exist_ok=True)
        # La ruta del archivo se construye solo con self.name ya saneado.
        self.session_file = self.base_dir / f"{self.name}.json"

    def add_target(self, mac: str, name: str = "", rssi: int = 0, **extra):
        """Agrega un objetivo a la sesión."""
        target = {
            "mac": mac,
            "name": name,
            "rssi": rssi,
            "first_seen": datetime.now().isoformat(),
            "last_seen": datetime.now().isoformat(),
            "services": [],
            "vulnerabilities": [],
            **extra,
        }

        # Evitar duplicados por MAC (tolerando targets malformados de un JSON cargado)
        for i, t in enumerate(self.targets):
            if isinstance(t, dict) and t.get("mac") == mac:
                self.targets[i]["last_seen"] = datetime.now().isoformat()
                self.targets[i]["rssi"] = rssi
                return self.targets[i]

        self.targets.append(target)
        return target

    def add_result(self, module: str, target: str, success: bool, data: dict = None, error: str = None):
        """Agrega el resultado de un ataque/escaneo."""
        result = {
            "module": module,
            "target": target,
            "timestamp": datetime.now().isoformat(),
            "success": success,
            "data": data or {},
            "error": error,
        }
        self.results.append(result)
        self.updated_at = datetime.now().isoformat()
        self._save()
        return result

    def save(self):
        """Guarda la sesión a disco (API pública).

        Los callers externos (CLI, consola) deben usar ``save()``;
        ``_save()`` se conserva como alias interno por compatibilidad.
        """
        self._save()

    def _save(self):
        """Guarda la sesión a disco."""
        data = {
            "name": self.name,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "targets": self.targets,
            "results": self.results,
            "notes": self.notes,
            "config": self.config,
        }
        self.session_file.write_text(json.dumps(data, indent=2, default=str))

    def load(self, name: str = None) -> bool:
        """Carga una sesión desde disco.

        Returns:
            True si se cargó, False si no existe o está corrupta
            (una sesión corrupta no debe crashear la consola al arrancar).
        """
        if name:
            # Saneamiento defensivo también al cargar: aunque __init__ ya
            # sanea, este método puede recibir un name nuevo.
            self.name = _sanitize_session_name(name)
            self.session_file = self.base_dir / f"{self.name}.json"
        # Defensa en profundidad: aunque el nombre esté saneado, comprobar
        # que la ruta resuelta sigue dentro de base_dir antes de leer.
        try:
            resolved = self.session_file.resolve()
            base_resolved = self.base_dir.resolve()
            if base_resolved not in resolved.parents and resolved != base_resolved:
                return False
        except (OSError, RuntimeError):
            return False

        if not self.session_file.exists():
            return False

        try:
            data = json.loads(self.session_file.read_text())
        except (json.JSONDecodeError, OSError):
            # Fichero corrupto/ilegible: conservar el estado en memoria y
            # reportar "no cargada" en lugar de lanzar una excepción.
            return False
        if not isinstance(data, dict):
            return False
        self.name = data.get("name", self.name)
        self.created_at = data.get("created_at", self.created_at)
        self.updated_at = data.get("updated_at", self.updated_at)
        self.targets = data.get("targets", []) if isinstance(data.get("targets"), list) else []
        self.results = data.get("results", []) if isinstance(data.get("results"), list) else []
        self.notes = data.get("notes", "")
        self.config = data.get("config", {}) if isinstance(data.get("config"), dict) else {}
        return True

    def summary(self) -> dict:
        """Retorna un resumen de la sesión."""
        return {
            "name": self.name,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "total_targets": len(self.targets),
            "total_results": len(self.results),
            "successful_attacks": sum(
                1 for r in self.results if isinstance(r, dict) and r.get("success")
            ),
            "failed_attacks": sum(
                1 for r in self.results if isinstance(r, dict) and not r.get("success")
            ),
            "targets": self.targets,
        }

    @staticmethod
    def list_sessions(base_dir: str = None) -> List[str]:
        """Lista todas las sesiones guardadas."""
        if base_dir:
            path = Path(base_dir)
        else:
            path = Path.home() / ".bluesky" / "sessions"

        if not path.exists():
            return []

        return [f.stem for f in path.glob("*.json")]
