"""
Session - Gestión de sesiones de auditoría Bluetooth.
Permite guardar/cargar el estado de una auditoría.
"""

import json
import time
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional


class Session:
    """Gestiona una sesión de auditoría Bluetooth."""

    def __init__(self, name: str = "default", base_dir: str = None):
        self.name = name
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
        self.session_file = self.base_dir / f"{name}.json"

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

        # Evitar duplicados por MAC
        for i, t in enumerate(self.targets):
            if t["mac"] == mac:
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
        """Carga una sesión desde disco."""
        if name:
            self.name = name
            self.session_file = self.base_dir / f"{name}.json"

        if not self.session_file.exists():
            return False

        data = json.loads(self.session_file.read_text())
        self.name = data.get("name", self.name)
        self.created_at = data.get("created_at", self.created_at)
        self.updated_at = data.get("updated_at", self.updated_at)
        self.targets = data.get("targets", [])
        self.results = data.get("results", [])
        self.notes = data.get("notes", "")
        self.config = data.get("config", {})
        return True

    def summary(self) -> dict:
        """Retorna un resumen de la sesión."""
        return {
            "name": self.name,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "total_targets": len(self.targets),
            "total_results": len(self.results),
            "successful_attacks": sum(1 for r in self.results if r.get("success")),
            "failed_attacks": sum(1 for r in self.results if not r.get("success")),
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
