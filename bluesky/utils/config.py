#!/usr/bin/env python3
"""
Bluesky Configuration Manager
==============================
Gestiona la configuración persistente del proyecto en formato JSON.
Soporta XDG Base Directory, múltiples rutas de búsqueda, validación
de esquema y persistencia desde la REPL.

Rutas de búsqueda (por orden de precedencia):
  1. `--config` CLI flag
  2. `./bluesky.json` (directorio actual)
  3. `~/.config/bluesky/bluesky.json` (XDG)
  4. `~/.bluesky.json` (home)
  5. Defaults internos
"""

from __future__ import annotations

import json
import os
import copy
from pathlib import Path
from typing import Any, Dict, List, Optional

# ─── Schema / defaults ───────────────────────────────────────────────────────

DEFAULT_CONFIG: Dict[str, Any] = {
    # Preferencias generales
    "general": {
        "theme": "auto",              # "auto" | "dark" | "light"
        "log_level": "info",          # "debug" | "info" | "warning" | "error"
        "report_format": "html",      # "html" | "json" | "txt"
        "safe_mode": True,            # False permite acciones destructivas
        "timeout": 30,                # Timeout por defecto (segundos)
        "max_devices": 50,            # Máx dispositivos a escanear
        "language": "es",             # "es" | "en"
    },

    # Target por defecto
    "default_target": {
        "address": "",                # MAC o UUID
        "name": "",
        "type": "auto",               # "auto" | "classic" | "ble"
    },

    # Targets favoritos (acceso rápido)
    "favorites": [
        # { "address": "XX:XX:XX:XX:XX:XX", "name": "MiBT", "type": "classic" }
    ],

    # Override de opciones por módulo (usado por `set` en console)
    "module_options": {
        # "knob": { "timeout": 60, "force": True }
    },

    # Historial de sesiones
    "session": {
        "autosave": True,
        "last_session": "",
        "history_size": 100,
    },

    # Scanners
    "scanner": {
        "active_scan": False,          # BLE active scan
        "classic_inquiry": True,       # Classic inquiry scan
        "scan_duration": 10,           # segundos
    },

    # Reporter
    "reporter": {
        "auto_generate": True,
        "include_remediation": True,
        "include_evidence": True,
    },
}

CONFIG_SCHEMA: Dict[str, type] = {
    "general.theme": str,
    "general.log_level": str,
    "general.report_format": str,
    "general.safe_mode": bool,
    "general.timeout": (int, float),
    "general.max_devices": int,
    "general.language": str,
    "default_target.address": str,
    "default_target.name": str,
    "default_target.type": str,
    "favorites": list,
    "module_options": dict,
    "session.autosave": bool,
    "session.last_session": str,
    "session.history_size": int,
    "scanner.active_scan": bool,
    "scanner.classic_inquiry": bool,
    "scanner.scan_duration": int,
    "reporter.auto_generate": bool,
    "reporter.include_remediation": bool,
    "reporter.include_evidence": bool,
}

VALID_LOG_LEVELS = {"debug", "info", "warning", "error"}
VALID_THEMES = {"auto", "dark", "light"}
VALID_FORMATS = {"html", "json", "txt"}
VALID_LANGUAGES = {"es", "en"}
VALID_TYPES = {"auto", "classic", "ble"}


# ─── Excepciones ─────────────────────────────────────────────────────────────

class ConfigError(Exception):
    """Error relacionado con la configuración."""


class ConfigValidationError(ConfigError):
    """Error de validación del esquema de configuración."""


# ─── Gestor de configuración ─────────────────────────────────────────────────

class BlueskyConfig:
    """Gestor de configuración singleton para Bluesky.

    Uso:
        cfg = BlueskyConfig()
        cfg.load()                          # Carga desde disco
        val = cfg.get("general.timeout")    # Lee con notación de puntos
        cfg.set("general.theme", "dark")    # Escribe y marca como modificado
        cfg.save()                          # Persiste a disco
    """

    _instance: Optional["BlueskyConfig"] = None

    def __init__(self) -> None:
        self._config: Dict[str, Any] = {}
        self._path: Optional[Path] = None
        self._dirty: bool = False
        self._loaded: bool = False

    # ── Singleton ────────────────────────────────────────────────────────────

    def __new__(cls, *args, **kwargs):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance

    @classmethod
    def reset_instance(cls):
        """Solo para tests: reinicia la singleton."""
        cls._instance = None

    # ── Carga ────────────────────────────────────────────────────────────────

    def load(self, path: Optional[str] = None) -> "BlueskyConfig":
        """Carga configuración desde disco.

        Args:
            path: Ruta opcional (corresponde a --config CLI flag).
                  Si no se provee, busca en orden de precedencia.

        Returns:
            self (para encadenamiento).
        """
        self._config = copy.deepcopy(DEFAULT_CONFIG)

        if path:
            self._path = Path(path)
        else:
            self._path = self._find_config()

        if self._path and self._path.exists():
            try:
                with open(self._path, "r", encoding="utf-8") as f:
                    user_config = json.load(f)
                self._merge(user_config)
                self._validate()
            except json.JSONDecodeError as e:
                raise ConfigError(
                    f"Error decodificando {self._path}: {e}"
                ) from e
            except ConfigValidationError:
                raise
            except Exception as e:
                raise ConfigError(f"Error cargando config: {e}") from e

        self._loaded = True
        self._dirty = False
        return self

    def _find_config(self) -> Optional[Path]:
        """Busca archivo de configuración en orden de precedencia."""
        candidates = [
            Path("bluesky.json"),
            Path.home() / ".config" / "bluesky" / "bluesky.json",
            Path.home() / ".bluesky.json",
        ]
        for p in candidates:
            if p.exists():
                return p
        # Si no existe ninguno, usa XDG por defecto
        xdg = Path.home() / ".config" / "bluesky" / "bluesky.json"
        xdg.parent.mkdir(parents=True, exist_ok=True)
        return xdg

    def _merge(self, user_config: Dict) -> None:
        """Merge recursivo del user_config sobre DEFAULT_CONFIG."""
        def deep_merge(base: Dict, override: Dict) -> None:
            for key, value in override.items():
                if key in base and isinstance(base[key], dict) and isinstance(value, dict):
                    deep_merge(base[key], value)
                else:
                    base[key] = copy.deepcopy(value)
        deep_merge(self._config, user_config)

    def _validate(self) -> None:
        """Valida tipos y valores de la configuración cargada."""
        errors = []

        for key, expected_type in CONFIG_SCHEMA.items():
            value = self._get_nested(key)
            if value is None:
                continue
            if isinstance(expected_type, tuple):
                if not isinstance(value, expected_type):
                    errors.append(f"  {key}: esperado {expected_type}, obtenido {type(value).__name__}")
            else:
                if not isinstance(value, expected_type):
                    errors.append(f"  {key}: esperado {expected_type.__name__}, obtenido {type(value).__name__}")

        # Validaciones específicas
        log_level = self._get_nested("general.log_level")
        if log_level and log_level not in VALID_LOG_LEVELS:
            errors.append(f"  general.log_level: '{log_level}' no es válido ({', '.join(VALID_LOG_LEVELS)})")

        theme = self._get_nested("general.theme")
        if theme and theme not in VALID_THEMES:
            errors.append(f"  general.theme: '{theme}' no es válido ({', '.join(VALID_THEMES)})")

        report_format = self._get_nested("general.report_format")
        if report_format and report_format not in VALID_FORMATS:
            errors.append(f"  general.report_format: '{report_format}' no es válido ({', '.join(VALID_FORMATS)})")

        language = self._get_nested("general.language")
        if language and language not in VALID_LANGUAGES:
            errors.append(f"  general.language: '{language}' no es válido ({', '.join(VALID_LANGUAGES)})")

        default_type = self._get_nested("default_target.type")
        if default_type and default_type not in VALID_TYPES:
            errors.append(f"  default_target.type: '{default_type}' no es válido ({', '.join(VALID_TYPES)})")

        timeout = self._get_nested("general.timeout")
        if timeout is not None and isinstance(timeout, (int, float)) and timeout <= 0:
            errors.append("  general.timeout: debe ser > 0")

        if errors:
            raise ConfigValidationError(
                "Errores de validación en configuración:\n" + "\n".join(errors)
            )

    # ── Acceso a valores ─────────────────────────────────────────────────────

    def _get_nested(self, key: str) -> Any:
        """Acceso anidado con notación de puntos: 'general.timeout'."""
        parts = key.split(".")
        current = self._config
        for part in parts:
            if isinstance(current, dict):
                current = current.get(part)
            else:
                return None
        return current

    def get(self, key: str, default: Any = None) -> Any:
        """Obtiene un valor de configuración.

        Args:
            key: Notación de puntos, ej. 'general.timeout'
            default: Valor por defecto si no existe.

        Returns:
            El valor configurado o default.
        """
        if not self._loaded:
            self.load()
        value = self._get_nested(key)
        return value if value is not None else default

    def get_all(self) -> Dict[str, Any]:
        """Retorna copia completa de la configuración."""
        if not self._loaded:
            self.load()
        return copy.deepcopy(self._config)

    def get_favorites(self) -> List[Dict[str, str]]:
        """Retorna lista de targets favoritos."""
        return self.get("favorites", [])

    def get_module_option(self, module_name: str, key: str, default: Any = None) -> Any:
        """Obtiene una opción específica de un módulo.

        Args:
            module_name: Nombre del módulo (ej. 'knob')
            key: Nombre de la opción
            default: Valor por defecto

        Returns:
            Valor de la opción o default.
        """
        module_opts = self.get("module_options", {})
        mod = module_opts.get(module_name, {})
        return mod.get(key, default)

    # ── Escritura ────────────────────────────────────────────────────────────

    def set(self, key: str, value: Any) -> None:
        """Establece un valor de configuración y marca como modificado.

        Args:
            key: Notación de puntos, ej. 'general.theme'
            value: Valor a asignar.
        """
        parts = key.split(".")
        current = self._config
        for i, part in enumerate(parts[:-1]):
            if part not in current or not isinstance(current[part], dict):
                current[part] = {}
            current = current[part]
        current[parts[-1]] = value
        self._dirty = True

    def set_module_option(self, module_name: str, key: str, value: Any) -> None:
        """Establece una opción específica de un módulo.

        Args:
            module_name: Nombre del módulo
            key: Nombre de la opción
            value: Valor a asignar
        """
        module_opts = self.get("module_options", {})
        if module_name not in module_opts:
            module_opts[module_name] = {}
        module_opts[module_name][key] = value
        self._config.setdefault("module_options", {})[module_name] = module_opts[module_name]
        self._dirty = True

    def add_favorite(self, address: str, name: str = "", type_: str = "auto") -> None:
        """Añade un target a favoritos.

        Args:
            address: Dirección MAC o UUID
            name: Nombre descriptivo
            type_: Tipo de dispositivo ('auto', 'classic', 'ble')
        """
        if type_ not in VALID_TYPES:
            type_ = "auto"
        favs = self.get("favorites", [])
        # Evitar duplicados por address
        favs = [f for f in favs if f.get("address", "").lower() != address.lower()]
        favs.append({"address": address, "name": name, "type": type_})
        self._config["favorites"] = favs
        self._dirty = True

    def remove_favorite(self, address: str) -> None:
        """Elimina un target de favoritos por address."""
        favs = self.get("favorites", [])
        favs = [f for f in favs if f.get("address", "").lower() != address.lower()]
        self._config["favorites"] = favs
        self._dirty = True

    # ── Persistencia ─────────────────────────────────────────────────────────

    def save(self, path: Optional[str] = None) -> None:
        """Guarda la configuración actual a disco.

        Args:
            path: Ruta opcional. Si no se provee, usa la ruta detectada.
        """
        if not self._dirty and not path:
            return

        dest = Path(path) if path else self._path
        if not dest:
            dest = Path.home() / ".config" / "bluesky" / "bluesky.json"
            dest.parent.mkdir(parents=True, exist_ok=True)

        try:
            dest.parent.mkdir(parents=True, exist_ok=True)
            with open(dest, "w", encoding="utf-8") as f:
                json.dump(self._config, f, indent=2, ensure_ascii=False)
            self._dirty = False
            self._path = dest
        except OSError as e:
            raise ConfigError(f"Error guardando configuración en {dest}: {e}") from e

    def is_dirty(self) -> bool:
        """¿Hay cambios sin guardar?"""
        return self._dirty

    # ── Reset ────────────────────────────────────────────────────────────────

    def reset_to_defaults(self) -> None:
        """Resetea toda la configuración a valores por defecto."""
        self._config = copy.deepcopy(DEFAULT_CONFIG)
        self._dirty = True

    # ── Helpers ──────────────────────────────────────────────────────────────

    def export_summary(self) -> str:
        """Retorna resumen legible de la configuración activa."""
        lines = [
            "╔══════════════════════════════════════╗",
            "║      Bluesky Config Summary          ║",
            "╚══════════════════════════════════════╝",
            "",
            f"  Config file : {self._path or '(defaults)'}",
            f"  Theme       : {self.get('general.theme')}",
            f"  Log level   : {self.get('general.log_level')}",
            f"  Safe mode   : {self.get('general.safe_mode')}",
            f"  Timeout     : {self.get('general.timeout')}s",
            f"  Language    : {self.get('general.language')}",
            f"  Report      : {self.get('general.report_format')}",
            f"  Scan        : {'active' if self.get('scanner.active_scan') else 'passive'}, "
            f"{'classic' if self.get('scanner.classic_inquiry') else 'BLE only'}, "
            f"{self.get('scanner.scan_duration')}s",
            f"  Favorites   : {len(self.get('favorites', []))} target(s)",
            f"  Module opts : {len(self.get('module_options', {}))} module(s)",
        ]
        return "\n".join(lines)


# ─── Función de acceso rápido ────────────────────────────────────────────────

_config_instance: Optional[BlueskyConfig] = None


def get_config() -> BlueskyConfig:
    """Obtiene/crea la instancia singleton de configuración.

    Returns:
        Instancia de BlueskyConfig (ya cargada).
    """
    global _config_instance
    if _config_instance is None:
        _config_instance = BlueskyConfig()
        _config_instance.load()
    return _config_instance


# ─── CLI integration helper ──────────────────────────────────────────────────

def parse_key_value(raw: str) -> tuple[str, Any]:
    """Parsea 'key=value' de línea de comandos.

    Args:
        raw: String en formato 'clave=valor'

    Returns:
        Tupla (clave, valor_parseado).

    Raises:
        ValueError: Si no se puede parsear.
    """
    if "=" not in raw:
        raise ValueError(f"Formato inválido. Use 'clave=valor', obtenido: '{raw}'")
    key, _, str_val = raw.partition("=")
    key = key.strip()
    str_val = str_val.strip()

    # Parseo automático de tipos
    if str_val.lower() in ("true", "yes", "1"):
        return key, True
    if str_val.lower() in ("false", "no", "0"):
        return key, False
    try:
        return key, int(str_val)
    except ValueError:
        pass
    try:
        return key, float(str_val)
    except ValueError:
        pass
    return key, str_val
