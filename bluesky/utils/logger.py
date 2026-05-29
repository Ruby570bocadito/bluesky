"""
Sistema de logging profesional para Bluesky.

Reemplaza los prints() con niveles de logging configurables:
  DEBUG, INFO, WARNING, ERROR, CRITICAL

Características:
  - Log a archivo y consola simultáneamente
  - Rich output cuando está disponible
  - Rotación de archivos
  - Colores por nivel
  - Verbose mode (-v, -vv, -vvv)
  - Sin dependencia de Rich si no está instalado
"""

import os
import sys
import logging
import logging.handlers
from pathlib import Path
from typing import Optional, Dict, Any
from datetime import datetime


# ─── Configuración global ─────────────────────────────────────────────────

_LOG_LEVELS: Dict[str, int] = {
    "debug": logging.DEBUG,
    "info": logging.INFO,
    "warning": logging.WARNING,
    "error": logging.ERROR,
    "critical": logging.CRITICAL,
}

_LOG_INITIALIZED = False
_LOG_FILE: Optional[str] = None

# Colores ANSI para terminal
_ANSI_COLORS = {
    "DEBUG": "\033[36m",      # Cyan
    "INFO": "\033[32m",       # Green
    "WARNING": "\033[33m",    # Yellow
    "ERROR": "\033[31m",      # Red
    "CRITICAL": "\033[41m",   # Red background
    "RESET": "\033[0m",
}

# Intentar importar Rich para output mejorado
try:
    from rich.logging import RichHandler
    from rich.console import Console
    RICH_AVAILABLE = True
    _rich_console = Console(stderr=True)
except ImportError:
    RICH_AVAILABLE = False


# ─── Formateadores personalizados ─────────────────────────────────────────

class ColorFormatter(logging.Formatter):
    """Formateador con colores ANSI para terminal."""

    def format(self, record):
        levelname = record.levelname
        color = _ANSI_COLORS.get(levelname, "")
        reset = _ANSI_COLORS["RESET"]
        record.levelname = f"{color}{levelname:8}{reset}"
        return super().format(record)


class CompactFormatter(logging.Formatter):
    """Formateador compacto para consola."""

    def format(self, record):
        record.msg = record.msg.replace("\n", " ")
        return super().format(record)


# ─── Logger principal ─────────────────────────────────────────────────────

class BlueskyLogger:
    """
    Logger principal de Bluesky.
    
    Ejemplo:
        >>> from bluesky.utils.logger import log
        >>> log.info("Módulo cargado: %s", name)
        >>> log.warning("Hardware no disponible: %s", hw)
        >>> log.error("Error en ataque: %s", e, exc_info=True)
    """

    def __init__(self):
        self._logger: Optional[logging.Logger] = None
        self._level = logging.INFO
        self._log_file: Optional[str] = None
        self._initialized = False

    def setup(
        self,
        level: str = "info",
        log_file: Optional[str] = None,
        verbose: bool = False,
        rich: bool = True,
    ):
        """
        Configura el sistema de logging.
        
        Args:
            level: Nivel mínimo ('debug', 'info', 'warning', 'error', 'critical')
            log_file: Ruta al archivo de log (opcional)
            verbose: Si True, muestra DEBUG en consola
            rich: Si True, usa RichHandler si está disponible
        """
        global _LOG_INITIALIZED, _LOG_FILE

        if self._initialized:
            return

        self._level = _LOG_LEVELS.get(level.lower(), logging.INFO)
        if verbose:
            self._level = logging.DEBUG

        self._logger = logging.getLogger("bluesky")
        self._logger.setLevel(self._level)
        self._logger.handlers.clear()

        # ─── Handler de consola ─────────────────────────────────────
        if rich and RICH_AVAILABLE:
            # Usar RichHandler para output bonito
            rich_handler = RichHandler(
                console=_rich_console,
                show_time=True,
                show_path=False,
                markup=True,
                rich_tracebacks=True,
            )
            rich_handler.setLevel(self._level)
            self._logger.addHandler(rich_handler)
        else:
            # Fallback ANSI
            console_handler = logging.StreamHandler(sys.stderr)
            console_handler.setLevel(self._level)
            console_fmt = ColorFormatter(
                "%(levelname)s %(message)s",
                datefmt="%H:%M:%S",
            )
            console_handler.setFormatter(console_fmt)
            self._logger.addHandler(console_handler)

        # ─── Handler de archivo ─────────────────────────────────────
        if log_file:
            self._log_file = log_file
            _LOG_FILE = log_file
            Path(log_file).parent.mkdir(parents=True, exist_ok=True)

            file_handler = logging.handlers.RotatingFileHandler(
                log_file,
                maxBytes=10 * 1024 * 1024,  # 10 MB
                backupCount=5,
                encoding="utf-8",
            )
            file_handler.setLevel(logging.DEBUG)  # Siempre log completo a archivo
            file_fmt = logging.Formatter(
                "%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
                datefmt="%Y-%m-%d %H:%M:%S",
            )
            file_handler.setFormatter(file_fmt)
            self._logger.addHandler(file_handler)

        else:
            # Log por defecto en reports/ si no se especifica
            default_log = Path("reports") / f"bluesky_{datetime.now():%Y%m%d}.log"
            default_log.parent.mkdir(parents=True, exist_ok=True)
            file_handler = logging.handlers.RotatingFileHandler(
                str(default_log),
                maxBytes=5 * 1024 * 1024,
                backupCount=3,
                encoding="utf-8",
            )
            file_handler.setLevel(logging.DEBUG)
            file_fmt = logging.Formatter(
                "%(asctime)s | %(levelname)-8s | %(message)s",
            )
            file_handler.setFormatter(file_fmt)
            self._logger.addHandler(file_handler)
            self._log_file = str(default_log)

        self._initialized = True
        _LOG_INITIALIZED = True

        self.debug("Logger initialized: level=%s, file=%s", level, self._log_file)

    # ─── Métodos de conveniencia ────────────────────────────────────

    @property
    def logger(self) -> logging.Logger:
        if not self._initialized:
            self.setup()
        return self._logger

    def debug(self, msg: str, *args, **kwargs):
        self.logger.debug(msg, *args, **kwargs)

    def info(self, msg: str, *args, **kwargs):
        self.logger.info(msg, *args, **kwargs)

    def warning(self, msg: str, *args, **kwargs):
        self.logger.warning(msg, *args, **kwargs)

    def error(self, msg: str, *args, **kwargs):
        self.logger.error(msg, *args, **kwargs)

    def critical(self, msg: str, *args, **kwargs):
        self.logger.critical(msg, *args, **kwargs)

    def exception(self, msg: str, *args, **kwargs):
        """Log con traceback de excepción."""
        self.logger.exception(msg, *args, **kwargs)

    def success(self, msg: str, *args, **kwargs):
        """Método especial: nivel INFO con marcador ✅."""
        self.logger.info(f"✅ {msg}", *args, **kwargs)

    def fail(self, msg: str, *args, **kwargs):
        """Método especial: nivel ERROR con marcador ❌."""
        self.logger.error(f"❌ {msg}", *args, **kwargs)

    def section(self, title: str):
        """Log de sección (separador visual)."""
        self.logger.info("─" * 50)
        self.logger.info(f"  {title}")
        self.logger.info("─" * 50)

    def get_log_file(self) -> Optional[str]:
        """Ruta al archivo de log actual."""
        return self._log_file

    def set_level(self, level: str):
        """Cambia el nivel de logging en caliente.

        Args:
            level: Nombre del nivel ('debug', 'info', 'warning', 'error', 'critical').
        """
        level_num = _LOG_LEVELS.get(level.lower())
        if level_num is None:
            raise ValueError(f"Nivel inválido: {level}. Use: {', '.join(_LOG_LEVELS)}")
        self._level = level_num
        if self._logger:
            self._logger.setLevel(level_num)
            for handler in self._logger.handlers:
                handler.setLevel(level_num)

    def get_level(self) -> str:
        """Nivel actual como string."""
        for name, num in _LOG_LEVELS.items():
            if num == self._level:
                return name
        return "info"


# ─── Singleton global ─────────────────────────────────────────────────────

log = BlueskyLogger()

__all__ = ["log", "BlueskyLogger", "_LOG_LEVELS"]
