#!/usr/bin/env python3
"""
Bluesky Plugin Loader
=====================
Sistema de carga dinámica de plugins para Bluesky.

Soporta dos mecanismos:
  1. **Plugins locales**: directorio `plugins/` en el proyecto
  2. **Entry points**: módulos instalados vía pip que registran
     el grupo `bluesky.modules` en `setup.py`

Formato de plugin:
    Un plugin es cualquier módulo Python que expone `PLUGIN_INFO`:

    ```python
    PLUGIN_INFO = {
        "name": "my-plugin",
        "version": "1.0.0",
        "description": "Descripción del plugin",
        "author": "Autor",
        "type": "attack",        # attack | scanner | utility | reporter
        "module": "MiClaseModulo",  # Clase dentro del módulo
        "requires": ["bleak"],      # Dependencias opcionales
    }
    ```
"""

from __future__ import annotations

import sys
import os
import importlib
import importlib.util
import inspect
from pathlib import Path
from typing import Any, Dict, List, Optional, Type, Callable
from dataclasses import dataclass, field


# ─── Data classes ────────────────────────────────────────────────────────────

@dataclass
class PluginInfo:
    """Metadatos de un plugin cargado."""
    name: str
    version: str
    description: str
    author: str = "unknown"
    plugin_type: str = "attack"  # attack | scanner | utility | reporter
    module_class: str = ""
    requires: List[str] = field(default_factory=list)
    path: Optional[str] = None
    entry_point: bool = False
    loaded: bool = False
    error: Optional[str] = None


# ─── Excepciones ─────────────────────────────────────────────────────────────

class PluginError(Exception):
    """Error relacionado con la carga de plugins."""


class PluginNotFound(PluginError):
    """Plugin no encontrado."""


class PluginDependencyError(PluginError):
    """Dependencia de plugin no satisfecha."""


# ─── Plugin Loader ───────────────────────────────────────────────────────────

class PluginLoader:
    """Cargador de plugins para Bluesky.

    Descubre, valida y carga módulos desde:
      - Directorio local `plugins/`
      - Entry points de pip (`bluesky.modules`)
      - Directorios personalizados

    Uso:
        loader = PluginLoader()
        loader.discover()                   # Buscar plugins
        loader.load_all()                   # Cargar todos
        loader.load("mi-plugin")            # Cargar uno específico
        modules = loader.get_module_classes()  # Obtener clases de módulo
    """

    def __init__(self, extra_paths: Optional[List[str]] = None):
        self._plugins: Dict[str, PluginInfo] = {}
        self._module_classes: Dict[str, Type] = {}
        self._extra_paths = extra_paths or []

        # Directorios de búsqueda
        self._plugin_dirs: List[Path] = []
        self._init_directories()

    def _init_directories(self):
        """Inicializa los directorios donde buscar plugins."""
        # plugins/ junto al proyecto
        project_root = Path(__file__).parent.parent.parent
        local_plugins = project_root / "plugins"
        if local_plugins.exists():
            self._plugin_dirs.append(local_plugins)

        # plugins/ en el directorio actual
        cwd_plugins = Path.cwd() / "plugins"
        if cwd_plugins.exists() and cwd_plugins != local_plugins:
            self._plugin_dirs.append(cwd_plugins)

        # Directorios extra
        for p in self._extra_paths:
            p_path = Path(p)
            if p_path.exists() and p_path.is_dir():
                self._plugin_dirs.append(p_path)

    # ── Descubrimiento ───────────────────────────────────────────────────────

    def discover(self) -> Dict[str, PluginInfo]:
        """Descubre todos los plugins disponibles.

        Returns:
            Dict nombre -> PluginInfo (no cargados aún).
        """
        self._plugins = {}
        self._discover_local()
        self._discover_entry_points()
        return dict(self._plugins)

    def _discover_local(self):
        """Busca plugins en directorios locales."""
        for plugin_dir in self._plugin_dirs:
            if not plugin_dir.exists():
                continue

            for item in plugin_dir.iterdir():
                if item.is_dir():
                    self._scan_package(item)
                elif item.suffix == ".py":
                    self._scan_module(item)

    def _scan_package(self, path: Path):
        """Escanea un paquete (directorio) como posible plugin."""
        # Debe tener __init__.py o un archivo .py con el mismo nombre
        init_file = path / "__init__.py"
        main_file = path / f"{path.name}.py"

        target = None
        if init_file.exists():
            target = init_file
        elif main_file.exists():
            target = main_file

        if target:
            self._extract_plugin_info(target, path)

    def _scan_module(self, path: Path):
        """Escanea un archivo .py como posible plugin."""
        # Ignorar __init__.py
        if path.name == "__init__.py":
            return
        self._extract_plugin_info(path)

    def _extract_plugin_info(self, filepath: Path, package_path: Optional[Path] = None):
        """Extrae PLUGIN_INFO de un archivo Python sin cargarlo."""
        try:
            with open(filepath, "r", encoding="utf-8") as f:
                source = f.read()
        except OSError:
            return

        # Buscar PLUGIN_INFO = {...} en el source
        # Usamos un método simple: buscar la línea que contiene PLUGIN_INFO
        # y hacer eval seguro. Alternativa más robusta: ast.literal_eval
        if "PLUGIN_INFO" not in source:
            return

        try:
            # Cargar el módulo para extraer PLUGIN_INFO
            module = self._import_module_from_path(filepath, package_path)
            if module is None:
                return

            info = getattr(module, "PLUGIN_INFO", None)
            if not isinstance(info, dict):
                return

            name = info.get("name", filepath.stem)
            self._plugins[name] = PluginInfo(
                name=name,
                version=info.get("version", "0.1.0"),
                description=info.get("description", ""),
                author=info.get("author", "unknown"),
                plugin_type=info.get("type", "attack"),
                module_class=info.get("module", ""),
                requires=info.get("requires", []),
                path=str(filepath),
                entry_point=False,
            )
        except Exception:
            # Si falla la extracción, ignoramos este plugin
            pass

    def _import_module_from_path(self, filepath: Path, package_path: Optional[Path] = None) -> Optional[Any]:
        """Importa un módulo Python desde una ruta de archivo específica."""
        try:
            # Si es parte de un paquete
            if package_path and package_path.is_dir():
                parent = str(package_path.parent)
                if parent not in sys.path:
                    sys.path.insert(0, parent)
                module_name = f"plugins.{filepath.stem}"
                return importlib.import_module(module_name)

            # Archivo .py suelto
            module_name = filepath.stem
            spec = importlib.util.spec_from_file_location(module_name, str(filepath))
            if spec is None or spec.loader is None:
                return None
            module = importlib.util.module_from_spec(spec)
            # No ejecutar el módulo aún (solo extraemos PLUGIN_INFO)
            # Necesitamos ejecutarlo para obtener PLUGIN_INFO
            spec.loader.exec_module(module)
            return module
        except Exception:
            return None

    def _discover_entry_points(self):
        """Busca plugins registrados como entry points de pip."""
        try:
            # Intentar con importlib.metadata (Python 3.8+)
            if sys.version_info >= (3, 8):
                from importlib.metadata import entry_points
                eps = entry_points(group="bluesky.modules")
                for ep in eps:
                    try:
                        module = ep.load()
                        info = getattr(module, "PLUGIN_INFO", None)
                        if not isinstance(info, dict):
                            info = {"name": ep.name, "description": f"Entry point: {ep.name}"}

                        name = info.get("name", ep.name)
                        self._plugins[name] = PluginInfo(
                            name=name,
                            version=info.get("version", "0.1.0"),
                            description=info.get("description", ""),
                            author=info.get("author", "unknown"),
                            plugin_type=info.get("type", "attack"),
                            module_class=info.get("module", ""),
                            requires=info.get("requires", []),
                            entry_point=True,
                        )
                    except Exception as e:
                        # Plugin entry point falló, lo ignoramos
                        self._plugins[ep.name] = PluginInfo(
                            name=ep.name,
                            version="?",
                            description=f"Error loading: {e}",
                            error=str(e),
                        )
        except Exception:
            # importlib.metadata puede no estar disponible
            pass

    # ── Carga ────────────────────────────────────────────────────────────────

    def load_all(self) -> List[PluginInfo]:
        """Carga todos los plugins descubiertos.

        Returns:
            Lista de PluginInfo con estado de carga.
        """
        if not self._plugins:
            self.discover()

        results = []
        for name in list(self._plugins.keys()):
            result = self.load(name)
            results.append(result)
        return results

    def load(self, name: str) -> PluginInfo:
        """Carga un plugin específico por nombre.

        Args:
            name: Nombre del plugin.

        Returns:
            PluginInfo con estado actualizado.

        Raises:
            PluginNotFound: Si el plugin no existe.
        """
        if not self._plugins:
            self.discover()

        if name not in self._plugins:
            raise PluginNotFound(f"Plugin '{name}' no encontrado. Usa discover() primero.")

        info = self._plugins[name]

        # Verificar dependencias
        if info.requires:
            missing = [dep for dep in info.requires if not self._check_dependency(dep)]
            if missing:
                err = f"Dependencias faltantes para '{name}': {', '.join(missing)}"
                info.error = err
                info.loaded = False
                return info

        # Cargar la clase del módulo
        if info.module_class:
            try:
                cls = self._import_class(info)
                if cls:
                    self._module_classes[name] = cls
                    info.loaded = True
                    info.error = None
                else:
                    info.error = f"No se pudo cargar la clase '{info.module_class}'"
                    info.loaded = False
            except Exception as e:
                info.error = str(e)
                info.loaded = False
        else:
            # El plugin no expone una clase de módulo (utilidad, reporter, etc.)
            info.loaded = True

        return info

    def _import_class(self, info: PluginInfo) -> Optional[Type]:
        """Importa la clase del módulo especificada en PLUGIN_INFO.

        Soporta formatos:
          - "MiClase" (misma clase en el módulo del plugin)
          - "modulo.Submodulo.Clase" (anidado)
        """
        # El path del plugin ya fue importado durante el descubrimiento
        # Necesitamos re-importar o ya tenemos el módulo en sys.modules
        if info.path:
            filepath = Path(info.path)
            module = self._import_module_from_path(filepath)
        else:
            # Es un entry point, intentar importar por nombre
            try:
                module = importlib.import_module(info.name.replace("-", "_"))
            except ImportError:
                return None

        if module is None:
            return None

        # Navegar por la ruta de la clase
        parts = info.module_class.split(".")
        cls = module
        for part in parts:
            cls = getattr(cls, part, None)
            if cls is None:
                return None

        if inspect.isclass(cls):
            return cls
        return None

    def _check_dependency(self, dep: str) -> bool:
        """Verifica si una dependencia Python está instalada."""
        try:
            importlib.import_module(dep)
            return True
        except ImportError:
            return False

    # ── Acceso a módulos cargados ────────────────────────────────────────────

    def get_module_classes(self) -> Dict[str, Type]:
        """Retorna todas las clases de módulo cargadas desde plugins.

        Returns:
            Dict nombre -> clase del módulo.
        """
        return dict(self._module_classes)

    def get_plugin_info(self, name: str) -> Optional[PluginInfo]:
        """Obtiene información de un plugin específico."""
        return self._plugins.get(name)

    def list_plugins(self, filter_type: Optional[str] = None) -> List[PluginInfo]:
        """Lista plugins descubiertos, opcionalmente filtrados por tipo.

        Args:
            filter_type: 'attack', 'scanner', 'utility', 'reporter' o None (todos).

        Returns:
            Lista de PluginInfo.
        """
        infos = list(self._plugins.values())
        if filter_type:
            infos = [i for i in infos if i.plugin_type == filter_type]
        return infos

    def count(self) -> int:
        """Número de plugins descubiertos."""
        return len(self._plugins)

    def count_loaded(self) -> int:
        """Número de plugins cargados exitosamente."""
        return sum(1 for p in self._plugins.values() if p.loaded)


# ─── Plugins directory initializer ──────────────────────────────────────────

def ensure_plugins_directory() -> Path:
    """Crea el directorio plugins/ si no existe y devuelve su ruta.

    Returns:
        Path al directorio plugins.
    """
    project_root = Path(__file__).parent.parent.parent
    plugins_dir = project_root / "plugins"
    plugins_dir.mkdir(exist_ok=True)
    init_file = plugins_dir / "__init__.py"
    if not init_file.exists():
        init_file.write_text("# Bluesky plugins directory\n")
    return plugins_dir


# ─── Función helper ──────────────────────────────────────────────────────────

def create_plugin_template(name: str, plugin_type: str = "attack") -> str:
    """Genera código fuente para un plugin Bluesky.

    Args:
        name: Nombre del plugin/clase.
        plugin_type: Tipo de plugin ('attack', 'scanner', 'utility', 'reporter').

    Returns:
        Código Python del plugin como string.
    """
    class_name = name.replace("-", "_").title().replace("_", "") + "Plugin"

    type_map = {
        "attack": "Módulo de ataque Bluetooth personalizado",
        "scanner": "Escáner Bluetooth personalizado",
        "utility": "Utilidad Bluetooth",
        "reporter": "Generador de reportes personalizado",
    }
    description = type_map.get(plugin_type, "Plugin Bluesky personalizado")

    return f'''#!/usr/bin/env python3
"""
Bluesky Plugin: {name}
{description}
"""

from typing import Dict, Any, List, Optional

PLUGIN_INFO = {{
    "name": "{name}",
    "version": "1.0.0",
    "description": "{description}",
    "author": "Tu Nombre",
    "type": "{plugin_type}",
    "module": "{class_name}",
    "requires": [],
}}


class {class_name}:
    """Plugin de ejemplo para Bluesky."""

    def __init__(self):
        self.name = "{name}"
        self.description = "{description}"

    def run(self, target: str = "", options: Dict[str, Any] = None) -> Dict[str, Any]:
        \"\"\"Ejecuta la funcionalidad del plugin.

        Args:
            target: Dirección MAC o UUID del target.
            options: Opciones adicionales.

        Returns:
            Dict con resultado.
        \"\"\"
        return {{
            "success": True,
            "data": {{
                "message": f"Plugin {{self.name}} ejecutado correctamente",
                "target": target,
            }}
        }}

    def get_info(self) -> Dict[str, Any]:
        \"\"\"Información del plugin.\"\"\"
        return {{
            "name": self.name,
            "description": self.description,
            "version": "1.0.0",
            "author": "Tu Nombre",
        }}
'''
