"""
ModuleEngine - Carga y gestión dinámica de módulos de ataque/escaneo.
"""

import os
import re
import inspect
import importlib
from pathlib import Path
from typing import TYPE_CHECKING, Dict, List, Optional, Type

if TYPE_CHECKING:
    from bluesky.core.plugin_loader import PluginLoader


# MAC Bluetooth: XX:XX:XX:XX:XX:XX o XX-XX-XX-XX-XX-XX (hex).
# Validar antes de pasar a subprocess evita que un caller poco cuidadoso
# introduzca argumentos extra en la línea de comandos de hcitool/sdptool/
# bluetoothctl/termux-bluetooth-* (defensa en profundidad aunque el argv
# separado ya evita shell injection).
_MAC_RE = re.compile(
    r"^[0-9A-Fa-f]{2}([:-][0-9A-Fa-f]{2}){5}$"
)


def is_valid_mac(address: str) -> bool:
    """Valida que una dirección tenga formato MAC Bluetooth."""
    return isinstance(address, str) and bool(_MAC_RE.match(address))


class BaseModule:
    """Clase base para todos los módulos de bluesky."""

    name: str = ""
    description: str = ""
    author: str = "Ruby570bocadito"
    version: str = "0.2.0"
    cve: str = ""
    cve_url: str = ""
    exploit_links: List[str] = []
    references: List[str] = []
    requires_hardware: List[str] = []
    requires_root: bool = False
    target_type: str = "classic"  # classic | ble | both | android
    severity: str = "medium"      # low | medium | high | critical
    module_options: Dict[str, str] = {
        "TARGET": "Dirección MAC del dispositivo objetivo"
    }

    def __init__(self, target: str = "", options: dict = None):
        self.target = target
        self.options = options or {}
        self.result = {"success": False, "data": {}, "error": None}

    def check_prerequisites(self) -> tuple[bool, str]:
        """Verifica si se cumplen los prerequisitos para ejecutar el módulo.

        Comprobaciones por defecto:
          - target presente si module_options incluye TARGET
          - plataforma compatible
          - hardware requerido (si se puede detectar)
          - root requerido
        """
        # Verificar target
        if "TARGET" in self.module_options and not self.target:
            # Si tiene opción TARGET pero no se pasó target directamente,
            # verificar si está en options
            if not self.options or not self.options.get("TARGET", ""):
                # Algunos módulos definen TARGET como opcional (p.ej.
                # crackle lo usa "para filtrado"). Si el módulo marca la
                # opción con descripción que contiene 'opcional', no la
                # exijamos. Esto es heurístico pero respeta la semántica
                # existente sin romper tests.
                target_desc = str(self.module_options.get("TARGET", ""))
                if "opcional" not in target_desc.lower():
                    return False, "Se requiere un target (MAC address). Usa set TARGET <MAC> o pasa el target al ejecutar."

        # Validar formato de MAC si se proporcionó target (defensa en
        # profundidad: aunque subprocess.run con argv separado evita shell
        # injection, un target mal formado podría ser pasado como flag
        # adicional a herramientas CLI y causar comportamiento inesperado).
        target_value = self.target or (self.options.get("TARGET", "") if self.options else "")
        if target_value and not is_valid_mac(target_value):
            return False, (
                f"Target '{target_value}' no tiene formato MAC válido "
                "(XX:XX:XX:XX:XX:XX)."
            )

        # Verificar root
        if self.requires_root:
            if os.name != "posix" or os.geteuid() != 0:
                return False, (f"El módulo '{self.name}' requiere privilegios de root. "
                              "Ejecuta con sudo.")

        # Verificar hardware requerido (solo check básico)
        if self.requires_hardware:
            hw_info = ", ".join(self.requires_hardware)
            # No fallamos, solo advertimos (podría estar en otro sistema)
            if self.options and self.options.get("STRICT_HW", False):
                return False, f"Requiere hardware: {hw_info}"

        return True, ""

    def run(self):
        """Ejecuta el módulo. Debe ser sobreescrito."""
        raise NotImplementedError

    def _opt_int(self, key: str, default: int) -> int:
        """Lee una opción numérica de self.options tolerando valores malformados.

        Un valor ausente o vacío devuelve `default`; un valor presente pero no
        numérico (p.ej. 'abc' llegado por --options) también devuelve `default`
        en lugar de lanzar ValueError durante __init__.
        """
        value = self.options.get(key)
        if value is None or value == "":
            return default
        try:
            return int(value)
        except (TypeError, ValueError):
            return default

    def get_info(self) -> dict:
        """Retorna información detallada del módulo."""
        return {
            "name": self.name,
            "description": self.description,
            "author": self.author,
            "version": self.version,
            "cve": self.cve,
            "cve_url": self.cve_url,
            "exploit_links": self.exploit_links,
            "references": self.references,
            "requires_hardware": self.requires_hardware,
            "requires_root": self.requires_root,
            "target_type": self.target_type,
            "severity": self.severity,
            "module_options": self.module_options,
        }


class ModuleEngine:
    """Motor que descubre, carga y ejecuta módulos dinámicamente."""

    def __init__(self, load_plugins: bool = True):
        self._modules: Dict[str, Type[BaseModule]] = {}
        self.plugin_loader: Optional["PluginLoader"] = None
        self._discover_modules()
        if load_plugins:
            self.load_plugins()

    def load_plugins(self) -> int:
        """Carga módulos desde plugins externos.

        Returns:
            Número de módulos plugin cargados.
        """
        from bluesky.core.plugin_loader import PluginLoader
        self.plugin_loader = PluginLoader()
        self.plugin_loader.discover()
        self.plugin_loader.load_all()

        count = 0
        for name, cls in self.plugin_loader.get_module_classes().items():
            # Verificar que herede de BaseModule o al menos tenga los métodos mínimos
            if isinstance(cls, type) and issubclass(cls, BaseModule):
                try:
                    inst = cls()
                    mod_name = inst.name.lower()
                    # No sobrescribir módulos nativos
                    if mod_name not in self._modules:
                        self._modules[mod_name] = cls
                        count += 1
                except Exception:
                    # Plugin inválido, ignorar
                    pass
            else:
                # Plugin que no hereda de BaseModule pero tiene interfaz compatible
                try:
                    inst = cls()
                    if hasattr(inst, 'run') and hasattr(inst, 'get_info'):
                        mod_name = getattr(inst, 'name', name).lower()
                        if mod_name not in self._modules:
                            self._modules[mod_name] = cls
                            count += 1
                except Exception:
                    pass

        return count

    def _discover_modules(self):
        """Descubre todos los módulos disponibles en el paquete de módulos."""
        modules_path = Path(__file__).parent.parent / "modules" / "attacks"
        scanners_path = Path(__file__).parent.parent / "modules" / "scanners"
        exploits_path = Path(__file__).parent.parent / "modules" / "exploits"

        base = Path(__file__).parent.parent.parent  # Raíz del proyecto

        for base_path in [modules_path, scanners_path, exploits_path]:
            if not base_path.exists():
                continue
            for f in base_path.iterdir():
                if f.name.startswith("_") or f.suffix != ".py":
                    continue
                module_name = f.stem
                try:
                    # Convertir ruta relativa a la raíz en un import absoluto
                    rel = f.resolve().relative_to(base.resolve())
                    parts = list(rel.parts)
                    if parts[-1].endswith('.py'):
                        parts[-1] = parts[-1][:-3]
                    pkg_path = ".".join(parts[:-1])
                    full_import = f"{pkg_path}.{parts[-1]}" if pkg_path else parts[-1]
                    mod = importlib.import_module(full_import)

                    # Buscar la clase del módulo (hereda de BaseModule)
                    for attr_name in dir(mod):
                        attr = getattr(mod, attr_name)
                        if isinstance(attr, type) and issubclass(attr, BaseModule) and attr is not BaseModule:
                            instance = attr()
                            self._modules[instance.name.lower()] = attr
                            break
                except Exception as e:
                    print(f"  [!] Error loading module {module_name}: {e}")

    def list_modules(self) -> List[dict]:
        """Lista todos los módulos disponibles con su metadata."""
        result = []
        for name, cls in sorted(self._modules.items()):
            try:
                info = cls().get_info()
                result.append(info)
            except Exception:
                result.append({"name": name, "error": "Cannot load info"})
        return result

    def get_module(self, name: str) -> Optional[Type[BaseModule]]:
        """Obtiene una clase de módulo por nombre."""
        return self._modules.get(name.lower())

    @staticmethod
    def _call_run(module, target: str, options: dict):
        """Invoca module.run() con target/options solo si su firma los acepta.

        Evita reintentar run() cuando un TypeError se produce DENTRO de la
        ejecución (ello ejecutaría el módulo dos veces). El fallback a
        run() sin kwargs solo ocurre si los argumentos no se pueden ligar,
        en cuyo caso no se ejecutó nada todavía.
        """
        run_fn = getattr(module, 'run', None)
        if run_fn is None:
            raise NotImplementedError(f"{module!r} no define run()")
        call_kwargs = {"target": target, "options": options}
        try:
            inspect.signature(run_fn).bind(**call_kwargs)
        except TypeError:
            # El módulo no acepta target/options extra (aún no ejecutó nada)
            return run_fn()
        return run_fn(**call_kwargs)

    def run_module(self, name: str, target: str = "", options: dict = None) -> dict:
        """Ejecuta un módulo por nombre.

        Todos los resultados comparten el mismo shape:
            {"success": bool, "data": dict, "error": str|None}
        """
        cls = self.get_module(name)
        if not cls:
            return {"success": False, "data": {}, "error": f"Módulo '{name}' no encontrado"}

        options = options or {}

        # Adaptar: soportar tanto BaseModule como plugins sin __init__ especial
        try:
            module = cls(target=target, options=options)
        except TypeError:
            # Plugin sin target/options en __init__
            module = cls()
            if target and hasattr(module, 'set_target'):
                module.set_target(target)
        except ValueError as e:
            # El __init__ del módulo rechazó las opciones (p.ej. un int() con
            # valor no numérico). No reintentamos: devolvemos error limpio.
            return {"success": False, "data": {},
                    "error": f"Opciones inválidas para '{name}': {e}"}

        # Verificar prerequisitos (solo si es BaseModule)
        ok, msg = True, ""
        if hasattr(module, 'check_prerequisites'):
            try:
                ok, msg = module.check_prerequisites()
            except (TypeError, AttributeError):
                # TypeError: interfaz de plugin no estándar.
                # AttributeError: plataforma sin símbolos usados por el check
                # (p.ej. os.geteuid en Windows). Degradar sin crashear.
                ok, msg = True, ""

        if not ok:
            return {"success": False, "data": {}, "error": msg}

        try:
            result = self._call_run(module, target, options)
            return result
        except Exception as e:
            # Contrato de resultados: TODOS los resultados comparten el shape
            # {"success", "data", "error"}. Sin "data", los consumidores
            # (web/console/reporter) que hacen result["data"] reventan.
            return {"success": False, "data": {}, "error": str(e)}
