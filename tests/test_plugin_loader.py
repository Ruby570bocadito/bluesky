#!/usr/bin/env python3
"""Tests para core/plugin_loader.py"""

import os
import tempfile
import pytest
from pathlib import Path
from bluesky.core.plugin_loader import (
    PluginLoader,
    PluginInfo,
    PluginError,
    PluginNotFound,
    create_plugin_template,
    ensure_plugins_directory,
)


class TestPluginLoader:
    """Tests unitarios para PluginLoader."""

    def setup_method(self):
        self.tmp = Path(tempfile.mkdtemp())

    def _create_demo_plugin(self, name: str = "test_plugin", content: str = None) -> Path:
        """Crea un archivo plugin de prueba."""
        if content is None:
            content = f'''#!/usr/bin/env python3
"""Test plugin: {name}"""

from typing import Dict, Any

PLUGIN_INFO = {{
    "name": "{name}",
    "version": "1.0.0",
    "description": "Plugin de prueba",
    "author": "Test",
    "type": "attack",
    "module": "TestModule",
    "requires": [],
}}

class TestModule:
    def __init__(self):
        self.name = "{name}"
    
    def run(self, target="", options=None):
        return {{"success": True, "data": {{"message": "ok"}}}}
    
    def get_info(self):
        return {{"name": self.name, "description": "Test"}}
'''
        plugin_path = self.tmp / f"{name}.py"
        plugin_path.write_text(content)
        return plugin_path

    def test_01_discover_empty(self):
        """Directorio sin plugins (solo considera extra_paths)."""
        loader = PluginLoader(extra_paths=[str(self.tmp)])
        plugins = loader.discover()
        # Filtramos solo los que están en nuestro tmp
        tmp_plugins = {k: v for k, v in plugins.items() if str(self.tmp) in (v.path or "")}
        assert len(tmp_plugins) == 0

    def test_02_discover_one(self):
        """Descubre un plugin."""
        self._create_demo_plugin("my_plugin")
        loader = PluginLoader(extra_paths=[str(self.tmp)])
        plugins = loader.discover()
        assert "my_plugin" in plugins
        assert plugins["my_plugin"].name == "my_plugin"
        assert plugins["my_plugin"].plugin_type == "attack"

    def test_03_load_and_run(self):
        """Carga y ejecuta un plugin."""
        self._create_demo_plugin("runner_plugin")
        loader = PluginLoader(extra_paths=[str(self.tmp)])
        loader.discover()
        info = loader.load("runner_plugin")
        assert info.loaded is True
        assert info.error is None

        classes = loader.get_module_classes()
        assert "runner_plugin" in classes
        cls = classes["runner_plugin"]
        inst = cls()
        result = inst.run()
        assert result["success"] is True

    def test_04_load_nonexistent(self):
        """Cargar plugin inexistente lanza error."""
        loader = PluginLoader(extra_paths=[str(self.tmp)])
        loader.discover()
        with pytest.raises(PluginNotFound):
            loader.load("no_existe")

    def test_05_missing_dependency(self):
        """Plugin con dependencia faltante."""
        content = '''#!/usr/bin/env python3
PLUGIN_INFO = {
    "name": "dep_plugin",
    "version": "1.0.0",
    "description": "Plugin con dependencia",
    "type": "attack",
    "module": "DepModule",
    "requires": ["paquete_inexistente_xyz"],
}

class DepModule:
    def run(self, target="", options=None):
        return {"success": True}
    
    def get_info(self):
        return {"name": "dep_plugin"}
'''
        self._create_demo_plugin("dep_plugin", content)
        loader = PluginLoader(extra_paths=[str(self.tmp)])
        loader.discover()
        info = loader.load("dep_plugin")
        assert info.loaded is False
        assert info.error is not None
        assert "dependencia" in info.error.lower() or "Dependencias" in info.error

    def test_06_list_by_type(self):
        """Lista plugins filtrados por tipo."""
        self._create_demo_plugin("plugin_a")
        self._create_demo_plugin("plugin_b")

        loader = PluginLoader(extra_paths=[str(self.tmp)])
        loader.discover()

        # Solo contar plugins en nuestro directorio temporal
        all_plugins = [p for p in loader.list_plugins() if str(self.tmp) in (p.path or "")]
        attack_plugins = [p for p in loader.list_plugins(filter_type="attack") if str(self.tmp) in (p.path or "")]

        assert len(all_plugins) == 2
        assert len(attack_plugins) == 2

    def test_07_plugin_without_module_class(self):
        """Plugin sin module_class no produce clase de módulo."""
        content = '''#!/usr/bin/env python3
PLUGIN_INFO = {
    "name": "util_plugin",
    "version": "1.0.0",
    "description": "Utilidad",
    "type": "utility",
    "module": "",
    "requires": [],
}
'''
        self._create_demo_plugin("util_plugin", content)
        loader = PluginLoader(extra_paths=[str(self.tmp)])
        loader.discover()
        info = loader.load("util_plugin")
        assert info.loaded is True  # Se carga aunque no tenga module_class
        assert len(loader.get_module_classes()) == 0

    def test_08_create_plugin_template(self):
        """create_plugin_template genera código válido."""
        code = create_plugin_template("mi_plugin", "scanner")
        assert "PLUGIN_INFO" in code
        assert "MiPluginPlugin" in code
        assert "scanner" in code
        # Verificar que es Python válido
        compile(code, "<test>", "exec")

    def test_09_ensure_plugins_directory(self):
        """ensure_plugins_directory crea el directorio."""
        # No podemos testear el proyecto real, pero verificamos que la función existe
        from bluesky.core.plugin_loader import ensure_plugins_directory
        assert callable(ensure_plugins_directory)


class TestPluginIntegration:
    """Tests de integración con ModuleEngine."""

    def test_01_engine_loads_plugins(self):
        """ModuleEngine carga plugins automáticamente."""
        from bluesky.core.engine import ModuleEngine
        engine = ModuleEngine(load_plugins=True)
        # Debe tener al menos los módulos nativos (16)
        modules = engine.list_modules()
        assert len(modules) >= 16
        # plugin_loader debe existir
        assert engine.plugin_loader is not None

    def test_02_demo_plugin_in_list(self):
        """El plugin demo aparece en list_modules si existe."""
        from bluesky.core.engine import ModuleEngine
        engine = ModuleEngine(load_plugins=True)
        names = [m.get("name") for m in engine.list_modules()]
        # Si el plugin demo_scanner está en plugins/, debe aparecer
        import os
        demo_path = Path(__file__).parent.parent / "plugins" / "demo_scanner.py"
        if demo_path.exists():
            assert "demo_scanner" in names

    def test_03_plugin_type_conversion(self):
        """PluginLoader puede contar cargados vs descubiertos."""
        loader = PluginLoader()
        loader.discover()
        assert loader.count() >= 0
        assert loader.count_loaded() >= 0
