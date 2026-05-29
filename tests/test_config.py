#!/usr/bin/env python3
"""Tests para utils/config.py"""

import json
import os
import tempfile
import pytest
from pathlib import Path
from bluesky.utils.config import (
    BlueskyConfig,
    get_config,
    parse_key_value,
    ConfigError,
    ConfigValidationError,
    DEFAULT_CONFIG,
)


class TestBlueskyConfig:
    """Tests unitarios para BlueskyConfig."""

    def setup_method(self):
        """Reinicia singleton antes de cada test."""
        BlueskyConfig.reset_instance()
        self.tmp = tempfile.mkdtemp()

    def test_01_default_values(self):
        """Valores por defecto sin archivo de config."""
        cfg = BlueskyConfig()
        # Forzar ruta inexistente
        cfg.load("/nonexistent/bluesky.json")
        assert cfg.get("general.theme") == "auto"
        assert cfg.get("general.log_level") == "info"
        assert cfg.get("general.safe_mode") is True
        assert cfg.get("general.timeout") == 30
        assert cfg.get("favorites") == []
        assert cfg.get("module_options") == {}

    def test_02_load_from_file(self):
        """Carga correcta desde archivo JSON."""
        config_data = {
            "general": {
                "theme": "dark",
                "log_level": "debug",
                "timeout": 60,
            },
            "favorites": [
                {"address": "AA:BB:CC:DD:EE:FF", "name": "Test", "type": "classic"}
            ],
        }
        config_path = os.path.join(self.tmp, "bluesky.json")
        with open(config_path, "w") as f:
            json.dump(config_data, f)

        cfg = BlueskyConfig()
        cfg.load(config_path)
        assert cfg.get("general.theme") == "dark"
        assert cfg.get("general.log_level") == "debug"
        assert cfg.get("general.timeout") == 60
        assert cfg.get("general.safe_mode") is True  # default preserved
        assert len(cfg.get("favorites")) == 1

    def test_03_save_and_reload(self):
        """Guardar y recargar preserva valores."""
        cfg = BlueskyConfig()
        cfg.load(os.path.join(self.tmp, "bluesky.json"))
        cfg.set("general.theme", "light")
        cfg.set("general.timeout", 120)
        cfg.add_favorite("11:22:33:44:55:66", "Phone", "ble")
        assert cfg.is_dirty() is True
        cfg.save()

        # Recargar con nueva instancia
        BlueskyConfig.reset_instance()
        cfg2 = BlueskyConfig()
        cfg2.load(os.path.join(self.tmp, "bluesky.json"))
        assert cfg2.get("general.theme") == "light"
        assert cfg2.get("general.timeout") == 120
        assert len(cfg2.get("favorites")) == 1
        assert cfg2.get("favorites")[0]["address"] == "11:22:33:44:55:66"

    def test_04_get_set_module_option(self):
        """Opciones de módulo funcionan."""
        cfg = BlueskyConfig()
        cfg.load(os.path.join(self.tmp, "bluesky.json"))

        cfg.set_module_option("knob", "timeout", 90)
        cfg.set_module_option("knob", "force", True)
        assert cfg.get_module_option("knob", "timeout") == 90
        assert cfg.get_module_option("knob", "force") is True
        assert cfg.get_module_option("knob", "nonexistent", "default") == "default"
        assert cfg.get_module_option("unknown", "key") is None

    def test_05_favorites(self):
        """Gestión de favoritos."""
        cfg = BlueskyConfig()
        cfg.load(os.path.join(self.tmp, "bluesky.json"))

        cfg.add_favorite("AA:BB:CC:DD:EE:FF", "Device1", "classic")
        cfg.add_favorite("11:22:33:44:55:66", "Device2", "ble")
        assert len(cfg.get("favorites")) == 2

        # No duplicados
        cfg.add_favorite("AA:BB:CC:DD:EE:FF", "Device1 Updated", "classic")
        assert len(cfg.get("favorites")) == 2

        # Remover
        cfg.remove_favorite("11:22:33:44:55:66")
        assert len(cfg.get("favorites")) == 1
        assert cfg.get("favorites")[0]["address"] == "AA:BB:CC:DD:EE:FF"

    def test_06_validation_error(self):
        """Tipo incorrecto lanza error de validación."""
        config_data = {"general": {"timeout": "treinta"}}
        config_path = os.path.join(self.tmp, "bad_types.json")
        with open(config_path, "w") as f:
            json.dump(config_data, f)

        cfg = BlueskyConfig()
        with pytest.raises(ConfigValidationError):
            cfg.load(config_path)

    def test_07_validation_log_level(self):
        """Log level inválido lanza error."""
        config_data = {"general": {"log_level": "superdebug"}}
        config_path = os.path.join(self.tmp, "bad_loglevel.json")
        with open(config_path, "w") as f:
            json.dump(config_data, f)

        cfg = BlueskyConfig()
        with pytest.raises(ConfigValidationError):
            cfg.load(config_path)

    def test_08_invalid_json(self):
        """JSON malformado lanza ConfigError."""
        config_path = os.path.join(self.tmp, "invalid.json")
        with open(config_path, "w") as f:
            f.write("{not json}")

        cfg = BlueskyConfig()
        with pytest.raises(ConfigError):
            cfg.load(config_path)

    def test_09_get_all(self):
        """get_all retorna copia completa."""
        cfg = BlueskyConfig()
        cfg.load(os.path.join(self.tmp, "bluesky.json"))
        all_cfg = cfg.get_all()
        assert isinstance(all_cfg, dict)
        assert "general" in all_cfg
        assert "favorites" in all_cfg

        # Es una copia, no el original
        all_cfg["general"]["timeout"] = 999
        assert cfg.get("general.timeout") != 999

    def test_10_reset(self):
        """reset_to_defaults restaura valores por defecto."""
        cfg = BlueskyConfig()
        cfg.load(os.path.join(self.tmp, "bluesky.json"))
        cfg.set("general.theme", "light")
        cfg.reset_to_defaults()
        assert cfg.get("general.theme") == "auto"
        assert cfg.is_dirty() is True

    def test_11_export_summary(self):
        """export_summary retorna string."""
        cfg = BlueskyConfig()
        cfg.load(os.path.join(self.tmp, "bluesky.json"))
        summary = cfg.export_summary()
        assert isinstance(summary, str)
        assert "Bluesky Config Summary" in summary

    def test_12_parse_key_value(self):
        """parse_key_value interpreta tipos correctamente."""
        k, v = parse_key_value("timeout=60")
        assert k == "timeout"
        assert v == 60
        assert type(v) is int

        k, v = parse_key_value("safe_mode=true")
        assert v is True

        k, v = parse_key_value("safe_mode=false")
        assert v is False

        k, v = parse_key_value("name=test")
        assert v == "test"

        k, v = parse_key_value("rate=3.14")
        assert v == 3.14
        assert type(v) is float

        with pytest.raises(ValueError):
            parse_key_value("invalid")

    def test_13_get_config_helper(self):
        """get_config() retorna singleton cargada."""
        BlueskyConfig.reset_instance()
        cfg = get_config()
        assert isinstance(cfg, BlueskyConfig)
        assert cfg.get("general.timeout") == 30

        # Es singleton
        cfg2 = get_config()
        assert cfg is cfg2

    def test_14_singleton_behavior(self):
        """Dos instancias con new() son la misma."""
        a = BlueskyConfig()
        b = BlueskyConfig()
        assert a is b

    def test_15_default_target_type_validation(self):
        """Tipo inválido en default_target lanza error."""
        config_data = {"default_target": {"type": "wifi"}}
        config_path = os.path.join(self.tmp, "bad_target_type.json")
        with open(config_path, "w") as f:
            json.dump(config_data, f)

        cfg = BlueskyConfig()
        with pytest.raises(ConfigValidationError):
            cfg.load(config_path)


class TestConfigIntegration:
    """Tests de integración del sistema de configuración."""

    def test_01_module_merge_deep(self):
        """Merge profundo no pierde defaults."""
        config_data = {
            "scanner": {
                "active_scan": True,
            }
        }
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump(config_data, f)
            tmp_path = f.name

        BlueskyConfig.reset_instance()
        cfg = BlueskyConfig()
        cfg.load(tmp_path)
        assert cfg.get("scanner.active_scan") is True
        assert cfg.get("scanner.classic_inquiry") is True  # default preserved
        assert cfg.get("scanner.scan_duration") == 10  # default preserved
        os.unlink(tmp_path)

    def test_02_path_precedence(self):
        """La ruta explícita tiene prioridad."""
        BlueskyConfig.reset_instance()
        # Crear config en temp
        config_data = {"general": {"theme": "dark"}}
        config_path = os.path.join(tempfile.mkdtemp(), "bluesky.json")
        with open(config_path, "w") as f:
            json.dump(config_data, f)

        cfg = BlueskyConfig()
        cfg.load(config_path)
        assert cfg.get("general.theme") == "dark"

    def test_03_save_without_path(self):
        """save() sin path previo usa directorio temporal."""
        BlueskyConfig.reset_instance()
        tmp_dir = tempfile.mkdtemp()
        # Forzar un path que no existe para que use el path cargado
        config_path = os.path.join(tmp_dir, "myconfig.json")
        cfg = BlueskyConfig()
        cfg.load(config_path)
        cfg.set("general.theme", "dark")
        cfg.save()
        assert os.path.exists(config_path)
        # Verificar contenido
        with open(config_path) as f:
            data = json.load(f)
        assert data["general"]["theme"] == "dark"
        os.unlink(config_path)
        os.rmdir(tmp_dir)
