"""
Bluesky Web Dashboard - Interfaz web para auditoría Bluetooth

Proporciona:
  - Dashboard con estado del sistema y hardware
  - Listado y ejecución de módulos de ataque/escaneo
  - Interfaz de escaneo en vivo
  - Historial de sesiones
  - Visor de reportes
  - API REST para integración programática

Uso:
  bluesky web [--port PORT] [--host HOST] [--debug]
  
Ejemplo:
  bluesky web --port 8080 --host 0.0.0.0
"""

from __future__ import annotations

import os
import sys
import json
import logging
import threading
import time
import webbrowser
from pathlib import Path
from typing import Dict, List, Optional, Any
from datetime import datetime, timedelta

try:
    from flask import (
        Flask, render_template, request, jsonify,
        send_file, redirect, url_for, flash, Response
    )
except ImportError:
    Flask = None

# ─── Configuración de logging ───────────────────────────────────────────────

log = logging.getLogger("bluesky.web")

# ─── Crear aplicación Flask ─────────────────────────────────────────────────

def create_app(engine=None, debug: bool = False) -> "Flask":
    """
    Crea y configura la aplicación Flask.

    Args:
        engine: Instancia de ModuleEngine (opcional)
        debug: Modo debug

    Returns:
        Flask app configurada
    """
    app = Flask(
        __name__,
        template_folder=str(Path(__file__).parent / "templates"),
        static_folder=str(Path(__file__).parent / "static"),
    )
    app.secret_key = os.urandom(24).hex()
    app.config["DEBUG"] = debug

    # ─── Estado global de la aplicación ─────────────────────────────────────
    app.state = {
        "engine": engine,
        "start_time": datetime.now(),
        "scan_in_progress": False,
        "scan_results": [],
        "last_scan_time": None,
        "web_log": [],
        "max_log_entries": 500,
    }

    # ─── Importar módulos de Bluesky ────────────────────────────────────────
    _import_bluesky(app)

    # ─── Registrar rutas ────────────────────────────────────────────────────
    _register_routes(app)

    return app


def _import_bluesky(app):
    """Importa componentes de Bluesky de forma segura."""
    try:
        from bluesky.core.engine import ModuleEngine
        if app.state["engine"] is None:
            app.state["engine"] = ModuleEngine()
        app.state["bluesky_imported"] = True
    except Exception as e:
        app.state["bluesky_imported"] = False
        app.state["bluesky_error"] = str(e)

    try:
        from bluesky.core.hardware import HardwareDetector
        app.state["hardware"] = HardwareDetector
    except Exception:
        app.state["hardware"] = None

    try:
        from bluesky.utils.platform import (
            get_platform, get_os_name, is_root, is_wsl, is_termux,
            get_available_backends,
        )
        app.state["platform_info"] = {
            "platform": get_platform(),
            "os_name": get_os_name(),
            "is_root": is_root(),
            "is_wsl": is_wsl(),
            "is_termux": is_termux(),
            "backends": get_available_backends(),
        }
    except Exception:
        app.state["platform_info"] = {"platform": "unknown", "os_name": "Unknown"}

    try:
        from bluesky.utils.config import BlueskyConfig
        app.state["config"] = BlueskyConfig.get_instance()
    except Exception:
        app.state["config"] = None

    try:
        from bluesky.core.session import SessionManager
        app.state["session_manager"] = SessionManager()
    except Exception:
        app.state["session_manager"] = None


def _register_routes(app):
    """Registra todas las rutas de la aplicación."""

    # ─── HELPERS ────────────────────────────────────────────────────────────

    def add_log(level: str, message: str):
        """Añade entrada al log web."""
        entry = {
            "time": datetime.now().strftime("%H:%M:%S"),
            "level": level,
            "message": message,
        }
        app.state["web_log"].append(entry)
        if len(app.state["web_log"]) > app.state["max_log_entries"]:
            app.state["web_log"] = app.state["web_log"][-app.state["max_log_entries"]:]
        return entry

    def get_uptime() -> str:
        """Calcula el uptime del servidor web."""
        delta = datetime.now() - app.state["start_time"]
        hours, remainder = divmod(int(delta.total_seconds()), 3600)
        minutes, seconds = divmod(remainder, 60)
        if hours > 0:
            return f"{hours}h {minutes}m {seconds}s"
        return f"{minutes}m {seconds}s"

    def get_capabilities() -> Dict:
        """Obtiene capacidades del hardware."""
        if app.state.get("hardware"):
            try:
                return app.state["hardware"].get_capabilities()
            except Exception:
                pass
        return {}

    def get_modules() -> List[Dict]:
        """Obtiene lista de módulos."""
        if app.state["engine"]:
            try:
                return app.state["engine"].list_modules()
            except Exception:
                pass
        return []

    # ─── RUTAS PRINCIPALES ──────────────────────────────────────────────────

    @app.route("/")
    def index():
        """Dashboard principal."""
        caps = get_capabilities()
        modules = get_modules()
        info = app.state.get("platform_info", {})

        # Estadísticas
        severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        target_counts = {"classic": 0, "ble": 0, "both": 0, "android": 0}
        for m in modules:
            sev = m.get("severity", "medium")
            if sev in severity_counts:
                severity_counts[sev] += 1
            ttype = m.get("target_type", "classic")
            if ttype in target_counts:
                target_counts[ttype] += 1

        return render_template("index.html",
            uptime=get_uptime(),
            caps=caps,
            modules=modules,
            info=info,
            severity_counts=severity_counts,
            target_counts=target_counts,
            modules_count=len(modules),
            scan_results=app.state["scan_results"][-10:],
            web_log=app.state["web_log"][-20:],
        )

    @app.route("/modules")
    def modules_page():
        """Página de listado de módulos."""
        modules = get_modules()
        search = request.args.get("search", "").lower()
        severity_filter = request.args.get("severity", "")
        type_filter = request.args.get("type", "")

        if search:
            modules = [m for m in modules
                      if search in m.get("name", "").lower()
                      or search in m.get("description", "").lower()]
        if severity_filter:
            modules = [m for m in modules if m.get("severity") == severity_filter]
        if type_filter:
            modules = [m for m in modules if m.get("target_type") == type_filter]

        return render_template("modules.html",
            modules=modules,
            search=search,
            severity_filter=severity_filter,
            type_filter=type_filter,
        )

    @app.route("/modules/<name>")
    def module_detail(name: str):
        """Detalle de un módulo específico."""
        cls = app.state["engine"].get_module(name) if app.state["engine"] else None
        if not cls:
            return render_template("error.html", message=f"Módulo '{name}' no encontrado"), 404

        try:
            inst = cls()
            info = inst.get_info()
            return render_template("module_detail.html",
                info=info,
                name=name,
            )
        except Exception as e:
            return render_template("error.html", message=str(e)), 500

    @app.route("/scan")
    def scan_page():
        """Página de escaneo."""
        return render_template("scan.html",
            scan_results=app.state["scan_results"],
            scan_in_progress=app.state["scan_in_progress"],
        )

    @app.route("/sessions")
    def sessions_page():
        """Página de sesiones."""
        sessions = []
        if app.state.get("session_manager"):
            try:
                sessions = app.state["session_manager"].list_sessions()
            except Exception:
                pass
        return render_template("sessions.html", sessions=sessions)

    @app.route("/reports")
    def reports_page():
        """Página de reportes."""
        reports_dir = Path("reports")
        reports = []
        if reports_dir.exists():
            for f in sorted(reports_dir.iterdir(), key=lambda x: x.stat().st_mtime, reverse=True):
                if f.suffix in (".html", ".json", ".txt"):
                    reports.append({
                        "name": f.name,
                        "path": str(f),
                        "size": f.stat().st_size,
                        "modified": datetime.fromtimestamp(f.stat().st_mtime).strftime("%Y-%m-%d %H:%M"),
                        "type": f.suffix[1:].upper(),
                    })
        return render_template("reports.html", reports=reports[:50])

    @app.route("/api")
    def api_docs():
        """Documentación de la API REST."""
        return render_template("api.html")

    @app.route("/about")
    def about_page():
        """Página Acerca de."""
        modules = get_modules()
        severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        target_counts = {"classic": 0, "ble": 0, "both": 0, "android": 0}
        for m in modules:
            sev = m.get("severity", "medium")
            if sev in severity_counts:
                severity_counts[sev] += 1
            ttype = m.get("target_type", "classic")
            if ttype in target_counts:
                target_counts[ttype] += 1

        return render_template("about.html",
            version="0.2.0",
            modules_count=len(modules),
            severity_counts=severity_counts,
            target_counts=target_counts,
        )

    @app.route("/logs")
    def logs_page():
        """Página de logs."""
        return render_template("logs.html",
            web_log=app.state["web_log"],
        )

    # ─── API REST ───────────────────────────────────────────────────────────

    @app.route("/api/status")
    def api_status():
        """Estado del sistema."""
        caps = get_capabilities()
        info = app.state.get("platform_info", {})
        modules = get_modules()
        return jsonify({
            "status": "ok",
            "uptime": get_uptime(),
            "started": app.state["start_time"].isoformat(),
            "platform": info,
            "hardware": caps,
            "modules_count": len(modules),
            "scan_in_progress": app.state["scan_in_progress"],
            "last_scan": (app.state["last_scan_time"].isoformat()
                         if app.state["last_scan_time"] else None),
            "web_log_count": len(app.state["web_log"]),
        })

    @app.route("/api/modules")
    def api_modules():
        """Lista de módulos."""
        modules = get_modules()
        return jsonify(modules)

    @app.route("/api/modules/<name>")
    def api_module_detail(name: str):
        """Detalle de un módulo."""
        cls = app.state["engine"].get_module(name) if app.state["engine"] else None
        if not cls:
            return jsonify({"error": f"Módulo '{name}' no encontrado"}), 404
        try:
            inst = cls()
            return jsonify(inst.get_info())
        except Exception as e:
            return jsonify({"error": str(e)}), 500

    @app.route("/api/modules/<name>/run", methods=["POST"])
    def api_module_run(name: str):
        """Ejecuta un módulo."""
        if not app.state["engine"]:
            return jsonify({"error": "Engine no disponible"}), 500

        data = request.get_json(silent=True) or {}
        target = data.get("target", "")
        options = data.get("options", {})

        add_log("info", f"Ejecutando módulo: {name} target={target}")

        def run_in_thread():
            app.state["scan_in_progress"] = True
            try:
                result = app.state["engine"].run_module(name, target=target, options=options)
                app.state["scan_results"].append({
                    "module": name,
                    "target": target,
                    "time": datetime.now().strftime("%H:%M:%S"),
                    "success": result.get("success", False),
                    "result": result,
                })
                app.state["last_scan_time"] = datetime.now()
                status = "✅ exitoso" if result.get("success") else "❌ falló"
                add_log("info", f"Módulo {name}: {status}")
            except Exception as e:
                add_log("error", f"Módulo {name}: {e}")
            finally:
                app.state["scan_in_progress"] = False

        thread = threading.Thread(target=run_in_thread, daemon=True)
        thread.start()

        return jsonify({
            "status": "started",
            "message": f"Módulo '{name}' iniciado",
            "module": name,
            "target": target,
        })

    @app.route("/api/scan", methods=["POST"])
    def api_scan():
        """Ejecuta escaneo de dispositivos."""
        data = request.get_json(silent=True) or {}
        scanner = data.get("scanner", "device")
        target = data.get("target", "")

        add_log("info", f"Iniciando escaneo: {scanner}")

        if not app.state["engine"]:
            return jsonify({"error": "Engine no disponible"}), 500

        def scan_thread():
            app.state["scan_in_progress"] = True
            try:
                result = app.state["engine"].run_module(
                    "scan" if scanner == "device" else "services",
                    target=target,
                )
                app.state["scan_results"].append({
                    "module": scanner,
                    "target": target or "broadcast",
                    "time": datetime.now().strftime("%H:%M:%S"),
                    "success": result.get("success", False),
                    "result": result,
                })
                app.state["last_scan_time"] = datetime.now()
                add_log("info", f"Escaneo {scanner}: {'✅ completado' if result.get('success') else '❌ falló'}")
            except Exception as e:
                add_log("error", f"Escaneo: {e}")
            finally:
                app.state["scan_in_progress"] = False

        thread = threading.Thread(target=scan_thread, daemon=True)
        thread.start()

        return jsonify({"status": "started", "message": "Escaneo iniciado"})

    @app.route("/api/scan/status")
    def api_scan_status():
        """Estado del escaneo actual."""
        return jsonify({
            "in_progress": app.state["scan_in_progress"],
            "last_scan": (app.state["last_scan_time"].isoformat()
                         if app.state["last_scan_time"] else None),
            "recent_results": app.state["scan_results"][-5:],
        })

    @app.route("/api/hardware")
    def api_hardware():
        """Información del hardware Bluetooth."""
        caps = get_capabilities()
        bt_devices = []
        if app.state.get("hardware"):
            try:
                bt_devices = app.state["hardware"].get_bluetooth_devices()
            except Exception:
                pass
        return jsonify({
            "capabilities": caps,
            "devices": bt_devices,
        })

    @app.route("/api/sessions")
    def api_sessions():
        """Lista de sesiones."""
        sessions = []
        if app.state.get("session_manager"):
            try:
                sessions = app.state["session_manager"].list_sessions()
            except Exception:
                pass
        return jsonify(sessions)

    @app.route("/api/reports")
    def api_reports():
        """Lista de reportes."""
        reports_dir = Path("reports")
        reports = []
        if reports_dir.exists():
            for f in sorted(reports_dir.iterdir(), key=lambda x: x.stat().st_mtime, reverse=True):
                if f.suffix in (".html", ".json", ".txt"):
                    try:
                        content = f.read_text(encoding="utf-8", errors="replace")[:5000]
                    except Exception:
                        content = ""
                    reports.append({
                        "name": f.name,
                        "path": str(f),
                        "size": f.stat().st_size,
                        "modified": datetime.fromtimestamp(f.stat().st_mtime).isoformat(),
                        "type": f.suffix[1:].upper(),
                        "preview": content[:500],
                    })
        return jsonify(reports[:50])

    @app.route("/api/reports/<path:filename>")
    def api_report_content(filename: str):
        """Contenido de un reporte."""
        reports_dir = Path("reports")
        filepath = reports_dir / filename
        if not filepath.exists() or not filepath.is_file():
            return jsonify({"error": "Archivo no encontrado"}), 404
        try:
            content = filepath.read_text(encoding="utf-8", errors="replace")
            return jsonify({
                "name": filename,
                "content": content,
                "type": filepath.suffix[1:].upper(),
                "size": filepath.stat().st_size,
            })
        except Exception as e:
            return jsonify({"error": str(e)}), 500

    @app.route("/api/logs")
    def api_logs():
        """Logs web."""
        since = request.args.get("since", 0, type=int)
        logs = app.state["web_log"][since:]
        return jsonify({
            "count": len(logs),
            "entries": logs,
            "total": len(app.state["web_log"]),
        })

    @app.route("/api/config")
    def api_config():
        """Configuración actual."""
        config_data = {}
        if app.state.get("config"):
            try:
                config_data = app.state["config"].get_all()
            except Exception:
                pass
        return jsonify({
            "config": config_data,
            "platform": app.state.get("platform_info", {}),
        })

    # ─── ERROR HANDLERS ────────────────────────────────────────────────────

    @app.errorhandler(404)
    def not_found(e):
        return render_template("error.html", message="Página no encontrada"), 404

    @app.errorhandler(500)
    def server_error(e):
        return render_template("error.html", message="Error interno del servidor"), 500

    # ─── LOG WEBHOOK ────────────────────────────────────────────────────────

    add_log("info", "🌐 Bluesky Web Dashboard iniciado")
    add_log("info", f"Plataforma: {app.state.get('platform_info', {}).get('os_name', 'Desconocida')}")
    add_log("info", f"Módulos cargados: {len(get_modules())}")


# ─── CLI Handler ────────────────────────────────────────────────────────────

def run_web_server(port: int = 5000, host: str = "127.0.0.1", debug: bool = False,
                   open_browser: bool = False):
    """
    Inicia el servidor web de Bluesky.

    Args:
        port: Puerto (default: 5000)
        host: Host (default: 127.0.0.1)
        debug: Modo debug
        open_browser: Abrir navegador automáticamente
    """
    if Flask is None:
        print("  ❌ Flask no está instalado.")
        print("  Instala: pip install flask")
        return

    app = create_app(debug=debug)

    url = f"http://{host}:{port}"

    print(f"""
  ╔══════════════════════════════════════════╗
  ║     🌐 Bluesky Web Dashboard              ║
  ╚══════════════════════════════════════════╝

  📡 Servidor: {url}
  📁 Reportes: {Path('reports').absolute()}
  🖥️  Plataforma: {app.state.get('platform_info', {}).get('os_name', '?')}
  📦 Módulos: {len(app.state.get('engine', app).list_modules() if hasattr(app.state.get('engine'), 'list_modules') else [])}

  Presiona Ctrl+C para detener
    """)

    if open_browser:
        webbrowser.open(url)

    try:
        app.run(host=host, port=port, debug=debug, use_reloader=False)
    except KeyboardInterrupt:
        print("\n  👋 Servidor detenido.")
    except OSError as e:
        print(f"  ❌ Error al iniciar servidor: {e}")
        if "address already in use" in str(e).lower():
            print(f"     El puerto {port} ya está en uso.")
            print(f"     Usa: bluesky web --port 8080")


if __name__ == "__main__":
    run_web_server(port=5000, debug=True)
