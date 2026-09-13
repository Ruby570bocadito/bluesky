"""
bluesky Web Dashboard - Interfaz web para auditoría Bluetooth

Diseño minimalista y profesional, 100% offline (sin CDN ni fuentes
externas) y a prueba de inyección: todo dato dinámico se renderiza en el
cliente con textContent y en el servidor con el autoescape de Jinja.

Endpoints:
  - Dashboard con estado del sistema y hardware
  - Listado, detalle (con modo educativo) y ejecución de módulos
  - Interfaz de escaneo en vivo
  - Historial de sesiones, visor de reportes y logs
  - API REST para integración programática

Uso:
  bluesky web [--port PORT] [--host HOST] [--debug]

Seguridad:
  - /api/reports/<file> valida que la ruta resuelta quede DENTRO del
    directorio reports/ (protección contra path traversal).
  - El estado mutado por hilos (logs, resultados de escaneo) se protege
    con un Lock.
"""

from __future__ import annotations

import os
import logging
import threading
import webbrowser
from pathlib import Path
from typing import Dict, List
from datetime import datetime

try:
    from flask import Flask, render_template, request, jsonify
except ImportError:
    Flask = None

# ─── Configuración de logging ───────────────────────────────────────────────

log = logging.getLogger("bluesky.web")

MAX_LOG_ENTRIES = 500
MAX_SCAN_RESULTS = 200


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

    # ─── Estado global de la aplicación (protegido con lock) ───────────────
    app.state = {
        "engine": engine,
        "start_time": datetime.now(),
        "scan_in_progress": False,
        "scan_results": [],
        "last_scan_time": None,
        "web_log": [],
        "lock": threading.Lock(),
    }

    # ─── Importar módulos de bluesky ────────────────────────────────────────
    _import_bluesky(app)

    # ─── Registrar rutas ────────────────────────────────────────────────────
    _register_routes(app)

    return app


def _import_bluesky(app):
    """Importa componentes de bluesky de forma segura."""
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
        from bluesky.utils.config import get_config
        app.state["config"] = get_config()
    except Exception:
        app.state["config"] = None

    # Session (no SessionManager: esa clase nunca existió — bug histórico
    # que dejaba /sessions y /api/sessions siempre vacíos).
    try:
        from bluesky.core.session import Session
        app.state["session_cls"] = Session
    except Exception:
        app.state["session_cls"] = None


def _register_routes(app):
    """Registra todas las rutas de la aplicación."""

    # ─── HELPERS ────────────────────────────────────────────────────────────

    def add_log(level: str, message: str):
        """Añade entrada al log web (thread-safe)."""
        entry = {
            "time": datetime.now().strftime("%H:%M:%S"),
            "level": level,
            "message": message,
        }
        with app.state["lock"]:
            app.state["web_log"].append(entry)
            if len(app.state["web_log"]) > MAX_LOG_ENTRIES:
                app.state["web_log"][:] = app.state["web_log"][-MAX_LOG_ENTRIES:]
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

    def list_saved_sessions() -> List[str]:
        """Lista las sesiones guardadas (tolera manager ausente)."""
        session_cls = app.state.get("session_cls")
        if not session_cls:
            return []
        try:
            return session_cls.list_sessions() or []
        except Exception:
            return []

    def list_reports() -> List[Dict]:
        """Lista los reportes del directorio reports/ de forma segura."""
        reports_dir = Path("reports")
        reports = []
        if reports_dir.exists():
            for f in reports_dir.iterdir():
                try:
                    if not f.is_file():
                        continue
                    if f.suffix not in (".html", ".json", ".txt"):
                        continue
                    stat = f.stat()
                    reports.append({
                        "name": f.name,
                        "path": str(f),
                        "size": stat.st_size,
                        "modified": datetime.fromtimestamp(
                            stat.st_mtime).strftime("%Y-%m-%d %H:%M"),
                        "type": f.suffix[1:].upper(),
                    })
                except OSError:
                    continue
        reports.sort(key=lambda r: r["modified"], reverse=True)
        return reports

    def severity_counts_of(modules: List[Dict]) -> Dict[str, int]:
        counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        for m in modules:
            sev = str(m.get("severity", "medium")).lower()
            if sev in counts:
                counts[sev] += 1
        return counts

    def target_counts_of(modules: List[Dict]) -> Dict[str, int]:
        counts = {"classic": 0, "ble": 0, "both": 0, "android": 0}
        for m in modules:
            ttype = str(m.get("target_type", "classic")).lower()
            if ttype in counts:
                counts[ttype] += 1
        return counts

    # ─── RUTAS PRINCIPALES ──────────────────────────────────────────────────

    @app.route("/")
    def index():
        """Dashboard principal."""
        caps = get_capabilities()
        modules = get_modules()
        info = app.state.get("platform_info", {})

        with app.state["lock"]:
            recent_results = app.state["scan_results"][-8:]
            recent_log = app.state["web_log"][-12:]

        return render_template("index.html",
            uptime=get_uptime(),
            caps=caps,
            modules=modules[:8],
            modules_total=len(modules),
            info=info,
            severity_counts=severity_counts_of(modules),
            target_counts=target_counts_of(modules),
            scan_in_progress=app.state["scan_in_progress"],
            scan_results=recent_results,
            web_log=recent_log,
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
                      if search in str(m.get("name", "")).lower()
                      or search in str(m.get("description", "")).lower()]
        if severity_filter:
            modules = [m for m in modules
                       if str(m.get("severity", "")).lower() == severity_filter]
        if type_filter:
            modules = [m for m in modules
                       if str(m.get("target_type", "")).lower() == type_filter]

        return render_template("modules.html",
            modules=modules,
            search=search,
            severity_filter=severity_filter,
            type_filter=type_filter,
            modules_total=len(get_modules()),
        )

    @app.route("/modules/<name>")
    def module_detail(name: str):
        """Detalle de un módulo específico + sección educativa."""
        cls = app.state["engine"].get_module(name) if app.state["engine"] else None
        if not cls:
            return render_template("error.html",
                message=f"Módulo '{name}' no encontrado"), 404

        try:
            inst = cls()
            info = inst.get_info()
        except Exception as e:
            return render_template("error.html", message=str(e)), 500

        # Modo educativo: explicación paso a paso del módulo (si existe)
        education = None
        try:
            from bluesky.core.education import get_education
            education = get_education(name)
        except Exception:
            education = None

        return render_template("module_detail.html",
            info=info,
            name=name,
            education=education,
        )

    @app.route("/scan")
    def scan_page():
        """Página de escaneo."""
        with app.state["lock"]:
            results = app.state["scan_results"]
        return render_template("scan.html",
            scan_results=results[-20:],
            scan_in_progress=app.state["scan_in_progress"],
        )

    @app.route("/sessions")
    def sessions_page():
        """Página de sesiones."""
        return render_template("sessions.html", sessions=list_saved_sessions())

    @app.route("/reports")
    def reports_page():
        """Página de reportes."""
        return render_template("reports.html", reports=list_reports()[:50])

    @app.route("/api")
    def api_docs():
        """Documentación de la API REST."""
        return render_template("api.html")

    @app.route("/about")
    def about_page():
        """Página Acerca de."""
        from bluesky import __version__
        modules = get_modules()
        return render_template("about.html",
            version=__version__,
            modules_count=len(modules),
            severity_counts=severity_counts_of(modules),
            target_counts=target_counts_of(modules),
        )

    @app.route("/logs")
    def logs_page():
        """Página de logs."""
        with app.state["lock"]:
            entries = list(app.state["web_log"])
        return render_template("logs.html", web_log=entries[-150:])

    # ─── API REST ───────────────────────────────────────────────────────────

    @app.route("/api/status")
    def api_status():
        """Estado del sistema."""
        caps = get_capabilities()
        info = app.state.get("platform_info", {})
        modules = get_modules()
        with app.state["lock"]:
            log_count = len(app.state["web_log"])
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
            "web_log_count": log_count,
        })

    @app.route("/api/modules")
    def api_modules():
        """Lista de módulos."""
        return jsonify(get_modules())

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

    @app.route("/api/modules/<name>/education")
    def api_module_education(name: str):
        """Contenido educativo de un módulo."""
        try:
            from bluesky.core.education import get_education
            entry = get_education(name)
        except Exception:
            entry = None
        if entry is None:
            return jsonify({"error": f"Sin contenido educativo para '{name}'"}), 404
        return jsonify(entry)

    @app.route("/api/modules/<name>/run", methods=["POST"])
    def api_module_run(name: str):
        """Ejecuta un módulo en background (thread-safe)."""
        if not app.state["engine"]:
            return jsonify({"error": "Engine no disponible"}), 500

        data = request.get_json(silent=True) or {}
        if not isinstance(data, dict):
            data = {}
        target = str(data.get("target", "") or "")
        options = data.get("options", {})
        if not isinstance(options, dict):
            options = {}

        add_log("info", f"Ejecutando módulo: {name} target={target}")

        def run_in_thread():
            with app.state["lock"]:
                if app.state["scan_in_progress"]:
                    return  # ya hay una ejecución activa
                app.state["scan_in_progress"] = True
            try:
                result = app.state["engine"].run_module(
                    name, target=target, options=options)
                with app.state["lock"]:
                    app.state["scan_results"].append({
                        "module": name,
                        "target": target,
                        "time": datetime.now().strftime("%H:%M:%S"),
                        "success": bool(result.get("success", False)),
                        "result": result,
                    })
                    if len(app.state["scan_results"]) > MAX_SCAN_RESULTS:
                        app.state["scan_results"][:] = \
                            app.state["scan_results"][-MAX_SCAN_RESULTS:]
                    app.state["last_scan_time"] = datetime.now()
                status = "exitoso" if result.get("success") else "falló"
                add_log("info", f"Módulo {name}: {status}")
            except Exception as e:
                add_log("error", f"Módulo {name}: {e}")
            finally:
                with app.state["lock"]:
                    app.state["scan_in_progress"] = False

        threading.Thread(target=run_in_thread, daemon=True).start()

        return jsonify({
            "status": "started",
            "message": f"Módulo '{name}' iniciado",
            "module": name,
            "target": target,
        })

    @app.route("/api/scan", methods=["POST"])
    def api_scan():
        """Ejecuta escaneo de dispositivos."""
        if not app.state["engine"]:
            return jsonify({"error": "Engine no disponible"}), 500

        data = request.get_json(silent=True) or {}
        if not isinstance(data, dict):
            data = {}
        scanner = str(data.get("scanner", "device") or "device")
        target = str(data.get("target", "") or "")

        with app.state["lock"]:
            if app.state["scan_in_progress"]:
                return jsonify({"status": "busy",
                                "message": "Ya hay una operación en curso"}), 409
            app.state["scan_in_progress"] = True

        add_log("info", f"Iniciando escaneo: {scanner}")

        def scan_thread():
            try:
                result = app.state["engine"].run_module(
                    "scan" if scanner == "device" else "services",
                    target=target,
                )
                with app.state["lock"]:
                    app.state["scan_results"].append({
                        "module": scanner,
                        "target": target or "broadcast",
                        "time": datetime.now().strftime("%H:%M:%S"),
                        "success": bool(result.get("success", False)),
                        "result": result,
                    })
                    app.state["last_scan_time"] = datetime.now()
                add_log("info", f"Escaneo {scanner}: "
                        f"{'completado' if result.get('success') else 'falló'}")
            except Exception as e:
                add_log("error", f"Escaneo: {e}")
            finally:
                with app.state["lock"]:
                    app.state["scan_in_progress"] = False

        threading.Thread(target=scan_thread, daemon=True).start()

        return jsonify({"status": "started", "message": "Escaneo iniciado"})

    @app.route("/api/scan/status")
    def api_scan_status():
        """Estado del escaneo actual."""
        with app.state["lock"]:
            recent = list(app.state["scan_results"][-5:])
        return jsonify({
            "in_progress": app.state["scan_in_progress"],
            "last_scan": (app.state["last_scan_time"].isoformat()
                         if app.state["last_scan_time"] else None),
            "recent_results": recent,
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
        return jsonify(list_saved_sessions())

    @app.route("/api/reports")
    def api_reports():
        """Lista de reportes."""
        reports = []
        for r in list_reports()[:50]:
            r = dict(r)
            r["preview"] = ""
            try:
                content = Path(r["path"]).read_text(
                    encoding="utf-8", errors="replace")[:500]
                r["preview"] = content
            except OSError:
                pass
            reports.append(r)
        return jsonify(reports)

    @app.route("/api/reports/<path:filename>")
    def api_report_content(filename: str):
        """Contenido de un reporte (protegido contra path traversal)."""
        reports_dir = Path("reports").resolve()
        filepath = (reports_dir / filename).resolve()
        # La ruta resuelta DEBE quedar dentro de reports/ — sin esta
        # comprobación, /api/reports/../../etc/passwd leía archivos
        # arbitrarios del sistema.
        if reports_dir not in filepath.parents or not filepath.is_file():
            return jsonify({"error": "Archivo no encontrado"}), 404
        try:
            content = filepath.read_text(encoding="utf-8", errors="replace")
            return jsonify({
                "name": filepath.name,
                "content": content,
                "type": filepath.suffix[1:].upper(),
                "size": filepath.stat().st_size,
            })
        except OSError as e:
            return jsonify({"error": str(e)}), 500

    @app.route("/api/logs")
    def api_logs():
        """Logs web."""
        since = request.args.get("since", 0, type=int)
        with app.state["lock"]:
            logs = list(app.state["web_log"])
        entries = logs[max(0, since):]
        return jsonify({
            "count": len(entries),
            "entries": entries,
            "total": len(logs),
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

    # ─── LOG INICIAL ────────────────────────────────────────────────────────

    add_log("info", "bluesky Web Dashboard iniciado")
    add_log("info", f"Plataforma: "
            f"{app.state.get('platform_info', {}).get('os_name', 'Desconocida')}")
    add_log("info", f"Módulos cargados: {len(get_modules())}")


# ─── CLI Handler ────────────────────────────────────────────────────────────

def run_web_server(port: int = 5000, host: str = "127.0.0.1", debug: bool = False,
                   open_browser: bool = False):
    """
    Inicia el servidor web de bluesky.

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

    reports_dir = Path("reports")
    reports_dir.mkdir(exist_ok=True)

    url = f"http://{host}:{port}"
    modules_count = 0
    if app.state.get("engine"):
        try:
            modules_count = len(app.state["engine"].list_modules())
        except Exception:
            pass

    print(f"""
  ╔══════════════════════════════════════════╗
  ║     🌐 bluesky Web Dashboard              ║
  ╚══════════════════════════════════════════╝

  📡 Servidor: {url}
  📁 Reportes: {reports_dir.absolute()}
  🖥️  Plataforma: {app.state.get('platform_info', {}).get('os_name', '?')}
  📦 Módulos: {modules_count}

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
            print("     Usa: bluesky web --port 8080")


if __name__ == "__main__":
    # debug=True por defecto en el __main__ era peligroso: el debugger
    # interactiva de Werkzeug permite ejecutar código Python arbitrario
    # desde el navegador si la app está accesible (incluso en 127.0.0.1,
    # cualquier web maliciosa con un payload POST al /console puede pwnear).
    # El modo debug debe ser opt-in explícito.
    import argparse
    parser = argparse.ArgumentParser(description="bluesky Web Dashboard")
    parser.add_argument("--port", type=int, default=5000)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--debug", action="store_true",
                        help="Habilitar modo debug de Flask (NO usar en producción)")
    parser.add_argument("--open", dest="open_browser", action="store_true")
    args = parser.parse_args()
    run_web_server(
        port=args.port,
        host=args.host,
        debug=args.debug,  # antes era True hardcoded
        open_browser=args.open_browser,
    )
