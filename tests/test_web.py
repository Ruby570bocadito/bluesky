"""
Tests para el Web Dashboard de Bluesky.
"""
import os
import sys
import json
import pytest
from unittest.mock import patch, MagicMock

# Asegurar que el proyecto está en sys.path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))


@pytest.fixture(scope="module")
def app():
    """Crea la app Flask para testing."""
    from bluesky.web.app import create_app
    application = create_app()
    application.config.update({
        "TESTING": True,
    })
    yield application


@pytest.fixture
def client(app):
    """Cliente de prueba Flask."""
    return app.test_client()


class TestWebRoutes:
    """Tests de rutas del dashboard web."""

    def test_index_route(self, client):
        """GET / -> 200, dashboard renderizado."""
        rv = client.get("/")
        assert rv.status_code == 200, f"Status: {rv.status_code}"
        assert b"Bluesky" in rv.data or b"bluesky" in rv.data.lower()

    def test_modules_route(self, client):
        """GET /modules -> 200, lista de módulos."""
        rv = client.get("/modules")
        assert rv.status_code == 200

    def test_scan_route(self, client):
        """GET /scan -> 200, página de escaneo."""
        rv = client.get("/scan")
        assert rv.status_code == 200

    def test_sessions_route(self, client):
        """GET /sessions -> 200, página de sesiones."""
        rv = client.get("/sessions")
        assert rv.status_code == 200

    def test_reports_route(self, client):
        """GET /reports -> 200, página de reportes."""
        rv = client.get("/reports")
        assert rv.status_code == 200

    def test_logs_route(self, client):
        """GET /logs -> 200, página de logs."""
        rv = client.get("/logs")
        assert rv.status_code == 200

    def test_api_docs_route(self, client):
        """GET /api -> 200, documentación API."""
        rv = client.get("/api")
        assert rv.status_code == 200

    def test_module_detail_route(self, client):
        """GET /modules/<name> -> 200 o 404."""
        rv = client.get("/modules/knob")
        assert rv.status_code in (200, 404)

    def test_module_detail_404(self, client):
        """GET /modules/nonexistent -> 404."""
        rv = client.get("/modules/this_module_does_not_exist_xyz")
        assert rv.status_code == 404

    def test_not_found_page(self, client):
        """GET /nonexistent -> 404."""
        rv = client.get("/this_path_does_not_exist_12345")
        assert rv.status_code == 404


class TestApiEndpoints:
    """Tests de la API REST."""

    def test_api_status(self, client):
        """GET /api/status -> JSON con estado del sistema."""
        rv = client.get("/api/status")
        assert rv.status_code == 200
        data = json.loads(rv.data)
        assert "status" in data
        assert "uptime" in data
        assert "hardware" in data

    def test_api_modules(self, client):
        """GET /api/modules -> JSON con lista de módulos."""
        rv = client.get("/api/modules")
        assert rv.status_code == 200
        data = json.loads(rv.data)
        # Returns array directly (jsonify(list))
        assert isinstance(data, list)

    def test_api_module_info_exists(self, client):
        """GET /api/modules/knob -> 200 si existe."""
        rv = client.get("/api/modules/knob")
        if rv.status_code == 200:
            data = json.loads(rv.data)
            assert "name" in data
        else:
            assert rv.status_code == 404

    def test_api_module_not_found(self, client):
        """GET /api/modules/nonexistent -> 404."""
        rv = client.get("/api/modules/this_module_does_not_exist_xyz")
        assert rv.status_code == 404
        data = json.loads(rv.data)
        assert "error" in data

    def test_api_hardware(self, client):
        """GET /api/hardware -> JSON con info de hardware."""
        rv = client.get("/api/hardware")
        assert rv.status_code == 200
        data = json.loads(rv.data)
        # Puede tener "capabilities" o "devices"
        assert isinstance(data, dict)

    def test_api_sessions(self, client):
        """GET /api/sessions -> JSON con sesiones."""
        rv = client.get("/api/sessions")
        assert rv.status_code == 200
        data = json.loads(rv.data)
        assert isinstance(data, list)

    def test_api_reports(self, client):
        """GET /api/reports -> JSON con reportes."""
        rv = client.get("/api/reports")
        assert rv.status_code == 200
        data = json.loads(rv.data)
        assert isinstance(data, list)

    def test_api_logs(self, client):
        """GET /api/logs -> JSON con logs."""
        rv = client.get("/api/logs")
        assert rv.status_code == 200
        data = json.loads(rv.data)
        assert "entries" in data

    def test_api_logs_since_filter(self, client):
        """GET /api/logs?since=N -> filtro correcto."""
        rv = client.get("/api/logs?since=0")
        assert rv.status_code == 200
        data = json.loads(rv.data)
        assert "entries" in data

    def test_api_config(self, client):
        """GET /api/config -> JSON con configuración."""
        rv = client.get("/api/config")
        assert rv.status_code == 200
        data = json.loads(rv.data)
        assert isinstance(data, dict)

    def test_api_report_content_not_found(self, client):
        """GET /api/reports/<file> -> 404 si no existe."""
        rv = client.get("/api/reports/nonexistent_file.html")
        assert rv.status_code == 404
        data = json.loads(rv.data)
        assert "error" in data

    def test_api_run_module_start(self, client):
        """POST /api/modules/status/run -> 200, módulo inicia."""
        rv = client.post("/api/modules/status/run",
                         data=json.dumps({"target": "", "options": {}}),
                         content_type="application/json")
        assert rv.status_code == 200
        data = json.loads(rv.data)
        assert "status" in data

    def test_api_run_module_not_found(self, client):
        """POST /api/modules/nonexistent/run -> 500 (engine.run_module falla)."""
        rv = client.post("/api/modules/this_module_does_not_exist_xyz/run",
                         data=json.dumps({"target": ""}),
                         content_type="application/json")
        # Engine devuelve resultado con error, o 500 si engine no tiene módulo
        data = json.loads(rv.data)
        assert "status" in data or "error" in data

    def test_api_scan_start(self, client):
        """POST /api/scan -> inicio de escaneo."""
        rv = client.post("/api/scan",
                         data=json.dumps({"scanner": "device", "target": ""}),
                         content_type="application/json")
        assert rv.status_code == 200
        data = json.loads(rv.data)
        assert "status" in data

    def test_api_scan_status(self, client):
        """GET /api/scan/status -> estado del escaneo."""
        rv = client.get("/api/scan/status")
        assert rv.status_code == 200
        data = json.loads(rv.data)
        assert "in_progress" in data

    def test_api_post_no_json_no_crash(self, client):
        """POST sin JSON -> no debe crashear."""
        rv = client.post("/api/scan",
                         data="not json",
                         content_type="text/plain")
        # get_json(silent=True) devuelve None, se usa {} por defecto
        assert rv.status_code == 200


class TestWebCLICommand:
    """Tests del comando CLI 'web'."""

    @patch("bluesky.web.app.run_web_server")
    def test_cmd_web_default_args(self, mock_run):
        """web() con args por defecto -> 127.0.0.1:5000."""
        from bluesky.cli import cmd_web
        cmd_web([])
        mock_run.assert_called_once_with(
            port=5000,
            host="127.0.0.1",
            debug=False,
            open_browser=False,
        )

    @patch("bluesky.web.app.run_web_server")
    def test_cmd_web_custom_port(self, mock_run):
        """web() con --port -> puerto personalizado."""
        from bluesky.cli import cmd_web
        cmd_web(["--port", "8080"])
        mock_run.assert_called_once_with(
            port=8080,
            host="127.0.0.1",
            debug=False,
            open_browser=False,
        )

    @patch("bluesky.web.app.run_web_server")
    def test_cmd_web_custom_host(self, mock_run):
        """web() con --host -> host personalizado."""
        from bluesky.cli import cmd_web
        cmd_web(["--host", "0.0.0.0"])
        mock_run.assert_called_once_with(
            port=5000,
            host="0.0.0.0",
            debug=False,
            open_browser=False,
        )

    @patch("bluesky.web.app.run_web_server")
    def test_cmd_web_debug(self, mock_run):
        """web() con --debug -> debug=True."""
        from bluesky.cli import cmd_web
        cmd_web(["--debug"])
        mock_run.assert_called_once_with(
            port=5000,
            host="127.0.0.1",
            debug=True,
            open_browser=False,
        )

    @patch("bluesky.web.app.run_web_server")
    def test_cmd_web_open(self, mock_run):
        """web() con --open -> open_browser=True."""
        from bluesky.cli import cmd_web
        cmd_web(["--open"])
        mock_run.assert_called_once_with(
            port=5000,
            host="127.0.0.1",
            debug=False,
            open_browser=True,
        )

    @patch("bluesky.web.app.run_web_server")
    def test_cmd_web_all_args(self, mock_run):
        """web() con todos los args."""
        from bluesky.cli import cmd_web
        cmd_web(["-p", "3000", "-H", "0.0.0.0", "--debug", "--open"])
        mock_run.assert_called_once_with(
            port=3000,
            host="0.0.0.0",
            debug=True,
            open_browser=True,
        )

    def test_cmd_web_no_flask(self):
        """web() sin Flask instalado -> mensaje de error."""
        with patch("bluesky.web.app.run_web_server", side_effect=ImportError("No module named flask")):
            from bluesky.cli import cmd_web
            # No debe lanzar excepción, debe imprimir error
            try:
                cmd_web([])
            except Exception:
                pytest.fail("cmd_web no debe lanzar excepción con ImportError")
