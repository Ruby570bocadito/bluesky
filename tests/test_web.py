"""
Tests para el Web Dashboard de bluesky.
"""
import os
import sys
import json
import pytest
from unittest.mock import patch

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
        assert b"bluesky" in rv.data.lower()

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


class TestScanApiOptions:
    """POST /api/scan con opciones de escaneo (modo, timeout, validación)."""

    class _FakeEngine:
        """Engine determinista para probar el endpoint sin hardware."""

        calls = []

        def list_modules(self):
            return []

        def run_module(self, name, target="", options=None):
            TestScanApiOptions._FakeEngine.calls.append((name, target, options))
            return {
                "success": True,
                "data": {"devices": [{
                    "mac": "B8:27:EB:12:34:56", "name": "pi", "type": "classic",
                    "vendor": "Raspberry Pi Trading", "rssi": -50,
                }]},
                "error": None,
            }

    @pytest.fixture(autouse=True)
    def _fake_engine(self, app):
        """Sustituye el engine real durante cada test y lo restaura."""
        original = app.state["engine"]
        TestScanApiOptions._FakeEngine.calls = []
        app.state["engine"] = TestScanApiOptions._FakeEngine()
        with app.state["lock"]:
            app.state["scan_results"] = []
            app.state["scan_in_progress"] = False
        yield
        app.state["engine"] = original
        with app.state["lock"]:
            app.state["scan_in_progress"] = False

    def _wait_scan_done(self, app, timeout=2.0):
        import time
        deadline = time.time() + timeout
        while time.time() < deadline:
            with app.state["lock"]:
                if not app.state["scan_in_progress"]:
                    return True
            time.sleep(0.02)
        return False

    def test_scan_con_modo_y_timeout(self, app, client):
        """POST /api/scan {type: ble, timeout: 12} -> options llegan al engine."""
        rv = client.post("/api/scan",
                         data=json.dumps({"scanner": "device", "type": "ble",
                                          "timeout": 12}),
                         content_type="application/json")
        assert rv.status_code == 200
        assert self._wait_scan_done(app)
        name, target, options = self._FakeEngine.calls[-1]
        assert name == "scan"
        assert options == {"type": "ble", "timeout": "12"}

    def test_scan_sin_opciones_usa_defaults(self, app, client):
        """POST /api/scan sin type/timeout -> options solo con type=all."""
        rv = client.post("/api/scan", data=json.dumps({"scanner": "device"}),
                         content_type="application/json")
        assert rv.status_code == 200
        assert self._wait_scan_done(app)
        name, _, options = self._FakeEngine.calls[-1]
        assert options == {"type": "all"}

    def test_scan_tipo_invalido_400(self, client):
        rv = client.post("/api/scan",
                         data=json.dumps({"scanner": "device", "type": "wifi"}),
                         content_type="application/json")
        assert rv.status_code == 400
        data = json.loads(rv.data)
        assert "error" in data

    def test_scan_timeout_no_numerico_400(self, client):
        rv = client.post("/api/scan",
                         data=json.dumps({"scanner": "device", "timeout": "abc"}),
                         content_type="application/json")
        assert rv.status_code == 400

    def test_scan_timeout_fuera_de_rango_400(self, client):
        rv = client.post("/api/scan",
                         data=json.dumps({"scanner": "device", "timeout": 999}),
                         content_type="application/json")
        assert rv.status_code == 400

    def test_scan_timeout_negativo_400(self, client):
        rv = client.post("/api/scan",
                         data=json.dumps({"scanner": "device", "timeout": 0}),
                         content_type="application/json")
        assert rv.status_code == 400

    def test_scanner_invalido_400(self, client):
        rv = client.post("/api/scan",
                         data=json.dumps({"scanner": "brute-force"}),
                         content_type="application/json")
        assert rv.status_code == 400

    def test_services_sin_target_400(self, client):
        """El escáner de servicios exige MAC: sin ella, error 400 (no crash)."""
        rv = client.post("/api/scan",
                         data=json.dumps({"scanner": "services", "target": ""}),
                         content_type="application/json")
        assert rv.status_code == 400
        data = json.loads(rv.data)
        assert "message" in data

    def test_services_con_target_pasa_options_vacias(self, app, client):
        rv = client.post("/api/scan",
                         data=json.dumps({"scanner": "services",
                                          "target": "AA:BB:CC:DD:EE:FF"}),
                         content_type="application/json")
        assert rv.status_code == 200
        assert self._wait_scan_done(app)
        name, target, options = self._FakeEngine.calls[-1]
        assert name == "services"
        assert target == "AA:BB:CC:DD:EE:FF"
        assert options == {}

    def test_scan_resultado_con_dispositivos(self, app, client):
        """El estado expone los dispositivos descubiertos (para la web)."""
        client.post("/api/scan", data=json.dumps({"scanner": "device"}),
                    content_type="application/json")
        assert self._wait_scan_done(app)
        rv = client.get("/api/scan/status")
        data = json.loads(rv.data)
        found = False
        for r in data["recent_results"]:
            devices = (r.get("result") or {}).get("data", {}).get("devices", [])
            if devices:
                found = True
                assert devices[0]["vendor"] == "Raspberry Pi Trading"
        assert found, "los dispositivos deben viajar en el resultado"


class TestScanExport:
    """GET /api/scan/export -> CSV de los dispositivos del último escaneo."""

    def test_export_sin_datos_404(self, app, client):
        with app.state["lock"]:
            app.state["scan_results"] = []
        rv = client.get("/api/scan/export")
        assert rv.status_code == 404
        data = json.loads(rv.data)
        assert "error" in data

    def test_export_con_dispositivos_csv(self, app, client):
        with app.state["lock"]:
            app.state["scan_results"] = [{
                "module": "device", "target": "broadcast", "time": "10:00:00",
                "success": True,
                "result": {"success": True, "data": {"devices": [
                    {"mac": "B8:27:EB:12:34:56", "name": "pi", "type": "classic",
                     "vendor": "Raspberry Pi Trading", "rssi": -50},
                    {"mac": "00:1A:7D:99:88:77", "name": "csr", "type": "ble"},
                ]}, "error": None},
            }]
        try:
            rv = client.get("/api/scan/export")
            assert rv.status_code == 200
            assert rv.mimetype == "text/csv"
            assert "attachment" in rv.headers.get("Content-Disposition", "")
            assert b"bluesky_devices.csv" in rv.headers.get(
                "Content-Disposition", "").encode()
            body = rv.data.decode("utf-8")
            assert body.startswith("mac,name,type,vendor,rssi,paired")
            assert "B8:27:EB:12:34:56" in body
            assert "Raspberry Pi Trading" in body
        finally:
            with app.state["lock"]:
                app.state["scan_results"] = []

    def test_export_ignora_resultados_sin_dispositivos(self, app, client):
        """Busca el último escaneo CON dispositivos, no solo el último run."""
        with app.state["lock"]:
            app.state["scan_results"] = [
                {"module": "device", "target": "broadcast", "time": "10:00:00",
                 "success": True,
                 "result": {"success": True, "data": {"devices": [
                     {"mac": "AA:BB:CC:DD:EE:FF", "name": "viejo"}]}, "error": None}},
                {"module": "services", "target": "AA:BB:CC:DD:EE:FF",
                 "time": "11:00:00", "success": False,
                 "result": {"success": False, "data": {}, "error": "x"}},
            ]
        try:
            rv = client.get("/api/scan/export")
            assert rv.status_code == 200
            assert "AA:BB:CC:DD:EE:FF" in rv.data.decode("utf-8")
        finally:
            with app.state["lock"]:
                app.state["scan_results"] = []


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
