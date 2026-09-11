# Changelog

Todos los cambios notables de este proyecto se documentan en este archivo.
El formato sigue [Keep a Changelog](https://keepachangelog.com/es-ES/1.1.0/)
y el versionado sigue [SemVer](https://semver.org/lang/es/).

## [0.3.0] - 2026-09-11

### Añadido

- **Modo educativo** (`bluesky educate <módulo>`, comando `educate` en la REPL,
  sección en la web y endpoint `GET /api/modules/<nombre>/education`): explica
  cada uno de los 22 módulos paso a paso — qué es, cómo funciona, impacto y
  mitigaciones accionables — con foco defensivo (core/education.py).
- **Web dashboard re-diseñado**: interfaz minimalista y profesional (1 acento,
  neutros slate, numerales tabulares, micro-labels), 100% offline (sin CDN ni
  fuentes externas) y renderizado seguro `textContent` (sin inyección de
  markup). Nuevo visor de reportes y auto-refresh de logs/estado.
- Nueva captura real del dashboard y del detalle de módulo en `docs/`.
- Sección del dashboard y del modo educativo en el README con capturas reales.

### Corregido

- `web/app.py`: import de `SessionManager` (clase inexistente) que dejaba las
  páginas de sesiones y `GET /api/sessions` siempre vacías — ahora usa
  `Session.list_sessions()`.
- `web/app.py`: **path traversal** en `GET /api/reports/<path>` — la ruta se
  resuelve y se verifica que quede dentro de `reports/` (antes
  `/api/reports/../../etc/passwd` leía archivos arbitrarios).
- `web/app.py`: estado mutado por hilos (logs, resultados de escaneo,
  `scan_in_progress`) ahora protegido con `threading.Lock` + tope de
  resultados (200) y de entradas de log (500).
- `core/engine.py`: `run_module()` devolvía `{"success", "error"}` sin la
  clave `"data"` cuando `run()` lanzaba una excepción — contrato de resultados
  roto para los consumidores (web/consola/reportes).
- `core/hardware.py`: `_check_usb_product()` se llamaba con una lista
  (`ubluetooth_dongle`) pero su firma era `str` → `AttributeError` silencioso
  que invalidaba el check en Linux; ahora acepta `str | list`.
- `core/reporter.py`: **XSS almacenado** en el reporte HTML — nombres de
  dispositivos, MACs, módulos y errores se interpolaban sin `html.escape`;
  ahora todo dato del escaneo se escapa y la clase de severidad usa whitelist.
- `core/reporter.py`: pie de reporte con versión obsoleta `v0.1.0` → usa
  `bluesky.__version__`.
- `core/session.py`: cargar una sesión con JSON corrupto lanzaba
  `JSONDecodeError` y crasheaba la consola; ahora degrada a `False` y tolera
  campos con tipos incorrectos.
- `modules/exploits/rfcomm_shell.py`: el listener RFCOMM en background dejaba
  los pipes abiertos sin drenar (posible deadlock por buffer lleno).
- 65 f-strings rotas en CLI/consola/módulos (mostraban llaves literales en
  pantalla) restauradas tras una limpieza defectuosa previa.
- Limpieza pyflakes completa: 365 → 0 avisos (imports muertos, variables sin
  uso, código muerto `console.py::_add_section` con referencia antes de
  asignación).

### Seguridad

- Endurecimiento defensivo general (sin capacidades ofensivas nuevas): escapes
  de salida, validación de rutas, locks de concurrencia y timeouts verificados
  en todos los `subprocess`.

### Tests

- 33 tests nuevos (regresión QA ronda 2 + modo educativo): 292 total,
  100% offline y en verde.
- CI actualizado: lint real con ruff (sin `|| echo skipped`) y job de tests
  sin advertencias pyflakes.

## [0.2.0] - 2026-09-10

- Renombrado del proyecto a bluesky, banner y URLs actualizadas.
- Suite de tests ampliada (regresión QA ronda 1).

## [0.1.0] - 2026-09-09

- Release inicial: consola REPL estilo Metasploit, 3 escáneres, 15+ módulos
  de ataque, 3 exploits, 13+ checks de vulnerabilidades, autopilot de 4 fases
  y dashboard web Flask.
