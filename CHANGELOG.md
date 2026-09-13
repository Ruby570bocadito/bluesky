# Changelog

Todos los cambios notables de este proyecto se documentan en este archivo.
El formato sigue [Keep a Changelog](https://keepachangelog.com/es-ES/1.1.0/)
y el versionado sigue [SemVer](https://semver.org/lang/es/).

## [0.5.0] - 2026-09-13

### Añadido

- **Identificación de fabricante (OUI) para dispositivos descubiertos**:
  nueva base OUI compartida y 100% offline (`bluesky/utils/oui.py`, 114
  prefijos: Apple, Samsung, Raspberry Pi, CSR, Xiaomi, Google, Sony…).
  `DeviceScanner` anota cada dispositivo con `vendor`, visible en CLI
  (`scan`), consola REPL (columna Vendor), web y exportaciones. El
  backend Termux ahora delega en la misma DB en lugar de mantener una
  copia propia desincronizada.
- **Exportación CSV/JSON de dispositivos**: `bluesky scan --export
  dispositivos.csv` (con BOM utf-8-sig para Excel; `--export x.json`
  para JSON). Compañero natural de `--json`: el entregable de
  descubrimiento se guarda a archivo sin salir del flujo de escaneo.
- **Web: tabla de dispositivos descubiertos en vivo** — la página de
  escaneo ahora muestra MAC, nombre, tipo, fabricante (OUI) y RSSI de
  cada dispositivo encontrado, con botón "Exportar CSV"
  (`GET /api/scan/export`, descarga con Content-Disposition).
- **Web: opciones de escaneo reales** — el formulario permite elegir
  modo (Todos/BLE/Classic) y timeout (1-60 s), y `/api/scan` valida y
  propaga `type`/`timeout` al escáner. El escáner de servicios exige
  ahora MAC (400 con mensaje claro en lugar de lanzar un escaneo sin
  objetivo).
- 57 tests nuevos (349 total, 100% offline): lookup OUI, CSV export
  (escaping, unicode, tolerancia a entradas malformadas), opciones y
  validación de `/api/scan` y endpoint de exportación web.

### Corregido

- `web/app.py`: `/api/scan` ejecutaba el escáner sin `options` (siempre
  "all" y timeout por defecto, ignorando la configuración) y aceptaba
  `scanner=services` sin target.

## [0.4.0] - 2026-09-12

### Añadido

- **CLI re-hecho sobre argparse** (`bluesky/cli.py`): cada subcomando tiene
  ahora ayuda propia (`bluesky scan --help`), validación estricta de opciones
  (puertos 1-65535, `--rate` 1-100, JSON de opciones verificado) y una ayuda
  principal agrupada por secciones (auditoría / catálogo / entorno / interfaz).
- **Exit codes consistentes**: `0` operación correcta, `1` error de ejecución,
  `2` error de uso — tanto en `python -m bluesky` como en el entry point pip.
- **Salida `--json`** para scripting en `scan`, `services`, `attack`, `vuln`,
  `auto`, `spam`, `list`, `info` y `status` (global o por comando; suprime
  banner y avisos para producir JSON limpio).
- **`--no-color`** global y soporte de la convención `NO_COLOR`.
- **Sugerencias con difflib**: `bluesky attack bluej` → "¿quisiste decir
  bluejacking?"; también para `info` y para comandos desconocidos.

### Cambiado

- **Web dashboard en modo oscuro**: paleta slate profundo tipo GitHub Dark
  (superficie `#161b22`, texto `#e6edf3`, acento `#4493f8`), `color-scheme:
  dark` para controles nativos, fix de autofill en inputs y favicon alineado
  al acento. Capturas regeneradas.
- Salida del CLI más sobria: banner compacto de 2 líneas y estados `OK` /
  `AVISO` / `ERROR` en lugar de arte ASCII y emojis dispersos.
- `bluesky report` vuelve a respetar `general.report_format` de la
  configuración como formato por defecto.

### Limpieza

- Eliminados los artefactos `docs/demo_report.{txt,html,json}` del repositorio
  (los genera `scripts/demo.sh` en runtime; estaban committeados por error).
- `TESTING_WINDOWS.md` movido a `docs/`; `.ruff_cache/` al `.gitignore`;
  números desactualizados de `scripts/demo.sh` corregidos (22 módulos,
  3 escáneres, 290+ tests).

### Tests

- 292 tests en verde (100% offline) tras la reescritura del CLI; contrato de
  compatibilidad preservado (`cmd_web`, `cmd_educate`, dispatch y `no_banner`).

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
