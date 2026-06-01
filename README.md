# 🦋 Bluesky - Bluetooth Security Toolkit

![Version](https://img.shields.io/badge/version-0.2.0-blue)
![Python](https://img.shields.io/badge/python-3.10%2B-brightgreen)
![Platform](https://img.shields.io/badge/platform-Windows%20|%20Linux%20|%20Termux%20|%20WSL-lightgrey)
![Tests](https://img.shields.io/badge/tests-222%20passed-brightgreen)
![License](https://img.shields.io/badge/license-MIT-green)

**Bluesky** es un framework de auditoría Bluetooth modular tipo Metasploit. Soporta 15+ módulos de ataque, 3 escáneres, 3 exploits, un escáner de vulnerabilidades unificado (13+ checks), consola interactiva REPL, dashboard web, y autopilot automatizado.

> ⚠️ **Solo usar en dispositivos con autorización explícita.**

---

## 📦 Instalación Rápida

### Windows
```powershell
git clone https://github.com/Ruby570bocadito/bluesky.git
cd bluesky
python -m venv venv
venv\Scripts\activate
pip install -r requirements.txt
pip install bleak pybluez scapy cryptography flask  # Bluetooth + Web
bluesky console
```

### Linux
```bash
git clone https://github.com/Ruby570bocadito/bluesky.git
cd bluesky
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt
sudo apt install bluez bluez-tools bluez-hcidump
pip install bleak pybluez scapy cryptography flask
bluesky console
```

### Termux (Android)
```bash
pkg install python python-pip bluez bluez-utils termux-api git
git clone https://github.com/Ruby570bocadito/bluesky.git
cd bluesky
pip install -r requirements.txt
bluesky console
```

### WSL
> ⚠️ Sin hardware Bluetooth. Usar `--dry-run` para desarrollo/testing.
```bash
bluesky scan --dry-run
bluesky attack knob --target AA:BB:CC:DD:EE:FF --dry-run
```

### Docker
```bash
docker build -t bluesky .
docker run --rm -it --privileged bluesky console
```

---

## 🚀 Uso Rápido

```bash
# Consola interactiva (Metasploit-style)
bluesky console

# Escanear dispositivos Bluetooth
bluesky scan
bluesky scan --ble            # Solo BLE
bluesky scan --classic        # Solo Classic
bluesky scan --timeout 15     # Timeout personalizado

# Escanear vulnerabilidades (13+ checks)
bluesky vuln AA:BB:CC:DD:EE:FF
bluesky vuln AA:BB:CC:DD:EE:FF --options '{"REPORT":"true"}'

# Autopilot completo (scan → detect → attack → report)
bluesky auto
bluesky auto AA:BB:CC:DD:EE:FF
bluesky auto --mode detect          # Solo detección
bluesky auto --mode attack          # Solo ataque

# Ejecutar módulo de ataque
bluesky attack knob --target AA:BB:CC:DD:EE:FF
bluesky attack btspam AA:BB:CC:DD:EE:FF --options '{"METHOD":"pairing_flood","RATE":"20"}'

# BTSpam - Inundación Bluetooth
bluesky spam AA:BB:CC:DD:EE:FF
bluesky spam --method obex_spam --rate 20 --message "Hello!" AA:BB:CC:DD:EE:FF
bluesky spam --method pairing_flood --duration 30 --delay 0.1 all
bluesky spam --method connection_flood --count 500 AA:BB:CC:DD:EE:FF

# Listar módulos
bluesky list

# Información de módulo
bluesky info knob

# Servicios SDP
bluesky services AA:BB:CC:DD:EE:FF

# Estado del sistema
bluesky status

# Generar reporte
bluesky report --html report.html
bluesky report --json report.json

# Dashboard web
bluesky web
bluesky web --port 8080 --open

# Gestión de sesiones
bluesky session list
bluesky session save mi_auditoria
bluesky session load mi_auditoria

# Configuración
bluesky config show
bluesky config set general.timeout=60
bluesky config save
```

---

## 🛡️ Módulos de Ataque

| Módulo | Clase | CVE | Tipo | Severidad | Hardware |
|--------|-------|-----|------|-----------|----------|
| `knob` | KNOB Attack | CVE-2019-9506 | Classic/BLE | 🔴 Alta | CSR 4.0+ |
| `bias` | BIAS Attack | CVE-2020-10135 | Classic | 🔴 Alta | CSR 4.0+ |
| `bluffs` | BLUFFS Attack | CVE-2023-24023 | Classic/BLE | 🔴 Alta | CSR 4.0+ |
| `blueborne` | BlueBorne | CVE-2017-0781 | Classic | 🔴 Alta | Cualquiera |
| `bluefrag` | BlueFrag | CVE-2020-0022 | Android BLE | 🟠 Media | Cualquiera |
| `blesa` | BLESA | CVE-2020-9770 | BLE | 🟠 Media | BLE |
| `sweyntooth` | SweynTooth | CVE-2019-169xx | BLE | 🔴 Alta | BLE |
| `whisperpair` | WhisperPair | CVE-2025-36911 | BLE | 🟠 Media | BLE |
| `crackle` | Crackle | CVE-2014-xxxx | BLE | 🟠 Media | CSR 4.0+ |
| `btlejack` | BTLEJack | - | BLE | 🔴 Alta | nRF52840 |
| `bluejacking` | Bluejacking | - | Classic | 🟢 Baja | Cualquiera |
| `bluesnarfing` | Bluesnarfing | - | Classic | 🟠 Media | Cualquiera |
| `bluebugging` | Bluebugging | - | Classic | 🔴 Alta | Cualquiera |
| `btspam` | BTSpam Flood | - | Classic/BLE | 🟡 Media | Cualquiera |

### 🔬 Módulos de Explotación

| Módulo | Descripción | Tipo |
|--------|-------------|------|
| `keystroke_injection` | Inyección de teclas HID Bluetooth | Classic |
| `l2cap_fuzz` | Fuzzing de paquetes L2CAP | Classic/BLE |
| `rfcomm_shell` | Shell remota vía RFCOMM | Classic |

### 🔍 Escáneres

| Módulo | Descripción |
|--------|-------------|
| `device_scanner` | Descubrimiento de dispositivos BT/LE |
| `service_scanner` | Enumeración de servicios SDP |
| `vuln` | Escáner unificado de 13+ vulnerabilidades |

---

## 🧠 Autopilot v2.0

Pipeline automatizado de 4 fases:

```
┌─────────┐    ┌─────────┐    ┌─────────┐    ┌─────────┐
│ Phase 1 │ →  │ Phase 2 │ →  │ Phase 3 │ →  │ Phase 4 │
│  SCAN   │    │ DETECT  │    │ ATTACK  │    │ REPORT  │
└─────────┘    └─────────┘    └─────────┘    └─────────┘
```

**Modos:**
- `full` — Pipeline completo (default)
- `detect` — Solo escaneo y detección de vulnerabilidades
- `attack` — Solo fase de explotación (usando datos previos)

```bash
bluesky auto AA:BB:CC:DD:EE:FF
bluesky auto --mode detect
bluesky auto --chain "knob,bias,bluffs" --timeout 60
```

---

## 💀 BTSpam - Bluetooth Spam Flood

3 técnicas de inundación:

| Técnica | Descripción | Flag |
|---------|-------------|------|
| `pairing_flood` | Inunda con solicitudes de emparejamiento | `--method pairing_flood` |
| `obex_spam` | Envía mensajes OBEX masivos | `--method obex_spam --message "txt"` |
| `connection_flood` | Inunda con solicitudes de conexión | `--method connection_flood` |

**Multi-target:** `all`, `*`, `broadcast` para atacar simultáneamente.

```bash
bluesky spam all                       # Todos los dispositivos
bluesky spam --method obex_spam --rate 20 AA:BB:CC:DD:EE:FF
bluesky spam --duration 60 --delay 0.05 broadcast
```

---

## 🎯 VulnScanner - Escáner de Vulnerabilidades

Analiza 13+ vulnerabilidades Bluetooth con CVSS, CVE, evidencia, y cadena de ataque recomendada:

| Vulnerabilidad | Cobertura |
|----------------|-----------|
| KNOB (CVE-2019-9506) | ✅ |
| BIAS (CVE-2020-10135) | ✅ |
| BLUFFS (CVE-2023-24023) | ✅ |
| BlueBorne (CVE-2017-0781) | ✅ |
| BlueFrag (CVE-2020-0022) | ✅ |
| SweynTooth (CVE-2019-169xx) | ✅ |
| WhisperPair (CVE-2025-36911) | ✅ |
| BLESA (CVE-2020-9770) | ✅ |
| Crackle (CVE-2014-xxxx) | ✅ |
| BTLEJack | ✅ |
| BlueBugging | ✅ |
| BlueSnarfing | ✅ |
| Keystroke Injection | ✅ |

```bash
bluesky vuln AA:BB:CC:DD:EE:FF
bluesky vuln AA:BB:CC:DD:EE:FF --options '{"REPORT":"true","SCAN_TYPE":"quick"}'
```

---

## 🖥️ Consola Interactiva (Metasploit-style)

```
╔══════════════════════════════════════════╗
║     BLUESKY CONSOLE - METASPLOIT MODE  ║
╚══════════════════════════════════════════╝

bluesky > use knob
bluesky (knob) > set TARGET AA:BB:CC:DD:EE:FF
bluesky (knob) > show options
bluesky (knob) > check
bluesky (knob) > run
bluesky (knob) > back
bluesky > search blueborne
bluesky > vuln AA:BB:CC:DD:EE:FF
bluesky > auto --mode detect
bluesky > report --html my_report.html
bluesky > exit
```

**Comandos:**
| Comando | Descripción |
|---------|-------------|
| `use <módulo>` | Seleccionar módulo |
| `back` | Deseleccionar módulo |
| `list` | Listar módulos |
| `search <keyword>` | Buscar módulos |
| `info [módulo]` | Información detallada |
| `set <opt> <val>` | Configurar opción |
| `show options` | Mostrar opciones |
| `show targets` | Mostrar targets |
| `run [target]` | Ejecutar módulo |
| `check [target]` | Verificar prerequisitos |
| `scan [--ble]` | Escanear dispositivos |
| `vuln <target>` | Escanear vulnerabilidades |
| `auto [target]` | Autopilot completo |
| `session list/save/load` | Gestión de sesiones |
| `report [--html]` | Generar reporte |
| `config show/set/save` | Configuración global |
| `help` | Mostrar ayuda |

---

## 🌐 Web Dashboard

Dashboard Flask embebido con 12 endpoints REST API:

```
bluesky web                     # http://127.0.0.1:5000
bluesky web --port 8080 --open  # Puerto + abrir navegador
```

**Rutas:**
| Ruta | Descripción |
|------|-------------|
| `/` | Dashboard principal |
| `/modules` | Lista de módulos |
| `/modules/<name>` | Detalle de módulo |
| `/scan` | Escaneo en vivo |
| `/sessions` | Gestión de sesiones |
| `/reports` | Reportes guardados |
| `/logs` | Logs del sistema |
| `/api/status` | API: estado del sistema |
| `/api/modules` | API: lista de módulos |
| `/api/scan` | API: iniciar escaneo |
| `/api/sessions` | API: sesiones |
| `/api/reports` | API: reportes |
| `/api/logs` | API: logs |
| `/api/config` | API: configuración |
| `/api/hardware` | API: hardware info |
| `/api/run-module` | API: ejecutar módulo |
| `/api-docs` | Documentación API |

---

## 🏗️ Arquitectura

```
bluesky/
├── bluesky/
│   ├── __init__.py           # Paquete principal
│   ├── cli.py                # CLI entry point
│   ├── console.py            # Consola interactiva REPL
│   ├── core/
│   │   ├── __init__.py
│   │   ├── engine.py         # ModuleEngine + BaseModule
│   │   ├── session.py        # Gestión de sesiones
│   │   ├── hardware.py       # Detección de hardware
│   │   ├── reporter.py       # Generación de reportes
│   │   └── plugin_loader.py  # Plugins externos
│   ├── modules/
│   │   ├── attacks/          # 15 módulos de ataque
│   │   │   ├── knob.py, bias.py, bluffs.py, blueborne.py
│   │   │   ├── blesa.py, sweyntooth.py, whisperpair.py
│   │   │   ├── crackle.py, btlejack.py, bluefrag.py
│   │   │   ├── bluejacking.py, bluesnarfing.py, bluebugging.py
│   │   │   ├── btspam.py     # BTSpam Flood
│   │   │   └── autopilot.py  # Autopilot v2.0
│   │   ├── scanners/         # 3 escáneres
│   │   │   ├── device_scanner.py
│   │   │   ├── service_scanner.py
│   │   │   └── vuln_scanner.py  # 13+ vulnerabilidades
│   │   ├── exploits/         # 3 exploits
│   │   │   ├── keystroke_injection.py
│   │   │   ├── l2cap_fuzz.py
│   │   │   └── rfcomm_shell.py
│   │   └── utils/            # Utilidades futuras
│   ├── web/                  # Web Dashboard (Flask)
│   │   ├── __init__.py
│   │   ├── app.py
│   │   └── templates/        # 8 plantillas Jinja2
│   └── utils/
│       ├── __init__.py
│       ├── config.py         # Configuración persistente
│       ├── logger.py         # Logging + Rich (lazy import)
│       ├── platform.py       # Detección de plataforma
│       ├── format_utils.py   # Formateo, colores, iconos
│       ├── windows_backend.py # Backend Windows (PowerShell)
│       ├── termux_backend.py  # Backend Termux (API + BlueZ)
│       └── reporter.py       # Generación de reportes HTML/JSON/TXT
├── tests/                    # 222 tests (pytest)
├── requirements.txt
├── setup.py / pyproject.toml
├── Dockerfile
└── README.md
```

---

## 🔧 Compatibilidad de Plataformas

| Funcionalidad | Windows | Linux | Termux | WSL |
|--------------|---------|-------|--------|-----|
| Escaneo BLE (bleak) | ✅ | ✅ | ✅ | ❌ |
| Escaneo Classic (PyBluez) | ✅ | ✅ | ✅ (BlueZ) | ❌ |
| Ataques BLE | ✅ | ✅ | ✅ | ❌ (dry-run) |
| Ataques Classic | ⚠️ | ✅ | ✅ | ❌ (dry-run) |
| KNOB/BLUFFS activo | ❌ | ✅ (CSR) | ❌ | ❌ |
| Web Dashboard | ✅ | ✅ | ✅ | ✅ |
| Consola REPL | ✅ | ✅ | ✅ | ✅ |
| Docker | ⚠️ | ✅ | ❌ | ✅ |
| Scapy (paquetes raw) | ❌ | ✅ | ⚠️ | ❌ |

---

## 🧪 Tests

**222 tests** — todos pasando ✅

```bash
# Ejecutar todos los tests
pytest tests/ -v

# Tests por categoría
pytest tests/test_engine.py -v       # Motor de módulos
pytest tests/test_exploits.py -v     # 81 tests: Crackle, BTLEJack, BlueFrag, BTSpam
pytest tests/test_config.py -v       # Configuración
pytest tests/test_web.py -v          # Dashboard web
pytest tests/test_session.py -v      # Sesiones
pytest tests/test_reporter.py -v     # Reportes
pytest tests/test_termux_backend.py -v  # Backend Termux
pytest tests/test_utils.py -v        # Utilidades
pytest tests/test_hardware.py -v     # Hardware
pytest tests/test_plugin_loader.py -v # Plugins

# Con cobertura
pytest tests/ --cov=bluesky --cov-report=html

# Tests rápidos (omitir web/flask)
pytest tests/ --ignore=tests/test_web.py -v
```

**Distribución de tests:**
| Archivo | Tests |
|---------|-------|
| `test_exploits.py` | 81 (Crackle 9 + BTLEJack 17 + BlueFrag 19 + BTSpam 30 + Engine 6) |
| `test_web.py` | 33 |
| `test_config.py` | 18 |
| `test_termux_backend.py` | 17 |
| `test_engine.py` | 17 |
| `test_termux_backend.py` | 17 |
| `test_utils.py` | 15 |
| `test_plugin_loader.py` | 12 |
| `test_reporter.py` | 10 |
| `test_session.py` | 10 |
| `test_hardware.py` | 9 |
| **Total** | **222** |

---

## 💻 Hardware Recomendado

| Dispositivo | Uso | Precio |
|-------------|-----|--------|
| CSR 4.0 Bluetooth dongle | KNOB, BIAS, BLUFFS activos | ~$5-10 |
| TP-Link UB500 + DarkFirmware | BLUFFS avanzado, BTLEJack | ~$12 |
| nRF52840 Dongle | BTLEJack completo, BLE sniffer | ~$25 |
| Ubertooth One | BLE sniffing avanzado | ~$120 |
| HackRF One | SDR Bluetooth | ~$300 |

---

## ⚖️ Aviso Legal

Este software es solo para **propósitos educativos y pruebas de seguridad autorizadas**. El uso no autorizado de este software contra dispositivos sin consentimiento explícito es ilegal. Los autores no se responsabilizan por el mal uso.

---

## 📄 Licencia

MIT License — Ver [LICENSE](LICENSE) para detalles.
