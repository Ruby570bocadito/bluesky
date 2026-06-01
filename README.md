# 🔵 Bluesky - Bluetooth Security Auditing Framework

![Version](https://img.shields.io/badge/version-0.1.0-blue)
![Python](https://img.shields.io/badge/python-3.8+-green)
![Platform](https://img.shields.io/badge/platform-Windows%20%7C%20Linux%20%7C%20Termux%20%7C%20WSL-orange)
![Tests](https://img.shields.io/badge/tests-212%20%C3%97%20%E2%9C%85-brightgreen)

**Bluesky** es un framework de auditoría Bluetooth unificado, compatible con **Windows**, **Linux**, **Termux (Android)** y **WSL**. Implementa **15+ módulos de ataque/escaneo/exploit** en una CLI modular tipo Metasploit, con **dashboard web Flask**, **consola interactiva REPL**, **sistema de plugins**, y **generación de reportes** (HTML/JSON/TXT).

---

## 🚀 Instalación Rápida

### Windows (PowerShell)

```powershell
# Clonar e instalar
git clone https://github.com/tuusuario/bluesky.git
cd bluesky
pip install -e .
python -m pip install flask pytest

# Probar
bluesky help
bluesky web
```

### Linux (Ubuntu/Debian)

```bash
git clone https://github.com/tuusuario/bluesky.git
cd bluesky
pip install -e .
bluesky help
```

### Termux (Android)

```bash
pkg install git
git clone https://github.com/tuusuario/bluesky.git
cd bluesky
chmod +x scripts/install_termux.sh
./scripts/install_termux.sh
```

### Docker

```bash
docker build -t bluesky .
docker run --rm -it --privileged bluesky
```

---

## 📋 Uso Rápido

```bash
# Escanear dispositivos Bluetooth cercanos
bluesky scan

# Escanear solo BLE
bluesky scan --ble

# Ver todos los módulos de ataque disponibles
bluesky list

# Ver info detallada de un ataque
bluesky info knob

# Ejecutar un ataque sobre un dispositivo
bluesky attack knob XX:XX:XX:XX:XX:XX

# Enumerar servicios de un dispositivo
bluesky services XX:XX:XX:XX:XX:XX

# Consola interactiva estilo Metasploit
bluesky console

# Dashboard web
bluesky web [--port 8080] [--host 0.0.0.0] [--open]

# Ver estado del hardware Bluetooth
bluesky status

# Generar reporte de auditoría
bluesky report --html report.html

# Gestionar sesiones
bluesky session list
bluesky session save mi_auditoria
```

---

## 🎯 Módulos de Ataque (14+)

| # | Módulo | Ataque | CVE | Tipo | Severidad | HW Ext. |
|---|--------|--------|-----|------|-----------|---------|
| 1 | `bluejacking` | Bluejacking — Mensajes vCard no solicitados | — | Classic | ⚪ Baja | ❌ |
| 2 | `bluesnarfing` | Bluesnarfing — Robo de datos vía OBEX | — | Classic | 🟠 Alta | ❌ |
| 3 | `bluebugging` | Bluebugging — Control AT remoto | — | Classic | 🔴 Crítica | ❌ |
| 4 | `bias` | BIAS — Suplantación de dispositivos | CVE-2020-10135 | Classic | 🔴 Crítica | ✅ |
| 5 | `knob` | KNOB — Degradación de clave de cifrado | CVE-2019-9506 | Classic/BLE | 🔴 Crítica | ✅ |
| 6 | `bluffs` | BLUFFS — Ruptura de seguridad forward | CVE-2023-24023 | Classic/BLE | 🔴 Crítica | ✅ |
| 7 | `blueborne` | BlueBorne — RCE sin emparejamiento | CVE-2017-0781 | Classic | 🔴 Crítica | ❌ |
| 8 | `blesa` | BLESA — Spoofing BLE en reconexión | CVE-2020-9770 | BLE | 🟠 Alta | ❌ |
| 9 | `sweyntooth` | SweynTooth — SoCs BLE vulnerables | CVE-2019-... | BLE | 🔴 Crítica | ❌ |
| 10 | `whisperpair` | WhisperPair — Secuestro Fast Pair | CVE-2025-36911 | BLE | 🔴 Crítica | ❌ |
| 11 | **`crackle`** | **Crackle — BLE LTK Cracking** | CVE-2014-... | BLE | 🔴 Crítica | ❌ |
| 12 | **`btlejack`** | **BTLEJack — BLE Connection Hijacking** | — | BLE | 🔴 Crítica | ✅ |
| 13 | **`bluefrag`** | **BlueFrag — Android Bluetooth RCE** | CVE-2020-0022 | Android | 🔴 Crítica | ❌ |
| 14 | **`btspam`** | **BTSpam — Bluetooth Spam Flood** | — | Classic/BLE | 🟡 Media | ❌ |

### 🔑 Leyenda
- ❌ **Sin hardware extra** — Funciona solo con el Bluetooth de tu portátil
- ✅ **Requiere HW** — Necesita dongle CSR 4.0+, TP-Link UB500, o nRF52840

---

## 🌐 Web Dashboard

Bluesky incluye un **dashboard web** construido con Flask + Bootstrap 5 (tema oscuro):

```
bluesky web                   # http://127.0.0.1:5000
bluesky web --port 8080       # Puerto personalizado
bluesky web --host 0.0.0.0    # Acceso remoto
bluesky web --open            # Abrir navegador
```

### Rutas principales
| Ruta | Descripción |
|------|-------------|
| `/` | Dashboard con estado del sistema |
| `/modules` | Lista de módulos con búsqueda/filtro |
| `/scan` | Interfaz de escaneo en vivo |
| `/sessions` | Historial de sesiones |
| `/reports` | Reportes generados |
| `/logs` | Logs en vivo (auto-refresh) |
| `/api` | Documentación interactiva de la API |

### API REST (12 endpoints)
| Método | Endpoint | Descripción |
|--------|----------|-------------|
| GET | `/api/status` | Estado, uptime, plataforma |
| GET | `/api/modules` | Todos los módulos |
| POST | `/api/modules/<name>/run` | Ejecutar módulo (async) |
| POST | `/api/scan` | Iniciar escaneo (async) |
| GET | `/api/hardware` | Información hardware BT |
| GET | `/api/logs` | Logs con filtro `?since=N` |

---

## 🏗️ Arquitectura

```
bluesky/
├── bluesky/
│   ├── cli.py                  # CLI principal (Click-style)
│   ├── console.py              # Consola interactiva REPL
│   ├── core/
│   │   ├── engine.py           # Motor de módulos (carga dinámica)
│   │   ├── session.py          # Gestión de sesiones de auditoría
│   │   ├── hardware.py         # Detección de hardware Bluetooth
│   │   ├── reporter.py         # Generador de reportes (HTML/JSON/TXT)
│   │   └── plugin_loader.py    # Carga dinámica de plugins
│   ├── modules/
│   │   ├── attacks/            # 13+ módulos de ataque
│   │   ├── scanners/           # Escáneres (dispositivos, servicios)
│   │   ├── exploits/           # Exploits CVE específicos
│   │   └── utils/              # Utilidades varias
│   ├── utils/
│   │   ├── platform.py         # Detección multiplataforma
│   │   ├── config.py           # Sistema de configuración (JSON)
│   │   ├── network.py          # Utilidades de red Bluetooth
│   │   ├── termux.py           # Soporte específico Termux
│   │   ├── termux_backend.py   # Backend Termux completo (OUI DB)
│   │   ├── windows_backend.py  # Backend Windows (PowerShell/WMI)
│   │   ├── format.py           # Formateo de salida (colores, TUI)
│   │   └── logger.py           # Sistema de logging profesional
│   ├── web/
│   │   ├── app.py              # Flask app + API REST
│   │   ├── templates/          # 8 templates Jinja2 (Bootstrap 5)
│   │   └── static/             # CSS + JS personalizados
├── scripts/
│   ├── install_linux.sh        # Instalación para Linux
│   ├── install_termux.sh       # Instalación para Termux (7 pasos)
│   ├── bluesky-termux.sh       # Launcher Termux
│   └── completion/             # Auto-completado (bash/zsh/powershell)
├── tests/                      # 191 tests unitarios
├── Dockerfile                  # Multi-stage Docker
├── docker-compose.yml          # 5 servicios
├── .github/workflows/ci.yml    # GitHub Actions CI
├── setup.py                    # Instalación pip
└── README.md
```

---

## 📱 Compatibilidad por Plataforma

| Característica | Windows | Linux | Termux | WSL |
|---------------|:-------:|:-----:|:------:|:---:|
| Escaneo Bluetooth | ✅ (bleak) | ✅ (BlueZ) | ✅ (Termux:API) | ⚠️ (limitado) |
| BLE Scanning | ✅ | ✅ | ✅ | ⚠️ |
| Módulos de ataque (13) | ✅ | ✅ | ✅ | ⚠️ |
| Consola REPL | ✅ | ✅ | ✅ | ✅ |
| Web Dashboard | ✅ | ✅ | ✅ | ✅ |
| Plugins | ✅ | ✅ | ✅ | ✅ |
| Reportes HTML/JSON/TXT | ✅ | ✅ | ✅ | ✅ |
| Auto-completado | ✅ (ps1) | ✅ (bash/zsh) | ✅ (bash) | ✅ |
| Ataques avanzados (KNOB/BIAS) | ⚠️ (HW) | ✅ (con dongle) | ⚠️ (root) | ❌ |

---

## 🧪 Tests

**191 tests** — todos pasando en Linux y Windows.

```bash
# Todos los tests
python -m pytest tests/ -v

# Tests rápidos (sin hardware)
python -m pytest tests/test_utils.py tests/test_config.py tests/test_engine.py tests/test_web.py tests/test_session.py tests/test_reporter.py -v

# Tests específicos
python -m pytest tests/test_web.py -v                    # Dashboard web
python -m pytest tests/test_exploits.py -v                # Exploits
python -m pytest tests/test_termux_backend.py -v          # Backend Termux

# Tests con cobertura
python -m pytest tests/ --cov=bluesky --cov-report=html
```

### Tests por archivo
| Archivo | Tests | ¿Windows? |
|---------|-------|-----------|
| `test_utils.py` | 14 | ✅ Sí |
| `test_config.py` | 18 | ✅ Sí |
| `test_engine.py` | 16 | ✅ Sí |
| `test_plugin_loader.py` | 12 | ✅ Sí |
| `test_reporter.py` | 10 | ✅ Sí |
| `test_session.py` | 10 | ✅ Sí |
| `test_hardware.py` | 13 | ⚠️ Parcial |
| `test_web.py` | 33 | ✅ Sí |
| `test_exploits.py` | 51 | ✅ Sí |
| `test_termux_backend.py` | 17 | ✅ Sí (no-op) |

---

## 🛠️ Hardware Recomendado

- **Para ataques básicos** (Bluejacking, Bluesnarfing, Bluebugging, BlueBorne, Crackle):
  ✅ Solo tu portátil o Android — No necesitas nada más

- **Para ataques avanzados** (KNOB, BIAS, BLUFFS, BTLEJack):
  - ✅ **Dongle CSR 4.0** — ~$5 en AliExpress
  - ✅ **TP-Link UB500 (RTL8761B)** — ~$13, permite DarkFirmware
  - ✅ **nRF52840** — ~$30, para desarrollo BLE

---

## ⚠️ Aviso Legal

Bluesky es una herramienta de **seguridad ofensiva** diseñada exclusivamente para:
- Pruebas de penetración autorizadas
- Auditorías de seguridad con consentimiento
- Investigación académica en seguridad Bluetooth

**No uses Bluesky en dispositivos que no te pertenezcan o sin autorización explícita.**

---

## 📄 Licencia

MIT License — Ver [LICENSE](LICENSE) para más detalles.

---

*Bluesky — Making Bluetooth security auditing accessible to everyone* 🚀
