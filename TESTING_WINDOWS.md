
## 🧪 Cómo hacer Testing de Bluesky en Windows

### Requisitos previos
- Python 3.8+ instalado (verificar con `python --version`)
- Git instalado
- PowerShell (viene con Windows)

### 1. Clonar e instalar

```powershell
# Clonar el repo
git clone https://github.com/TU_USUARIO/bluesky.git
cd bluesky

# Instalar dependencias base
pip install -e .
pip install flask pytest
```

### 2. Ejecutar tests

#### ✅ Tests que funcionan en Windows (102 tests, 94 pasando)

```powershell
python -m pytest tests/test_utils.py tests/test_config.py tests/test_engine.py tests/test_web.py tests/test_session.py tests/test_reporter.py -v
```

#### 🧪 Tests completos (191 tests, todos en Linux)

```powershell
# En WSL funciona todo:
wsl python3 -m pytest tests/ -v

# En Windows nativo (algunos fallan por falta de hardware BT):
python -m pytest tests/ -v --tb=short
```

### 3. Tests por área

| Área | Comando | Tests |
|------|---------|-------|
| **Utils** | `python -m pytest tests/test_utils.py -v` | 14 ✅ |
| **Config** | `python -m pytest tests/test_config.py -v` | 18 ✅ |
| **Engine** | `python -m pytest tests/test_engine.py -v` | 16 (6 fallan: módulos nativos no se descubren) |
| **Web** | `python -m pytest tests/test_web.py -v` | 33 ✅ |
| **Sesiones** | `python -m pytest tests/test_session.py -v` | 10 ✅ |
| **Reportes** | `python -m pytest tests/test_reporter.py -v` | 10 (2 fallan: emojis en cp1252) |
| **Plugins** | `python -m pytest tests/test_plugin_loader.py -v` | 12 ✅ |
| **Exploits** | `python -m pytest tests/test_exploits.py -v` | 51 ✅ |
| **Termux** | `python -m pytest tests/test_termux_backend.py -v` | 17 ✅ |
| **Hardware** | `python -m pytest tests/test_hardware.py -v` | 13 (requiere BT) |

### 4. Problemas conocidos en Windows

| Síntoma | Causa | Solución |
|---------|-------|----------|
| `pytest` no encontrado | Scripts de Python no están en PATH | Usar `python -m pytest` |
| `venv\Scripts\Activate.ps1` no funciona | Política de ejecución restringida | `Set-ExecutionPolicy -Scope CurrentUser RemoteSigned` |
| `test_engine` falla (solo demo_scanner) | Paths con `\` vs `/` en descubrimiento de módulos | Se corrigió en `engine.py` (usar `Path.resolve().parts`) |
| `test_reporter` falla (UnicodeEncodeError) | Emojis no caben en cp1252 | Se corrigió en `reporter.py` (usar `encoding="utf-8"`) |
| `test_hardware` falla | No hay Bluetooth hardware en Windows | Esperado, saltar con `-m "not hardware"` |
| `test_exploits` lento o cuelga | Scapy tarda en importar | Esperar, o saltar con `-m "not slow"` |
| `test_web` no detecta módulos | Mismo problema paths que engine | Ya corregido |

### 5. Dashboard web (probar manualmente)

```powershell
bluesky web --port 5000
# Abrir navegador en http://127.0.0.1:5000
```

### 6. Cobertura de código

```powershell
python -m pytest tests/ --cov=bluesky --cov-report=html
# Abrir htmlcov/index.html en el navegador
```
