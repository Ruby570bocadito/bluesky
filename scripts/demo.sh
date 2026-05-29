#!/bin/bash
"""
Bluesky Demo - Script de demostración de capacidades
=====================================================
Muestra en acción los módulos principales de Bluesky.
"""

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
cd "$SCRIPT_DIR"

BLUESKY="python3 bluesky/cli.py"
if command -v bluesky &>/dev/null; then
    BLUESKY="bluesky"
fi

clear

# ============================================================
echo ""
echo "  ╔══════════════════════════════════════════════════╗"
echo "  ║          BLUESKY - DEMO DE CAPACIDADES           ║"
echo "  ║     Bluetooth Security Auditing Framework        ║"
echo "  ╚══════════════════════════════════════════════════╝"
echo ""
echo "  Este script muestra las capacidades de Bluesky"
echo "  sin necesidad de hardware Bluetooth."
echo ""
echo "  Presiona ENTER para comenzar..."
echo "  (o Ctrl+C para saltar)..."
read -r

# ============================================================
echo ""
echo "  ╔══════════════════════════════════════════════════╗"
echo "  ║  1. ESTADO DEL SISTEMA                          ║"
echo "  ╚══════════════════════════════════════════════════╝"
echo ""
$BLUESKY status
echo ""
echo "  Presiona ENTER para continuar..."
read -r

# ============================================================
echo ""
echo "  ╔══════════════════════════════════════════════════╗"
echo "  ║  2. MÓDULOS DISPONIBLES (10 ATAQUES BLUETOOTH)  ║"
echo "  ╚══════════════════════════════════════════════════╝"
echo ""
echo "  Cargando motor de módulos..."
echo ""

$BLUESKY list
echo ""
echo "  Presiona ENTER para continuar..."
read -r

# ============================================================
echo ""
echo "  ╔══════════════════════════════════════════════════╗"
echo "  ║  3. INFORMACIÓN DETALLADA DE MÓDULOS            ║"
echo "  ╚══════════════════════════════════════════════════╝"
echo ""

echo "  ─── Módulo: Bluejacking ───"
$BLUESKY info bluejacking
echo ""

echo "  ─── Módulo: WhisperPair (CVE-2025-36911) ───"
$BLUESKY info whisperpair
echo ""

echo "  ─── Módulo: KNOB (CVE-2019-9506) ───"
$BLUESKY info knob
echo ""

echo "  Presiona ENTER para continuar..."
read -r

# ============================================================
echo ""
echo "  ╔══════════════════════════════════════════════════╗"
echo "  ║  4. GENERAR REPORTE DE AUDITORÍA DE EJEMPLO     ║"
echo "  ╚══════════════════════════════════════════════════╝"
echo ""
echo "  Generando reportes de ejemplo..."

python3 -c "
import sys
sys.path.insert(0, '.')
from bluesky.core.reporter import Reporter
from bluesky.core.session import Session

# Crear sesión de demostración con datos simulados
session = Session('demo_audit')
session.add_target('00:1A:7D:DA:71:13', 'iPhone 15 Pro', -55)
session.add_target('AC:3F:A4:12:34:56', 'Sony WH-1000XM5', -72)
session.add_target('DC:0C:5C:78:90:AB', 'Samsung Galaxy S25', -61)

# Agregar resultados simulados
session.add_result('scan', '00:1A:7D:DA:71:13', True, {'services': 12, 'note': 'Bluetooth 5.3'})
session.add_result('bluejacking', '00:1A:7D:DA:71:13', True, {'message': 'vCard sent'})
session.add_result('blueborne', '00:1A:7D:DA:71:13', False, {}, 'Device patched')
session.add_result('whisperpair', 'AC:3F:A4:12:34:56', True, {
    'vulnerable_devices': [{'name': 'Sony WH-1000XM5', 'manufacturer': 'Sony'}],
    'vulnerabilities': [{'name': 'WhisperPair', 'severity': 'critical'}]
})
session.add_result('blesa', 'DC:0C:5C:78:90:AB', True, {'vulnerabilities': [{'name': 'BLESA possible', 'severity': 'high'}]})

summary = session.summary()
summary['session'] = {
    'name': 'Demo Audit - Bluetooth Pentest',
    'date': '2026-05-28',
    'environment': 'Linux',
    'duration': '15m'
}

reporter = Reporter(summary)

# Generar TXT
reporter.to_txt('docs/demo_report.txt')
print('  ✅ Reporte TXT: docs/demo_report.txt')

# Generar HTML
reporter.to_html('docs/demo_report.html')
print('  ✅ Reporte HTML: docs/demo_report.html')

# Generar JSON
reporter.to_json('docs/demo_report.json')
print('  ✅ Reporte JSON: docs/demo_report.json')
"
echo ""

# ============================================================
echo ""
echo "  ╔══════════════════════════════════════════════════╗"
echo "  ║  5. RESUMEN DEL PROYECTO                        ║"
echo "  ╚══════════════════════════════════════════════════╝"
echo ""

echo "  📋 Bluesky incluye:"
echo "  ─────────────────────────────────────────────"
echo "   🔴 10 módulos de ataque Bluetooth"
echo "   🔴 3  módulos de exploit avanzado"
echo "   🔵 2  escáneres (dispositivos + servicios)"
echo "   📊 3 formatos de reporte (HTML/JSON/TXT)"
echo "   📱 Soporte nativo para Termux (Android)"
echo "   💻 Soporte completo para Linux (BlueZ)"
echo "   🔧 Sistema modular tipo Metasploit"
echo "   📦 Binario único con PyInstaller"
echo ""

echo "  📁 Estructura:"
echo "  ─────────────────────────────────────────────"
echo "   bluesky/"
echo "   ├── bluesky/          → Paquete Python"
echo "   │   ├── core/         → Motor principal"
echo "   │   ├── modules/      → 15 módulos total"
echo "   │   │   ├── attacks/  → 10 ataques BT"
echo "   │   │   ├── scanners/ → 2 escáneres"
echo "   │   │   └── exploits/ → 3 exploits"
echo "   │   └── utils/        → Utilidades"
echo "   ├── tests/            → 60+ tests unitarios"
echo "   ├── scripts/          → Instalación + build"
echo "   ├── docs/             → Documentación"
echo "   └── setup.py          → Instalación pip"
echo ""

echo "  ╔══════════════════════════════════════════════════╗"
echo "  ║     DEMO COMPLETADA                             ║"
echo "  ╚══════════════════════════════════════════════════╝"
echo ""
echo "  Reportes generados en docs/:"
echo "    📄 docs/demo_report.txt"
echo "    🌐 docs/demo_report.html"
echo "    📋 docs/demo_report.json"
echo ""
echo "  Para usar Bluesky con Bluetooth real:"
echo "    bluesky scan                    # Escanear dispositivos"
echo "    bluesky attack bluejacking <MAC>  # Enviar mensaje"
echo "    bluesky attack whisperpair       # Detectar Fast Pair vulns"
echo "    bluesky report --html            # Generar reporte"
echo ""
echo "  Más información: $BLUESKY help"
echo ""
