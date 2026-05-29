#!/bin/bash
"""
Bluesky - Build standalone binary with PyInstaller
==================================================
Genera un binario único para Linux sin dependencias Python.
"""

set -e

echo ""
echo "  ╔══════════════════════════════════════════╗"
echo "  ║   Building Bluesky Standalone Binary     ║"
echo "  ╚══════════════════════════════════════════╝"
echo ""

SCRIPT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
cd "$SCRIPT_DIR"

# Verificar Python
echo "  [1/4] Verificando entorno..."
if ! command -v python3 &>/dev/null; then
    echo "  ERROR: Python 3 no encontrado"
    exit 1
fi

# Instalar dependencias
echo "  [2/4] Instalando dependencias de build..."
pip install --quiet pyinstaller 2>/dev/null || pip3 install --quiet pyinstaller 2>/dev/null
pip install --quiet -e . 2>/dev/null || true

# Verificar PyInstaller
if ! command -v pyinstaller &>/dev/null; then
    echo "  ERROR: PyInstaller no instalado"
    exit 1
fi

# Compilar
echo "  [3/4] Compilando binario..."
echo "       Target: bluesky"

pyinstaller \
    --onefile \
    --name bluesky \
    --clean \
    --noconfirm \
    --add-data "bluesky:bluesky" \
    bluesky/cli.py 2>&1 | tail -5

# Verificar resultado
echo "  [4/4] Verificando binario..."
if [ -f "dist/bluesky" ]; then
    SIZE=$(du -h "dist/bluesky" | cut -f1)
    echo ""
    echo "  ╔══════════════════════════════════════════╗"
    echo "  ║   ✅ Build completado!                    ║"
    echo "  ╚══════════════════════════════════════════╝"
    echo ""
    echo "  Binario: dist/bluesky ($SIZE)"
    echo "  Uso:     ./dist/bluesky help"
    echo "  Copia:   sudo cp dist/bluesky /usr/local/bin/"
else
    echo ""
    echo "  ❌ Build falló"
    exit 1
fi

# Limpiar
echo ""
echo "  Limpiando archivos temporales..."
rm -rf build/ __pycache__/ *.spec 2>/dev/null || true
echo "  Done!"
