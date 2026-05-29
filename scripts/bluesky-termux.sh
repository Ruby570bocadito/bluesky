#!/data/data/com.termux/files/usr/bin/bash
"""
bluesky - Termux Launcher
==========================
Wrapper script para ejecutar Bluesky en Termux (Android).
Configura el entorno, verifica dependencias y lanza la CLI.
"""

BLUESKY_DIR="$(cd "$(dirname "$0")/.." && pwd)"
PYTHON="${PYTHON:-python3}"

echo "  ╔══════════════════════════════════════════╗"
echo "  ║          Bluesky - Termux Edition         ║"
echo "  ║    Auditoría Bluetooth para Android       ║"
echo "  ╚══════════════════════════════════════════╝"
echo ""

# Verificar Python
if ! command -v "$PYTHON" &>/dev/null; then
    echo "  ❌ Python no encontrado."
    echo "  Instala: pkg install python"
    exit 1
fi

# Verificar Termux:API
if ! command -v termux-bluetooth &>/dev/null; then
    echo "  ⚠️  Termux:API no instalado."
    echo "     Algunas funciones pueden no estar disponibles."
    echo "     Instala: pkg install termux-api"
    echo "     Y concede: Android Settings → Termux → Permisos → Bluetooth"
    echo ""
fi

# Verificar Bluetooth
if command -v termux-bluetooth-scan &>/dev/null; then
    echo "  📡 Probando Bluetooth..."
    termux-bluetooth-scan --limit 1 &>/dev/null
    if [ $? -eq 0 ]; then
        echo "  ✅ Bluetooth disponible"
    else
        echo "  ⚠️  Bluetooth parece apagado."
        echo "     Actívalo: termux-bluetooth-enable"
        echo "     O desde: Android Settings → Bluetooth"
    fi
fi
echo ""

# Ejecutar Bluesky
cd "$BLUESKY_DIR"
export PYTHONPATH="$BLUESKY_DIR:$PYTHONPATH"
exec "$PYTHON" -m bluesky.cli "$@"
