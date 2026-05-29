#!/data/data/com.termux/files/usr/bin/bash
"""
Bluesky - Instalación para Termux (Android)
============================================
Instalación completa con Termux:API, BlueZ tools,
scripts de lanzamiento y auto-completado.
"""

set -e

echo ""
echo "  ╔══════════════════════════════════════════╗"
echo "  ║   Instalando Bluesky para Termux          ║"
echo "  ╚══════════════════════════════════════════╝"
echo ""

# ─── Verificar Termux ───────────────────────────────────────────────────────

if [ ! -d "/data/data/com.termux" ]; then
    echo "  ⚠️  Esto no parece ser Termux."
    echo "  Usa install_linux.sh para Linux.\n"
    exit 1
fi

# ─── [1/7] Repositorios ─────────────────────────────────────────────────────

echo "  [1/7] Actualizando repositorios..."
apt update -y || pkg update -y

# ─── [2/7] Dependencias Python ──────────────────────────────────────────────

echo "  [2/7] Instalando Python y dependencias..."
pkg install -y \
    python \
    python-pip \
    binutils \
    || true

# ─── [3/7] Bluetooth stack ─────────────────────────────────────────────────

echo "  [3/7] Instalando herramientas Bluetooth..."
pkg install -y \
    bluez \
    bluez-utils \
    hcitool \
    bluetoothctl \
    glib \
    || echo "  ⚠️  Algunos paquetes Bluetooth pueden no estar disponibles"

# ─── [4/7] Termux:API ──────────────────────────────────────────────────────

echo "  [4/7] Instalando Termux:API para Bluetooth nativo Android..."
pkg install -y termux-api termux-tools || true

echo ""
echo "  📱 IMPORTANTE: Concede permisos Bluetooth a Termux:"
echo "     Android Settings → Apps → Termux → Permissions"
echo "     Activa: Bluetooth y Location (necesario para BLE)"
echo ""

# ─── [5/7] Dependencias Python ─────────────────────────────────────────────

echo "  [5/7] Instalando dependencias Python..."
SCRIPT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
cd "$SCRIPT_DIR"

# Instalar dependencias del proyecto
if [ -f "setup.py" ] || [ -f "pyproject.toml" ] || [ -f "requirements.txt" ]; then
    pip install --user -e . 2>/dev/null || \
    pip install -e . 2>/dev/null || \
    pip install -r requirements.txt 2>/dev/null || \
    echo "  ⚠️  Instalación pip falló, usando ejecución directa"
fi

# Dependencias específicas para Termux
pip install --user bleak 2>/dev/null || true
pip install --user scapy 2>/dev/null || true
pip install --user cryptography 2>/dev/null || true
pip install --user rich 2>/dev/null || true

# ─── [6/7] Launcher ─────────────────────────────────────────────────────────

echo "  [6/7] Instalando launcher..."

# Copiar script de lanzamiento
if [ -f "scripts/bluesky-termux.sh" ]; then
    cp scripts/bluesky-termux.sh $PREFIX/bin/bluesky
    chmod +x $PREFIX/bin/bluesky
    echo "  ✅ Launcher instalado en $PREFIX/bin/bluesky"
fi

# ─── [7/7] Auto-completado (bash) ──────────────────────────────────────────

echo "  [7/7] Configurando auto-completado..."

if [ -f "scripts/completion/bluesky-completion.bash" ]; then
    cp scripts/completion/bluesky-completion.bash $PREFIX/etc/bash_completion.d/bluesky 2>/dev/null || \
    cp scripts/completion/bluesky-completion.bash $PREFIX/share/bash-completion/completions/bluesky 2>/dev/null || \
    echo "  ⚠️  No se pudo instalar auto-completado"
fi

# ─── Verificación ────────────────────────────────────────────────────────────

echo ""
echo "  ╔══════════════════════════════════════════╗"
echo "  ║   ✅ Bluesky instalado correctamente      ║"
echo "  ╚══════════════════════════════════════════╝"
echo ""

if command -v bluesky &>/dev/null; then
    echo "  Ejecuta: bluesky help"
    echo "  Escanea: bluesky scan"
else
    echo "  Ejecuta: python3 bluesky/cli.py help"
    echo "  Escanea: python3 bluesky/cli.py scan"
fi

echo ""
echo "  📱 GUÍA RÁPIDA TERMUX:"
echo "  ─────────────────────"
echo "  1. Activa Bluetooth en Ajustes del teléfono"
echo "  2. Concede permiso de ubicación (necesario para BLE)"
echo "  3. Verifica Bluetooth: termux-bluetooth-enable"
echo "  4. Escanea: bluesky scan"
echo "  5. Consola interactiva: bluesky console"
echo ""

# Verificar instalación
echo "  📋 Resumen de componentes:"
echo "  ───────────────────────"
for cmd in python3 termux-bluetooth termux-bluetooth-scan hcitool bluetoothctl bleak; do
    if command -v "$cmd" &>/dev/null; then
        echo "  ✅ $cmd"
    else
        echo "  ⚠️  $cmd (no encontrado)"
    fi
done
