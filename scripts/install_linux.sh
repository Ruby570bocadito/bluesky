#!/bin/bash
"""
Bluesky - Instalación para Linux
=================================
"""

set -e

echo ""
echo "  ╔══════════════════════════════════════════╗"
echo "  ║     Instalando Bluesky para Linux        ║"
echo "  ╚══════════════════════════════════════════╝"
echo ""

# Verificar Python
echo "  [1/4] Verificando Python..."
if command -v python3 &>/dev/null; then
    PYTHON=$(command -v python3)
    echo "       Python: $($PYTHON --version)"
else
    echo "       ERROR: Python 3 no encontrado"
    echo "       Instala: sudo apt install python3 python3-pip"
    exit 1
fi

# Instalar dependencias del sistema
echo "  [2/4] Instalando dependencias del sistema..."
if command -v apt &>/dev/null; then
    sudo apt update
    sudo apt install -y \
        python3-pip \
        python3-dev \
        bluez \
        bluez-tools \
        bluez-hcidump \
        libbluetooth-dev \
        || echo "       Algunos paquetes no están disponibles, continuando..."
elif command -v pacman &>/dev/null; then
    sudo pacman -Sy --noconfirm bluez bluez-utils python-pip
elif command -v dnf &>/dev/null; then
    sudo dnf install -y bluez bluez-tools python3-pip python3-devel
fi

# Instalar Bluesky
echo "  [3/4] Instalando Bluesky..."
SCRIPT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
cd "$SCRIPT_DIR"

if [ -f "setup.py" ]; then
    pip3 install --user -e .
    echo "       Bluesky instalado como paquete Python"
fi

# Crear enlace simbólico (opcional)
if [ ! -f "/usr/local/bin/bluesky" ]; then
    echo "       Creando enlace simbólico en /usr/local/bin/bluesky..."
    if command -v bluesky &>/dev/null; then
        echo "       ✅ bluesky ya está en el PATH"
    else
        sudo ln -sf "$(pwd)/bluesky/cli.py" /usr/local/bin/bluesky 2>/dev/null || \
        echo "       ⚠️  Crea un alias manual: alias bluesky='python3 $(pwd)/bluesky/cli.py'"
    fi
fi

# Verificar Bluetooth
echo "  [4/4] Verificando Bluetooth..."
if command -v systemctl &>/dev/null; then
    sudo systemctl enable bluetooth 2>/dev/null || true
    sudo systemctl start bluetooth 2>/dev/null || true
    echo "       Servicio Bluetooth iniciado"
fi

# Verificar instalación
if command -v bluesky &>/dev/null; then
    echo ""
    echo "  ╔══════════════════════════════════════════╗"
    echo "  ║   ✅ Bluesky instalado correctamente      ║"
    echo "  ╚══════════════════════════════════════════╝"
    echo ""
    echo "  Ejecuta: bluesky help"
    echo "  Escanea: bluesky scan"
    echo ""
else
    echo ""
    echo "  ╔══════════════════════════════════════════╗"
    echo "  ║   ✅ Instalación completada               ║"
    echo "  ╚══════════════════════════════════════════╝"
    echo ""
    echo "  Para usar: python3 bluesky/cli.py help"
    echo ""
fi
