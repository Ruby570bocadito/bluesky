<#
.SYNOPSIS
    Instalador de Bluesky para Windows nativo.
    Bluetooth Security Auditing Framework.

.DESCRIPTION
    Este script instala Bluesky y todas sus dependencias en Windows.
    Soporta Python 3.10+ y funciona con Bluetooth nativo de Windows.

    Requisitos:
    - Windows 10 2004+ (Build 19041+) o Windows 11
    - Python 3.10+ instalado
    - Bluetooth activado

    Componentes instalados:
    - Bluesky CLI + Consola interactiva
    - bleak (BLE Bluetooth nativo Windows)
    - pybluez2 (Bluetooth Classic opcional)
    - PowerShell scripts de detección Bluetooth
    - Accesos directos (opcional)

.EXAMPLE
    # Instalación normal
    .\install_windows.ps1

    # Instalación con ruta personalizada
    .\install_windows.ps1 -InstallDir "C:\tools\bluesky"

    # Solo dependencias (no copiar scripts)
    .\install_windows.ps1 -DepsOnly
#>

param(
    [string]$InstallDir = "$env:USERPROFILE\bluesky",
    [switch]$DepsOnly = $false,
    [switch]$NoShortcut = $false
)

$ErrorActionPreference = "Stop"
$Host.UI.RawUI.WindowTitle = "Instalando Bluesky..."

function Write-Step {
    param([string]$Message, [string]$Color = "Cyan")
    Write-Host "`n→ $Message" -ForegroundColor $Color
}

function Write-Success {
    param([string]$Message)
    Write-Host "  ✓ $Message" -ForegroundColor Green
}

function Write-Warning {
    param([string]$Message)
    Write-Host "  ⚠ $Message" -ForegroundColor Yellow
}

function Write-Error {
    param([string]$Message)
    Write-Host "  ✘ $Message" -ForegroundColor Red
}

# ─── Banner ─────────────────────────────────────────────────────────────────
Clear-Host
Write-Host @"

  ██████╗ ██╗     ██╗   ██╗███████╗██╗  ██╗██╗   ██╗
  ██╔══██╗██║     ██║   ██║██╔════╝██║ ██╔╝╚██╗ ██╔╝
  ██████╔╝██║     ██║   ██║███████╗█████╔╝  ╚████╔╝
  ██╔══██╗██║     ██║   ██║╚════██║██╔═██╗   ╚██╔╝
  ██████╔╝███████╗╚██████╔╝███████║██║  ██╗   ██║
  ╚═════╝ ╚══════╝ ╚═════╝ ╚══════╝╚═╝  ╚═╝   ╚═╝

"@ -ForegroundColor Cyan
Write-Host "  Bluetooth Security Auditing Framework" -ForegroundColor DarkCyan
Write-Host "  Instalador para Windows nativo`n" -ForegroundColor DarkCyan

# ─── Verificar Python ──────────────────────────────────────────────────────
Write-Step "Verificando Python..."

$python = $null
foreach ($cmd in @("python", "python3", "py")) {
    try {
        $version = & $cmd --version 2>&1
        if ($version -match "Python 3\.(\d+)") {
            if ([int]$Matches[1] -ge 10) {
                $python = $cmd
                Write-Success "Python detectado: $version ($cmd)"
                break
            }
        }
    } catch { continue }
}

if (-not $python) {
    Write-Error "Python 3.10+ no encontrado."
    Write-Host "  Descárgalo desde: https://www.python.org/downloads/" -ForegroundColor Yellow
    Write-Host "  (Asegúrate de marcar 'Add Python to PATH' durante la instalación)`n"
    exit 1
}

# ─── Verificar Bluetooth ────────────────────────────────────────────────────
Write-Step "Verificando Bluetooth..."

$btRadio = Get-PnpDevice -Class Bluetooth -ErrorAction SilentlyContinue |
           Where-Object { $_.FriendlyName -like '*Radio*' } |
           Select-Object -First 1

if (-not $btRadio) {
    Write-Warning "No se detectó radio Bluetooth en este equipo."
    Write-Warning "Bluesky funcionará limitado a BLE si instalas bleak."
}
elseif ($btRadio.Status -ne "OK") {
    Write-Warning "Bluetooth detectado pero apagado. Enciéndelo desde:"
    Write-Warning "  Configuración → Bluetooth y dispositivos"
}
else {
    Write-Success "Bluetooth detectado: $($btRadio.FriendlyName)"
}

# ─── Instalar dependencias Python ──────────────────────────────────────────
Write-Step "Instalando dependencias Python..."

$deps = @(
    "bleak",           # BLE cross-platform (Windows nativo)
    "rich",            # CLI interactiva mejorada
    "click",           # CLI framework
    "colorama",        # Colores en Windows terminal
    "pybluez2",        # Bluetooth Classic (opcional)
    "pytest",          # Testing
    "pytest-cov"       # Cobertura de tests
)

foreach ($dep in $deps) {
    try {
        $output = & $python -m pip install $dep --quiet 2>&1
        if ($LASTEXITCODE -eq 0) {
            Write-Success "$dep instalado"
        } else {
            Write-Warning "No se pudo instalar $dep (pip falló)"
        }
    } catch {
        Write-Warning "Error instalando $dep : $_"
    }
}

# ─── Verificar bleak (esencial para BLE en Windows) ────────────────────────
Write-Step "Verificando bleak (BLE)..."
try {
    & $python -c "import bleak; print('bleak', bleak.__version__)" 2>&1 | Out-Null
    Write-Success "bleak disponible - BLE funcionará en Windows"
} catch {
    Write-Warning "bleak no disponible. El escaneo BLE no funcionará."
    Write-Warning "Instálalo manualmente: pip install bleak"
}

# ─── Copiar archivos de Bluesky ────────────────────────────────────────────
if (-not $DepsOnly) {
    Write-Step "Instalando Bluesky en: $InstallDir"

    # Crear directorio
    New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null

    # Buscar origen (el script está en scripts/ del proyecto)
    $scriptPath = Split-Path -Parent $MyInvocation.MyCommand.Path
    $projectRoot = Resolve-Path "$scriptPath\.."

    if (Test-Path "$projectRoot\bluesky") {
        # Copy entire project
        Copy-Item "$projectRoot\bluesky" "$InstallDir\" -Recurse -Force
        Copy-Item "$projectRoot\scripts" "$InstallDir\" -Recurse -Force -ErrorAction SilentlyContinue
        Copy-Item "$projectRoot\tests" "$InstallDir\" -Recurse -Force -ErrorAction SilentlyContinue

        # Files at root level
        foreach ($file in @("setup.py", "requirements.txt", "README.md")) {
            if (Test-Path "$projectRoot\$file") {
                Copy-Item "$projectRoot\$file" "$InstallDir\" -Force
            }
        }

        Write-Success "Archivos copiados a $InstallDir"
    } else {
        Write-Warning "No se encuentra la carpeta 'bluesky' en $projectRoot"
        Write-Warning "Copiando solo el script actual"
    }

    # ─── Crear lanzador .bat ──────────────────────────────────────────────
    $batContent = @"
@echo off
title Bluesky - Bluetooth Security Auditor
echo.
python "%~dp0bluesky\cli.py" %*
echo.
if "%1"=="" (
    echo.
    echo Bluesky - Bluetooth Security Auditing Framework
    echo ===============================================
    echo.
    echo Comandos disponibles:
    echo   bluesky scan           Escanear dispositivos
    echo   bluesky list           Listar modulos
    echo   bluesky console        Consola interactiva
    echo   bluesky status         Estado del hardware
    echo   bluesky attack ^<mod^>  Ejecutar ataque
    echo.
    pause
)
"@
    $batPath = "$InstallDir\bluesky.bat"
    Set-Content -Path $batPath -Value $batContent -Encoding ASCII
    Write-Success "Lanzador creado: $batPath"

    # ─── Acceso directo en el Menú Inicio ─────────────────────────────────
    if (-not $NoShortcut) {
        $startMenu = "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\Bluesky"
        New-Item -ItemType Directory -Path $startMenu -Force | Out-Null

        $shortcutPath = "$startMenu\Bluesky Console.lnk"
        $WScriptShell = New-Object -ComObject WScript.Shell
        $shortcut = $WScriptShell.CreateShortcut($shortcutPath)
        $shortcut.TargetPath = "cmd.exe"
        $shortcut.Arguments = "/k python $InstallDir\bluesky\cli.py console"
        $shortcut.WorkingDirectory = "$InstallDir"
        $shortcut.Description = "Bluesky Bluetooth Security Auditor"
        $shortcut.Save()

        # Acceso directo en el escritorio
        $desktop = [Environment]::GetFolderPath("Desktop")
        $desktopShortcut = "$desktop\Bluesky.lnk"
        $shortcut2 = $WScriptShell.CreateShortcut($desktopShortcut)
        $shortcut2.TargetPath = "cmd.exe"
        $shortcut2.Arguments = "/k python $InstallDir\bluesky\cli.py console"
        $shortcut2.WorkingDirectory = "$InstallDir"
        $shortcut2.Description = "Bluesky Bluetooth Security Auditor"
        $shortcut2.Save()

        Write-Success "Accesos directos creados (Menú Inicio + Escritorio)"
    }

    # ─── Agregar al PATH del usuario ──────────────────────────────────────
    $userPath = [Environment]::GetEnvironmentVariable("PATH", "User")
    if ($userPath -notlike "*$InstallDir*") {
        [Environment]::SetEnvironmentVariable("PATH", "$userPath;$InstallDir", "User")
        Write-Success "Directorio agregado al PATH del usuario"
        Write-Warning "Reinicia la terminal para usar 'bluesky' directamente"
    }

    # ─── Verificar instalación ─────────────────────────────────────────────
    Write-Step "Verificando instalación..."
    try {
        $output = & $python "$InstallDir\bluesky\cli.py" list 2>&1
        if ($LASTEXITCODE -eq 0) {
            Write-Success "Bluesky instalado correctamente!"
        } else {
            Write-Warning "La instalación podría tener problemas: $output"
        }
    } catch {
        Write-Warning "No se pudo verificar: $_"
    }
}

# ─── Resumen final ──────────────────────────────────────────────────────────
Write-Host @"

╔══════════════════════════════════════════════════════════╗
║              BLUESKY INSTALADO EN WINDOWS               ║
╠══════════════════════════════════════════════════════════╣
║                                                        ║
║  Para usar:                                            ║
║                                                        ║
║    cd $InstallDir                                       ║
║    python bluesky\cli.py list                          ║
║    python bluesky\cli.py console                        ║
║    python bluesky\cli.py status                         ║
║                                                        ║
║  O desde cualquier terminal (si está en PATH):          ║
║                                                        ║
║    bluesky.bat list                                     ║
║    bluesky.bat console                                  ║
║                                                        ║
║  Requisitos para Bluetooth real:                       ║
║  • BLE:   bleak instalado (funciona en Windows)         ║
║  • Classic: pybluez2 o PowerShell (limitado)            ║
║                                                        ║
╚══════════════════════════════════════════════════════════╝

"@ -ForegroundColor Cyan
