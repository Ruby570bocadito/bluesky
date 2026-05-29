# ==============================================================================
# Bluesky auto-completion para PowerShell
# ==============================================================================
# Instalación:
#   . .\scripts\completion\bluesky-completion.ps1
#   # o agregar al perfil: notepad $PROFILE
# ==============================================================================

# Registrar argument completer para bluesky.exe y bluesky.bat
$scriptblock = {
    param($wordToComplete, $commandAst, $cursorPosition)

    $commands = @(
        'scan', 'list', 'info', 'attack', 'services',
        'status', 'console', 'report', 'session', 'help'
    )

    $currentCommand = $commandAst.CommandElements[1].Value

    switch ($currentCommand) {
        'scan' {
            $opts = @('--ble', '--classic', '--timeout')
            return $opts | Where-Object { $_ -like "$wordToComplete*" }
        }
        'info' {
            return Get-BlueskyModules | Where-Object { $_ -like "$wordToComplete*" }
        }
        'attack' {
            return Get-BlueskyModules | Where-Object { $_ -like "$wordToComplete*" }
        }
        'report' {
            $opts = @('--html', '--json', '--txt', '--output')
            return $opts | Where-Object { $_ -like "$wordToComplete*" }
        }
        'session' {
            $subs = @('save', 'load', 'list', 'summary')
            return $subs | Where-Object { $_ -like "$wordToComplete*" }
        }
        default {
            return $commands | Where-Object { $_ -like "$wordToComplete*" }
        }
    }
}

# Función helper para obtener módulos desde Python
function Get-BlueskyModules {
    $modules = python3 -c "
import sys
sys.path.insert(0, 'bluesky')
from bluesky.core.engine import ModuleEngine
e = ModuleEngine()
for m in e.list_modules():
    print(m.get('name', ''))
" 2>$null
    return $modules -split "`n" | Where-Object { $_ -ne '' }
}

# Registrar el completer
if (-not (Get-Command Register-ArgumentCompleter -ErrorAction SilentlyContinue)) {
    Write-Warning "PowerShell 5.0+ requerido para auto-completion"
    return
}

Register-ArgumentCompleter -Native -CommandName bluesky -ScriptBlock $scriptblock
Register-ArgumentCompleter -Native -CommandName bluesky.bat -ScriptBlock $scriptblock

Write-Host "✓ Bluesky auto-completion para PowerShell registrado" -ForegroundColor Green
