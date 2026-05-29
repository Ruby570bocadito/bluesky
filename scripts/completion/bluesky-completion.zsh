# ==============================================================================
# Bluesky auto-completion para Zsh
# ==============================================================================
# Instalación:
#   source scripts/completion/bluesky-completion.zsh
#   # o copiar a /usr/local/share/zsh/site-functions/_bluesky
# ==============================================================================

#compdef bluesky

_bluesky() {
    local -a commands
    commands=(
        'scan:Escanear dispositivos Bluetooth cercanos'
        'list:Listar módulos de ataque'
        'info:Información detallada de un módulo'
        'attack:Ejecutar un ataque'
        'services:Enumerar servicios SDP'
        'status:Estado del hardware Bluetooth'
        'console:Consola interactiva'
        'report:Generar reporte'
        'session:Gestionar sesiones'
        'help:Ayuda'
    )

    local -a scan_opts
    scan_opts=(
        '--ble[Escanear solo BLE]'
        '--classic[Escanear solo Classic]'
        '--timeout[Timeout de escaneo (segundos)]'
    )

    local -a report_opts
    report_opts=(
        '--html[Formato HTML]'
        '--json[Formato JSON]'
        '--txt[Formato TXT]'
        '--output[Archivo de salida]'
    )

    # Cargar módulos desde Python para completar
    local -a modules
    modules=(${(f)"$(python3 -c "
import sys
sys.path.insert(0, 'bluesky')
from bluesky.core.engine import ModuleEngine
e = ModuleEngine()
for m in e.list_modules():
    name = m.get('name', '')
    desc = m.get('description', '')[:40]
    print(f'{name}:{desc}')
" 2>/dev/null)"})

    _arguments -C \
        '(-):command:->command' \
        '(-)*:options:->options'

    case $state in
        command)
            _describe -t commands 'bluesky commands' commands
            ;;
        options)
            case $words[1] in
                scan)
                    _arguments $scan_opts
                    ;;
                info|attack)
                    _describe -t modules 'attack modules' modules
                    ;;
                report)
                    _arguments $report_opts
                    ;;
                session)
                    local -a session_cmds
                    session_cmds=('save:Guardar sesión' 'load:Cargar sesión' 'list:Listar sesiones' 'summary:Resumen')
                    _describe -t session_cmds 'session commands' session_cmds
                    ;;
                services)
                    _arguments ':mac address:'
                    ;;
            esac
            ;;
    esac
}

_bluesky "$@"
