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
        'list:Listar módulos del catálogo'
        'info:Información detallada de un módulo'
        'vuln:Análisis de vulnerabilidades (13+ checks)'
        'auto:Autopilot: scan → vuln → attack → report'
        'attack:Ejecutar un módulo de ataque'
        'services:Enumerar servicios SDP'
        'status:Estado del hardware y backends'
        'report:Generar reporte de la sesión'
        'session:Gestionar sesiones'
        'console:Consola interactiva estilo Metasploit'
        'spam:BTSpam: inundación Bluetooth'
        'config:Ver o editar la configuración'
        'plugin:Gestionar plugins'
        'web:Dashboard web'
        'educate:Modo educativo'
        'help:Ayuda'
    )

    local -a global_opts scan_opts report_opts auto_opts spam_opts web_opts
    global_opts=(
        '(-V --version)'{-V,--version}'[Mostrar la versión y salir]'
        '--config[Archivo de configuración personalizado]'
        '--no-color[Desactivar color]'
        '--json[Salida JSON para scripting]'
    )
    scan_opts=(
        '--ble[Escanear solo BLE]'
        '--classic[Escanear solo Classic]'
        '--timeout[Timeout de escaneo (segundos)]'
        '--json[Salida JSON]'
    )
    report_opts=(
        '--html[Formato HTML]'
        '--json[Formato JSON]'
        '--txt[Formato TXT]'
        '(-o --output)'{-o,--output}'[Archivo de salida]'
    )
    auto_opts=(
        '--mode[Modo del pipeline]:mode:(detect attack full)'
        '--chain[Cadena personalizada: mod1,mod2,mod3]'
        '--timeout[Timeout por módulo (segundos)]'
        '--json[Salida JSON]'
    )
    spam_opts=(
        '--method[Técnica]:method:(all pairing_flood obex_spam connection_flood)'
        '--rate[Tasa por segundo]'
        '--count[Número de repeticiones]'
        '--duration[Duración (segundos)]'
        '--delay[Delay (ms)]'
        '--message[Mensaje a enviar]'
        '--json[Salida JSON]'
    )
    web_opts=(
        '(-p --port)'{-p,--port}'[Puerto del servidor]'
        '(-H --host)'{-H,--host}'[Host de escucha]'
        '--debug[Modo debug de Flask]'
        '(-o --open)'{-o,--open}'[Abrir el navegador]'
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
                    _describe -t modules 'módulos' modules
                    ;;
                auto)
                    _arguments $auto_opts
                    ;;
                spam)
                    _arguments $spam_opts
                    ;;
                report)
                    _arguments $report_opts
                    ;;
                web)
                    _arguments $web_opts
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
