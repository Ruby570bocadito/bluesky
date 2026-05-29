# ==============================================================================
# Bluesky auto-completion para Bash
# ==============================================================================
# Instalación:
#   source scripts/completion/bluesky-completion.bash
#   # o copiar a /etc/bash_completion.d/
# ==============================================================================

_bluesky_complete() {
    local cur prev words cword
    _init_completion || return

    # Comandos principales
    local COMMANDS="scan list info attack services status console report session help"

    # Opciones globales
    local GLOBAL_OPTS="-h --help --version -v -vv --verbose --debug --log-file"

    # Opciones por comando
    local SCAN_OPTS="--ble --classic --timeout"
    local REPORT_OPTS="--html --json --txt --output"
    local SESSION_OPTS="save load list summary"
    local ATTACK_OPTS="--options"

    if [[ $cword -eq 1 ]]; then
        # Primer argumento: comandos principales + flags
        COMPREPLY=($(compgen -W "$COMMANDS $GLOBAL_OPTS" -- "$cur"))
        return
    fi

    case "${words[1]}" in
        scan)
            COMPREPLY=($(compgen -W "$SCAN_OPTS" -- "$cur"))
            ;;
        info|attack)
            if [[ $cword -eq 2 ]]; then
                # Completar nombres de módulos
                local modules=$(python3 -c "
import sys, json
sys.path.insert(0, 'bluesky')
from bluesky.core.engine import ModuleEngine
e = ModuleEngine()
for m in e.list_modules():
    print(m.get('name', ''))
" 2>/dev/null)
                COMPREPLY=($(compgen -W "$modules" -- "$cur"))
            else
                COMPREPLY=($(compgen -W "$ATTACK_OPTS" -- "$cur"))
            fi
            ;;
        services)
            # Completar targets de la sesión actual si existen
            local targets=$(python3 -c "
import sys, json
sys.path.insert(0, 'bluesky')
from bluesky.core.session import Session
s = Session('')
if s.load():
    for t in s.targets:
        print(t.get('mac', ''))
" 2>/dev/null)
            COMPREPLY=($(compgen -W "$targets" -- "$cur"))
            ;;
        report)
            COMPREPLY=($(compgen -W "$REPORT_OPTS" -- "$cur"))
            ;;
        session)
            COMPREPLY=($(compgen -W "$SESSION_OPTS" -- "$cur"))
            local sessions=$(python3 -c "
import sys
sys.path.insert(0, 'bluesky')
from bluesky.core.session import Session
for s in Session.list_sessions():
    print(s)
" 2>/dev/null)
            if [[ $cword -eq 3 ]] && [[ "${words[2]}" == "load" || "${words[2]}" == "save" ]]; then
                COMPREPLY=($(compgen -W "$sessions" -- "$cur"))
            fi
            ;;
        console)
            # Sin autocompletado adicional para la consola interactiva
            ;;
        *)
            # Intentar completar archivos
            COMPREPLY=($(compgen -f -- "$cur"))
            ;;
    esac
}

complete -F _bluesky_complete bluesky
