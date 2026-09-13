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

    # Comandos principales (los mismos que enruta bluesky/cli.py)
    local COMMANDS="scan list info vuln auto attack services status report session console spam config plugin web educate help"

    # Opciones globales (las reales: -V/--version, --config, --no-color, --json)
    local GLOBAL_OPTS="-h --help -V --version --config --no-color --json"

    # Opciones por comando
    local SCAN_OPTS="--ble --classic --timeout --json"
    local SERVICES_OPTS="--json"
    local ATTACK_OPTS="--target --options --json"
    local VULN_OPTS="--options --json"
    local AUTO_OPTS="--mode --chain --timeout --json"
    local SPAM_OPTS="--method --rate --count --duration --delay --message --json"
    local REPORT_OPTS="--html --json --txt -o --output"
    local LIST_OPTS="--json"
    local STATUS_OPTS="--json"
    local WEB_OPTS="-p --port -H --host --debug -o --open"
    local SESSION_OPTS="save load list summary"

    if [[ $cword -eq 1 ]]; then
        # Primer argumento: comandos principales + flags globales
        COMPREPLY=($(compgen -W "$COMMANDS $GLOBAL_OPTS" -- "$cur"))
        return
    fi

    case "${words[1]}" in
        scan)
            COMPREPLY=($(compgen -W "$SCAN_OPTS" -- "$cur"))
            ;;
        services|vuln)
            if [[ $cword -eq 2 ]]; then
                COMPREPLY=()  # el target es una MAC
            else
                COMPREPLY=($(compgen -W "$SERVICES_OPTS $VULN_OPTS" -- "$cur"))
            fi
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
        auto)
            if [[ $cword -eq 2 ]]; then
                COMPREPLY=($(compgen -W "--mode --chain --timeout --json" -- "$cur"))
            else
                case "${words[2]}" in
                    --mode) COMPREPLY=($(compgen -W "detect attack full" -- "$cur")) ;;
                esac
            fi
            ;;
        spam)
            COMPREPLY=($(compgen -W "$SPAM_OPTS all" -- "$cur"))
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
        web)
            COMPREPLY=($(compgen -W "$WEB_OPTS" -- "$cur"))
            ;;
        educate)
            local topics=$(python3 -c "
import sys
sys.path.insert(0, 'bluesky')
from bluesky.core.education import covered_modules
for m in covered_modules():
    print(m)
" 2>/dev/null)
            COMPREPLY=($(compgen -W "$topics" -- "$cur"))
            ;;
        list|status)
            COMPREPLY=($(compgen -W "$LIST_OPTS $STATUS_OPTS" -- "$cur"))
            ;;
        console|config|plugin|help)
            # Sin autocompletado adicional
            ;;
        *)
            # Intentar completar archivos
            COMPREPLY=($(compgen -f -- "$cur"))
            ;;
    esac
}

complete -F _bluesky_complete bluesky
