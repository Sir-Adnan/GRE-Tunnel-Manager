# Command-line entry. Tunnels are managed in the web panel; this script is its
# privileged engine (--api) plus a few read-only inspections. Run without
# arguments, it opens gtm (or installs the panel when gtm is missing).
GTM_RAW_URL=https://raw.githubusercontent.com/Sir-Adnan/GRE-Tunnel-Manager/main

gtm_usage() {
    printf 'GRE Tunnel Manager %s\n\n' "$GTM_VERSION"
    printf 'Tunnels are managed in the web panel. Run without arguments to open gtm\n(status, updates, HTTPS, port, password) or to install the panel.\n\n'
    printf 'Usage: sudo bash gre.sh [installer options]\n'
    printf 'Read only:\n  --validate | --plan [--state-file PATH]\n  --doctor | --catalog | --haproxy-status F000001 | --version\n'
    printf 'Engine (used by the panel): --api OPERATION ...\n'
}

# Download an installer and run it with the given options: install.sh for a
# plain run, panel-install.sh (which maps the pre-v1.6.0 options) otherwise.
# The script is syntax-checked first and removed afterwards.
gtm_install_panel() {
    local tmp result script=install.sh
    (($# == 0)) || script=panel-install.sh
    ((EUID==0)) || { gtm_error 'Run with sudo or as root to install the web panel.'; return 1; }
    [[ $(uname -s) == Linux ]] || { gtm_error 'The web panel runs on Linux with systemd.'; return 1; }
    gtm_need curl || return 1
    tmp=$(mktemp) || return 1
    if ! curl --proto '=https' --tlsv1.2 -fsSL --connect-timeout 15 --max-time 120 "$GTM_RAW_URL/$script" -o "$tmp"; then
        rm -f "$tmp"; gtm_error 'Could not download the panel installer.'; return 1
    fi
    bash -n "$tmp" && bash "$tmp" "$@"; result=$?
    rm -f "$tmp"
    return "$result"
}

gtm_main() {
    local action='' state_file='' status_id=''
    gtm_paths
    if [[ ${1:-} == --api ]]; then shift; gtm_api "$@"; return $?; fi
    if (($# == 0)); then
        # gtm is the maintenance command installed with the panel or Agent.
        if [[ -x /usr/local/bin/gtm ]]; then /usr/local/bin/gtm; return $?; fi
        gtm_install_panel; return $?
    fi
    while (( $# )); do
        case $1 in
            --help|-h) gtm_usage; return;;
            --version) printf 'v%s\n' "$GTM_VERSION"; return;;
            --validate|--plan|--doctor|--catalog) [[ -z $action ]] || { gtm_error 'Choose one inspection action.'; return 2; }; action=${1#--};;
            --haproxy-status) [[ -z $action && $# -ge 2 ]] && gtm_id "$2" || return 2; action=haproxy-status; status_id=$2; shift;;
            --state-file) (( $#>=2 )) && [[ -n $2 ]] || return 2; state_file=$2; shift;;
            # Anything else is for the installer (--quick, --port, --uninstall ...).
            *) [[ -z $action && -z $state_file ]] || { gtm_error "Unknown argument: $1"; return 2; }
                gtm_install_panel "$@"; return $?;;
        esac
        shift
    done
    if [[ -n $state_file && $action != validate && $action != plan ]]; then gtm_error '--state-file requires --validate or --plan.'; return 2; fi
    case $action in
        validate) gtm_inspect_state "${state_file:-$GTM_STATE}";;
        plan) gtm_plan "${state_file:-$GTM_STATE}";;
        doctor) gtm_doctor;;
        catalog) gtm_catalog;;
        haproxy-status) gtm_haproxy_status "$status_id";;
        *) gtm_usage; return 2;;
    esac
}
