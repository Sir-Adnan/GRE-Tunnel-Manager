#!/usr/bin/env bash
# Compatibility entry point. Since v1.6.0:
#   Agent:      curl -fsSL .../install.sh | sudo bash -s -- --agent [--operations] [--traffic]
#   Controller: sudo gtm controller enable --url https://IP_OR_DOMAIN:9443
set -euo pipefail
NODE_VERSION=1.7.0
NODE_REPOSITORY=Sir-Adnan/GRE-Tunnel-Manager

node_install_main() {
    local role='' url='' listen='' here installer
    local -a args=()
    while (($#)); do
        case $1 in
            --operations|--traffic) args+=("$1"); shift;;
            --controller|--agent) [[ -z $role ]] || { printf 'Choose one role.\n' >&2; return 1; }; role=${1#--}; shift;;
            --url|--listen|--package-dir)
                (($# >= 2)) && [[ -n $2 && $2 != --* ]] || { printf 'Missing option value.\n' >&2; return 1; }
                case $1 in --url) url=$2;; --listen) listen=$2;; --package-dir) args+=(--package-dir "$2");; esac
                shift 2;;
            --help|-h)
                printf 'node-install.sh is kept for compatibility.\n  Agent:      curl -fsSL https://raw.githubusercontent.com/%s/main/install.sh | sudo bash -s -- --agent [--operations] [--traffic]\n  Controller: sudo gtm controller enable --url https://IP_OR_DOMAIN:9443\n' "$NODE_REPOSITORY"
                return 0;;
            *) printf 'Unknown option. Run --help.\n' >&2; return 1;;
        esac
    done
    [[ -n $role ]] || { printf 'Choose --controller or --agent.\n' >&2; return 1; }
    if [[ $role == controller ]]; then
        [[ ${#args[@]} == 0 ]] || { printf '--operations, --traffic and --package-dir are Agent options.\n' >&2; return 1; }
        [[ -n $url ]] || { printf 'Provide --url for the Agent HTTPS listener.\n' >&2; return 1; }
        command -v gtm >/dev/null || { printf 'Install or update the panel first (install.sh); it provides the gtm command.\n' >&2; return 1; }
        local -a controller=(gtm controller enable --url "$url")
        [[ -z $listen ]] || controller+=(--listen "$listen")
        "${controller[@]}"
        return $?
    fi
    [[ -z $url && -z $listen ]] || { printf '--url and --listen are Controller options.\n' >&2; return 1; }
    here=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
    if [[ -f $here/install.sh ]]; then
        bash "$here/install.sh" --version "$NODE_VERSION" --agent "${args[@]}"
        return $?
    fi
    installer=$(mktemp)
    NODE_INSTALLER_TMP=$installer
    trap 'rm -f -- "$NODE_INSTALLER_TMP"' EXIT
    curl --proto '=https' --tlsv1.2 -fsSL --connect-timeout 15 --max-time 60 "https://raw.githubusercontent.com/$NODE_REPOSITORY/main/install.sh" -o "$installer" ||
        { printf 'Could not download install.sh.\n' >&2; return 1; }
    bash -n "$installer"
    bash "$installer" --version "$NODE_VERSION" --agent "${args[@]}"
}
if [[ ${BASH_SOURCE[0]} == "$0" ]]; then node_install_main "$@"; fi
