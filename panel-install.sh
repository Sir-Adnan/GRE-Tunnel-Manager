#!/usr/bin/env bash
# Compatibility entry point. Since v1.6.0 install.sh installs the panel and
# "gtm" maintains it; this script maps the earlier options onto them.
set -euo pipefail
PANEL_VERSION=1.6.1
PANEL_REPOSITORY=Sir-Adnan/GRE-Tunnel-Manager

# Maps the earlier options; the panel kept a self-signed default unless
# Let's Encrypt was requested, so --quick keeps that behavior.
panel_install_options() {
    PANEL_ARGS=()
    local protocol='' letsencrypt=false
    while (($#)); do
        case $1 in
            --quick|--yes) PANEL_ARGS+=(--yes); shift;;
            --uninstall) PANEL_ARGS+=(--remove); shift;;
            --install-engines) PANEL_ARGS+=(--engines); shift;;
            --letsencrypt) letsencrypt=true; shift;;
            --staging) letsencrypt=true; PANEL_ARGS+=(--staging); shift;;
            --protocol|--address|--domain|--port|--listen|--username|--email|--cloudflare-token-file|--package-dir)
                (($# >= 2)) && [[ -n $2 && $2 != --* ]] || { printf 'Missing value for %s\n' "$1" >&2; return 1; }
                case $1 in
                    --protocol) [[ $2 == http || $2 == https ]] || { printf 'Protocol must be https or http.\n' >&2; return 1; }; protocol=$2;;
                    --address|--domain) PANEL_ARGS+=(--domain "$2");;
                    --username) PANEL_ARGS+=(--user "$2");;
                    --email|--cloudflare-token-file) letsencrypt=true; PANEL_ARGS+=("$1" "$2");;
                    *) PANEL_ARGS+=("$1" "$2");;
                esac
                shift 2;;
            --help|-h)
                printf 'panel-install.sh is kept for compatibility. Use install.sh and gtm instead:\n  curl -fsSL https://raw.githubusercontent.com/%s/main/install.sh | sudo bash\n  sudo gtm --help\n' "$PANEL_REPOSITORY"
                return 2;;
            *) printf 'Unknown installer option. Run --help for supported options.\n' >&2; return 1;;
        esac
    done
    if [[ $letsencrypt == true && $protocol == http ]]; then
        printf 'Let'"'"'s Encrypt certificates need HTTPS; drop --protocol http.\n' >&2; return 1
    fi
    # Earlier releases used a self-signed certificate unless asked otherwise.
    # Removal takes no security option.
    if [[ " ${PANEL_ARGS[*]} " == *' --remove '* ]]; then return 0
    elif [[ $letsencrypt == true ]]; then PANEL_ARGS+=(--https)
    elif [[ $protocol == http ]]; then PANEL_ARGS+=(--http)
    elif [[ $protocol == https || " ${PANEL_ARGS[*]} " == *' --yes '* ]]; then PANEL_ARGS+=(--self-signed)
    fi
}

panel_install_main() {
    local result=0 here installer
    panel_install_options "$@" || result=$?
    [[ $result != 2 ]] || return 0
    [[ $result == 0 ]] || return "$result"
    here=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
    if [[ -f $here/install.sh ]]; then
        bash "$here/install.sh" --version "$PANEL_VERSION" "${PANEL_ARGS[@]}"
        return $?
    fi
    installer=$(mktemp)
    PANEL_INSTALLER_TMP=$installer
    trap 'rm -f -- "$PANEL_INSTALLER_TMP"' EXIT
    curl --proto '=https' --tlsv1.2 -fsSL --connect-timeout 15 --max-time 60 "https://raw.githubusercontent.com/$PANEL_REPOSITORY/main/install.sh" -o "$installer" ||
        { printf 'Could not download install.sh.\n' >&2; return 1; }
    bash -n "$installer"
    bash "$installer" --version "$PANEL_VERSION" "${PANEL_ARGS[@]}"
}

if [[ ${BASH_SOURCE[0]} == "$0" ]]; then panel_install_main "$@"; fi
