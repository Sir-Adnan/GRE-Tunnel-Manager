# Shared pure validation and explicit command execution.
GTM_VERSION=1.3.0

gtm_error() { printf 'Error: %s\n' "$*" >&2; return 1; }

gtm_uint() {
    [[ $1 =~ ^[0-9]{1,6}$ ]] || return 1
    (( 10#$1 >= $2 && 10#$1 <= $3 ))
}

gtm_port() { gtm_uint "$1" 1 65535; }

gtm_ipv4() {
    local ip=$1 octet
    [[ $ip =~ ^([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})$ ]] || return 1
    for octet in "${BASH_REMATCH[@]:1}"; do
        [[ $octet == 0 || $octet != 0* ]] || return 1
        (( 10#$octet <= 255 )) || return 1
    done
}

gtm_ipv6() {
    local ip=$1 left right part count=0
    [[ $ip == *:* && $ip =~ ^[0-9a-fA-F:]+$ && ${#ip} -le 39 && $ip != *:::* ]] || return 1
    if [[ $ip == *::* ]]; then
        left=${ip%%::*}; right=${ip#*::}
        [[ $right != *::* ]] || return 1
        ip=${left:+$left:}$right
        for part in ${ip//:/ }; do [[ ${#part} -le 4 ]] || return 1; ((count+=1)); done
        (( count < 8 ))
    else
        [[ $ip != :* && $ip != *: ]] || return 1
        for part in ${ip//:/ }; do [[ ${#part} -le 4 ]] || return 1; ((count+=1)); done
        (( count == 8 ))
    fi
}

gtm_ip() { gtm_ipv4 "$1" || gtm_ipv6 "$1"; }

# A stable comparison key; equivalent IPv6 spellings must not evade ownership checks.
gtm_ip_key() {
    local address=$1 left right part missing index
    local -a words=() suffix=()
    gtm_ip "$address" || return 1
    if [[ $address != *:* ]]; then printf '%s' "$address"; return; fi
    if [[ $address == *::* ]]; then
        left=${address%%::*}; right=${address#*::}
        [[ -z $left ]] || IFS=: read -r -a words <<< "$left"
        [[ -z $right ]] || IFS=: read -r -a suffix <<< "$right"
        missing=$((8-${#words[@]}-${#suffix[@]}))
        for ((index=0; index<missing; index++)); do words+=(0); done
        words+=("${suffix[@]}")
    else IFS=: read -r -a words <<< "$address"; fi
    for part in "${words[@]}"; do printf '%04x' "$((16#$part))"; done
}
gtm_name() { [[ $1 =~ ^[a-zA-Z0-9][a-zA-Z0-9_.\ -]{0,39}$ ]]; }
gtm_id() { [[ $1 =~ ^F[0-9]{6}$ ]]; }
gtm_iface() { [[ $1 == any || $1 =~ ^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,14}$ ]]; }

# Sets EP_IP, EP_PORT and EP_WEIGHT. IPv6 endpoints use [address]:port@weight.
gtm_endpoint() {
    local value=$1 address port weight=1
    if [[ $value == *@* ]]; then weight=${value##*@}; value=${value%@*}; fi
    gtm_uint "$weight" 1 256 || return 1
    if [[ $value =~ ^\[([0-9a-fA-F:]+)\]:([0-9]+)$ ]]; then
        address=${BASH_REMATCH[1]}; port=${BASH_REMATCH[2]}
        gtm_ipv6 "$address" || return 1
    elif [[ $value =~ ^([0-9.]+):([0-9]+)$ ]]; then
        address=${BASH_REMATCH[1]}; port=${BASH_REMATCH[2]}
        gtm_ipv4 "$address" || return 1
    else return 1; fi
    gtm_port "$port" || return 1
    EP_IP=$address; EP_PORT=$((10#$port)); EP_WEIGHT=$((10#$weight))
}

gtm_address() { if [[ $1 == *:* ]]; then printf '[%s]:%s' "$1" "$2"; else printf '%s:%s' "$1" "$2"; fi; }

gtm_need() { command -v "$1" >/dev/null 2>&1 || gtm_error "Install the required tool first: $1"; }

gtm_root() {
    [[ ${GTM_DEMO:-0} == 0 ]] || { gtm_error 'Demo mode does not apply changes.'; return 1; }
    (( EUID == 0 )) || gtm_error 'Run with sudo to change server settings.'
}

gtm_pause() { [[ -t 0 ]] && { printf '\n'; read -r -p 'Enter to continue... ' _; }; return 0; }

gtm_confirm() {
    local answer
    printf '\n  [1] Confirm\n  [0] Cancel\n'
    gtm_default 'Select option' answer 0 || return 1
    [[ $answer == 1 || $answer == y || $answer == Y || $answer == yes ]]
}

gtm_paths() {
    GTM_CONFIG_DIR=${GTM_CONFIG_DIR:-/etc/gre-manager}
    GTM_STATE="$GTM_CONFIG_DIR/connections.tsv"
    GTM_RUN_DIR=${GTM_RUN_DIR:-/run/gre-manager}
    GTM_SERVICE_DIR=${GTM_SERVICE_DIR:-/etc/systemd/system}
    GTM_RUNTIME=${GTM_RUNTIME:-/usr/local/lib/gre-manager/apply.sh}
    GTM_SYSCTL_DIR=${GTM_SYSCTL_DIR:-/etc/sysctl.d}
    GTM_TUNING_STATE="$GTM_CONFIG_DIR/tuning.tsv"
    GTM_TUNING_FILE="$GTM_SYSCTL_DIR/99-z-gre-manager-owned.conf"
    GTM_SIMPLE_SCRIPT=${GTM_SIMPLE_SCRIPT:-/opt/simple_gre_script.sh}
    GTM_SIMPLE_UNIT="$GTM_SERVICE_DIR/simple-gre.service"
}

gtm_prepare() {
    gtm_root && gtm_need flock || return 1
    umask 077
    mkdir -p "$GTM_CONFIG_DIR" "$GTM_CONFIG_DIR/backups" "$GTM_RUN_DIR" || return 1
    chmod 700 "$GTM_CONFIG_DIR" "$GTM_CONFIG_DIR/backups" "$GTM_RUN_DIR" || return 1
}

gtm_lock() {
    exec 9>"$GTM_CONFIG_DIR/manager.lock" || return 1
    flock -x -w 10 9 || { exec 9>&-; gtm_error 'Another operation is running. Try again.'; }
}
gtm_unlock() { flock -u 9; exec 9>&-; }

# Legacy validators now share the same bounded input checks.
validate_port() { gtm_port "$1"; }
validate_ipv4() { gtm_ipv4 "$1"; }
validate_ipv6() { gtm_ipv6 "$1"; }
