# Bounded Realm 2.x network options. Native transports remain separate adapters.
gtm_realm_defaults() {
    M_TCP_TIMEOUT=5; M_UDP_TIMEOUT=30; M_KEEPALIVE=15; M_PROBES=3
    M_SEND_PROXY=false; M_PROXY_VERSION=2; M_ACCEPT_PROXY=false; M_ACCEPT_TIMEOUT=5; M_LOG=warn
    M_SEND_MPTCP=false; M_ACCEPT_MPTCP=false; M_IPV6_ONLY=false
    M_LISTEN_TRANSPORT=plain; M_REMOTE_TRANSPORT=plain; M_WS_HOST=localhost; M_WS_PATH=/
}
gtm_realm_options_validate() {
    local input=$1 pair key value
    local -a pairs=()
    local -A seen=()
    gtm_realm_defaults
    [[ -n $input && $input != ';'* && $input != *';' && $input != *';;'* ]] || return 1
    IFS=';' read -r -a pairs <<< "$input"
    ((${#pairs[@]}<=16)) || return 1
    for pair in "${pairs[@]}"; do
        [[ $pair == *=* ]] || return 1
        key=${pair%%=*}; value=${pair#*=}
        [[ -n $value && ! ${seen[$key]+set} ]] || return 1; seen[$key]=1
        case $key in
            tcp_timeout) gtm_uint "$value" 1 300 || return 1; M_TCP_TIMEOUT=$value;;
            udp_timeout) gtm_uint "$value" 1 3600 || return 1; M_UDP_TIMEOUT=$value;;
            tcp_keepalive) gtm_uint "$value" 0 3600 || return 1; M_KEEPALIVE=$value;;
            tcp_keepalive_probe) gtm_uint "$value" 1 30 || return 1; M_PROBES=$value;;
            send_proxy) [[ $value == true || $value == false ]] || return 1; M_SEND_PROXY=$value;;
            send_proxy_version) [[ $value == 1 || $value == 2 ]] || return 1; M_PROXY_VERSION=$value;;
            accept_proxy) [[ $value == true || $value == false ]] || return 1; M_ACCEPT_PROXY=$value;;
            accept_proxy_timeout) gtm_uint "$value" 1 300 || return 1; M_ACCEPT_TIMEOUT=$value;;
            log) [[ $value =~ ^(off|error|warn|info|debug|trace)$ ]] || return 1; M_LOG=$value;;
            send_mptcp|accept_mptcp|ipv6_only)
                [[ $value == true || $value == false ]] || return 1
                case $key in send_mptcp) M_SEND_MPTCP=$value;; accept_mptcp) M_ACCEPT_MPTCP=$value;; ipv6_only) M_IPV6_ONLY=$value;; esac;;
            listen_transport|remote_transport)
                [[ $value == plain || $value == ws ]] || return 1
                if [[ $key == listen_transport ]]; then M_LISTEN_TRANSPORT=$value; else M_REMOTE_TRANSPORT=$value; fi;;
            ws_host) [[ $value =~ ^[a-zA-Z0-9]([a-zA-Z0-9.-]{0,251}[a-zA-Z0-9])?$ ]] || return 1; M_WS_HOST=$value;;
            ws_path) [[ $value =~ ^/[a-zA-Z0-9/_.~-]{0,127}$ ]] || return 1; M_WS_PATH=$value;;
            *) return 1;;
        esac
    done
}

gtm_realm_profile_validate() {
    [[ $M_IPV6_ONLY != true || $R_BIND == *:* ]] || return 1
    [[ $R_PROTO != udp || ( $M_SEND_MPTCP == false && $M_ACCEPT_MPTCP == false ) ]] || return 1
    [[ $R_PROTO == tcp || ( $M_LISTEN_TRANSPORT == plain && $M_REMOTE_TRANSPORT == plain ) ]] || return 1
}

gtm_realm_profile_preflight() {
    local version
    if [[ $M_SEND_MPTCP == true || $M_ACCEPT_MPTCP == true || $M_IPV6_ONLY == true || $M_LISTEN_TRANSPORT != plain || $M_REMOTE_TRANSPORT != plain ]]; then
        version=$(realm --version) || return 1
        [[ $version =~ ^[Rr]ealm[[:space:]]+2\.9\.6([[:space:]]|$) ]] || { gtm_error 'Extended Realm profiles require the pinned Realm 2.9.6 binary.'; return 1; }
        if [[ $M_LISTEN_TRANSPORT != plain || $M_REMOTE_TRANSPORT != plain ]]; then
            [[ $version == *'[transport]'* ]] || { gtm_error 'This Realm binary was built without native transport support.'; return 1; }
        fi
    fi
    if [[ $M_SEND_MPTCP == true || $M_ACCEPT_MPTCP == true ]]; then
        [[ $(sysctl -n net.mptcp.enabled 2>/dev/null) == 1 ]] || { gtm_error 'MPTCP requires a compatible kernel with net.mptcp.enabled=1; no sysctl was changed.'; return 1; }
    fi
}
