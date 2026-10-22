# Bounded Realm 2.x network options. Native transports remain separate adapters.
gtm_realm_defaults() {
    M_TCP_TIMEOUT=5; M_UDP_TIMEOUT=30; M_KEEPALIVE=15; M_PROBES=3
    M_SEND_PROXY=false; M_PROXY_VERSION=2; M_ACCEPT_PROXY=false; M_ACCEPT_TIMEOUT=5; M_LOG=warn
}
gtm_realm_options_validate() {
    local input=$1 pair key value
    local -a pairs=()
    local -A seen=()
    gtm_realm_defaults
    [[ -n $input && $input != ';'* && $input != *';' && $input != *';;'* ]] || return 1
    IFS=';' read -r -a pairs <<< "$input"
    ((${#pairs[@]}<=9)) || return 1
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
            *) return 1;;
        esac
    done
}
