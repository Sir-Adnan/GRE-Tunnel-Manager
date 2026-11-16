# FRP transport is separate from the service's TCP/UDP protocol.
# TCPMUX here means FRP stream multiplexing (tcpMux), NOT HTTP CONNECT tcpmux proxies.
gtm_frp_validate() {
    [[ $P_ROLE == entrance || $P_ROLE == destination ]] && gtm_name "$P_NAME" && gtm_ip "$P_HOST" && gtm_ip "$P_LOCAL_IP" || return 1
    gtm_port "$P_CONTROL" && gtm_port "$P_PUBLIC" && gtm_port "$P_LOCAL_PORT" || return 1
    (( 10#$P_CONTROL != 10#$P_PUBLIC )) || return 1
    [[ $P_TRANSPORT =~ ^(tcp|websocket|wss|quic|kcp)$ && $P_PROTO =~ ^(tcp|udp)$ && $P_MUX =~ ^(true|false)$ ]] || return 1
    [[ $P_TOKEN =~ ^[a-zA-Z0-9_-]{24,128}$ && $P_GROUP =~ ^[a-zA-Z0-9_-]{1,32}$ ]] || return 1
    if [[ $P_TRANSPORT == wss ]]; then
        if [[ $P_ROLE == entrance ]]; then
            gtm_port "${P_INTERNAL:-7001}" && [[ ${P_GATEWAY_CERT:-} =~ ^/[a-zA-Z0-9_./-]+$ ]] || return 1
            (( 10#${P_INTERNAL:-7001} != 10#$P_PUBLIC && 10#${P_INTERNAL:-7001} != 10#$P_CONTROL )) || return 1
        else [[ ${P_TLS_CA:-} =~ ^/[a-zA-Z0-9_./-]+$ ]] || return 1; fi
    fi
}

gtm_frp_render() {
    gtm_frp_validate || return 1
    printf 'log.to = "console"\n'
    if [[ $P_ROLE == entrance ]]; then
        if [[ $P_TRANSPORT == wss ]]; then printf 'bindAddr = "127.0.0.1"\nbindPort = %d\n' "$((10#${P_INTERNAL:-7001}))"
        else printf 'bindAddr = "%s"\nbindPort = %d\n' "$P_HOST" "$((10#$P_CONTROL))"; fi
        [[ $P_TRANSPORT != quic ]] || printf 'quicBindPort = %d\n' "$((10#$P_CONTROL))"
        [[ $P_TRANSPORT != kcp ]] || printf 'kcpBindPort = %d\n' "$((10#$P_CONTROL))"
        printf 'proxyBindAddr = "%s"\nallowPorts = [{ single = %d }]\n' "$P_HOST" "$((10#$P_PUBLIC))"
        printf 'auth.method = "token"\nauth.token = "%s"\ntransport.tls.force = %s\ntransport.tcpMux = %s\n' "$P_TOKEN" "$([[ $P_TRANSPORT == wss ]] && echo false || echo true)" "$P_MUX"
    else
        printf 'serverAddr = "%s"\nserverPort = %d\nauth.method = "token"\nauth.token = "%s"\n' "$P_HOST" "$((10#$P_CONTROL))" "$P_TOKEN"
        printf 'transport.protocol = "%s"\ntransport.tcpMux = %s\ntransport.tls.enable = true\n' "$P_TRANSPORT" "$P_MUX"
        [[ $P_TRANSPORT != wss ]] || printf 'transport.tls.trustedCaFile = "%s"\n' "$P_TLS_CA"
        printf '\n[[proxies]]\nname = "%s"\ntype = "%s"\nlocalIP = "%s"\nlocalPort = %d\nremotePort = %d\n' "$P_NAME" "$P_PROTO" "$P_LOCAL_IP" "$((10#$P_LOCAL_PORT))" "$((10#$P_PUBLIC))"
        if [[ $P_PROTO == tcp ]]; then
            printf 'loadBalancer.group = "%s"\nloadBalancer.groupKey = "%s"\nhealthCheck.type = "tcp"\nhealthCheck.timeoutSeconds = 3\nhealthCheck.maxFailed = 3\nhealthCheck.intervalSeconds = 10\n' "$P_GROUP" "$P_TOKEN"
        fi
    fi
}

gtm_wss_haproxy_render() {
    printf 'global\n    log stdout format raw local0\n    user nobody\n    group nogroup\ndefaults\n    mode tcp\n    timeout connect 5s\n    timeout client 1h\n    timeout server 1h\nfrontend wss_entrance\n    bind %s ssl crt %s\n    default_backend local_frps\nbackend local_frps\n    server local 127.0.0.1:%d\n' "$(gtm_address "$P_HOST" "$P_CONTROL")" "$P_GATEWAY_CERT" "$((10#${P_INTERNAL:-7001}))"
}
