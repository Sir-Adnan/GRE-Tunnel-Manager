# FRP transport is separate from the service's TCP/UDP protocol.
# TCPMUX here means FRP stream multiplexing (tcpMux), NOT HTTP CONNECT tcpmux proxies.
gtm_frp_validate() {
    [[ $P_ROLE == entrance || $P_ROLE == destination ]] && gtm_name "$P_NAME" && gtm_ip "$P_HOST" && gtm_ip "$P_LOCAL_IP" || return 1
    gtm_port "$P_CONTROL" && gtm_port "$P_PUBLIC" && gtm_port "$P_LOCAL_PORT" || return 1
    (( 10#$P_CONTROL != 10#$P_PUBLIC )) || return 1
    [[ $P_TRANSPORT =~ ^(tcp|websocket|wss|quic)$ && $P_PROTO =~ ^(tcp|udp)$ && $P_MUX =~ ^(true|false)$ ]] || return 1
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

gtm_frp_menu() {
    local choice id file unit bin name
    gtm_header 'FRP Manager'
    gtm_option 1 'Setup Server' 'Public entry server'
    gtm_option 2 'Setup Client' 'Server running your service'
    gtm_option 3 'List / remove' 'Managed FRP connections'
    gtm_option 0 Back
    gtm_read 'Choose: ' choice || return
    [[ $choice == 0 ]] && return
    [[ $choice != 3 ]] || { gtm_frp_remove; return; }
    case $choice in 1) P_ROLE=entrance;; 2) P_ROLE=destination;; *) return;; esac
    gtm_step 1 3 Ports
    gtm_ask_port 'Public port (users connect here)' 443 || return; P_PUBLIC=$GTM_REPLY
    gtm_ask_port 'Tunnel control port (same on both servers)' 7000 || return; P_CONTROL=$GTM_REPLY
    gtm_step 2 3 'Server & connection'
    gtm_ask_ip 'Public server IP' '' || return; P_HOST=$GTM_REPLY
    gtm_choose Transport tcp TCP tcp WebSocket websocket WSS wss QUIC quic || return; P_TRANSPORT=$GTM_REPLY
    gtm_choose 'TCP multiplexing' true Enabled true Disabled false || return; P_MUX=$GTM_REPLY
    P_LOCAL_IP=127.0.0.1; P_LOCAL_PORT=$P_PUBLIC; P_PROTO=tcp; P_GROUP=default
    printf '  Use the SAME token on both sides (24-128 letters/digits/_/-).\n'
    read -r -s -p '  Shared token: ' P_TOKEN || return; printf '\n'
    if [[ $P_ROLE == destination ]]; then
        gtm_ask_ip 'Service IP' 127.0.0.1 || return; P_LOCAL_IP=$GTM_REPLY
        gtm_ask_port 'Service port' "$P_PUBLIC" || return; P_LOCAL_PORT=$GTM_REPLY
        gtm_choose Protocol tcp TCP tcp UDP udp || return; P_PROTO=$GTM_REPLY
        gtm_read 'Load balance group [default]: ' P_GROUP || return; P_GROUP=${P_GROUP:-default}
    fi
    if [[ $P_TRANSPORT == wss ]]; then
        if [[ $P_ROLE == entrance ]]; then
            printf '  WSS uses HAProxy for TLS and a loopback-only FRP listener.\n'
            gtm_read 'Internal FRP control port [7001]: ' P_INTERNAL || return; P_INTERNAL=${P_INTERNAL:-7001}
            gtm_read 'TLS PEM path (certificate chain + private key; under /etc): ' P_GATEWAY_CERT || return
            [[ $P_GATEWAY_CERT == /etc/* && -r $P_GATEWAY_CERT ]] || { gtm_error 'Use a readable PEM file under /etc (service sandbox restriction).'; return; }
        else
            gtm_read 'Trusted CA / server certificate path (under /etc): ' P_TLS_CA || return
            [[ $P_TLS_CA == /etc/* && -r $P_TLS_CA ]] || { gtm_error 'Use a readable trusted certificate under /etc (service sandbox restriction).'; return; }
        fi
    fi
    gtm_default 'Connection name (same on both servers)' name "tunnel-$P_PUBLIC" || return
    [[ $name =~ ^[a-zA-Z0-9_-]{1,32}$ ]] || { gtm_error 'Use 1-32 letters, digits, dash or underscore.'; return; }
    P_NAME=$name
    gtm_frp_validate || { gtm_error 'Invalid connection settings.'; return; }
    gtm_step 3 3 Review
    printf '\n  %s / %s / %s / public port %s\n' "$P_ROLE" "$P_NAME" "$P_TRANSPORT" "$P_PUBLIC"
    printf '  Allow the control port and public service port in the host firewall.\n'
    if [[ $P_TRANSPORT == wss ]]; then printf '  WSS verifies the entrance certificate using the selected CA. Use an IP SAN matching the entrance IP.\n'
    else printf '  TLS encrypts the connection. This preset uses token authentication; custom CA verification is not configured.\n'; fi
    gtm_confirm || return
    gtm_prepare && gtm_install_component frp || return
    [[ $P_TRANSPORT != wss ]] || gtm_install_component haproxy || return
    gtm_lock || return
    id="gtm-frp-$P_ROLE-$P_NAME"
    if [[ $P_ROLE == entrance ]]; then
        if ! { gtm_local_address "$P_HOST" && gtm_port_available tcp "$P_HOST" "$P_CONTROL" && gtm_port_available both "$P_HOST" "$P_PUBLIC"; }; then gtm_unlock; return 1; fi
        if [[ $P_TRANSPORT == quic ]] && ! gtm_port_available udp "$P_HOST" "$P_CONTROL"; then gtm_unlock; return 1; fi
        if [[ $P_TRANSPORT == wss ]] && ! gtm_port_available tcp 127.0.0.1 "$P_INTERNAL"; then gtm_unlock; return 1; fi
    fi
    file="$GTM_CONFIG_DIR/$id.toml"; unit="$GTM_SERVICE_DIR/$id.service"
    if [[ -e $file || -e $unit ]]; then gtm_error 'Name already exists. Remove it or choose a new name.'; gtm_unlock; return; fi
    if [[ $P_ROLE == entrance ]]; then bin=$(command -v frps); else bin=$(command -v frpc); fi
    if ! { gtm_frp_render > "$file.tmp" && "$bin" verify -c "$file.tmp"; }; then rm -f "$file.tmp"; gtm_unlock; return 1; fi
    local gateway="gtm-gateway-$P_NAME" gateway_config="$GTM_CONFIG_DIR/gtm-gateway-$P_NAME.conf"
    if [[ $P_TRANSPORT == wss && $P_ROLE == entrance ]]; then
        if ! { gtm_wss_haproxy_render > "$gateway_config.tmp" && haproxy -c -f "$gateway_config.tmp"; }; then rm -f "$file.tmp" "$gateway_config.tmp"; gtm_unlock; return 1; fi
        mv "$gateway_config.tmp" "$gateway_config"; chmod 600 "$gateway_config"
        gtm_relay_unit "$(command -v haproxy)" "$gateway_config" "$P_NAME" | sed "s|^ExecStart=.*|ExecStart=$(command -v haproxy) -Ws -f $gateway_config|; /After=network-online.target/a PartOf=$id.service\nAfter=$id.service" > "$GTM_SERVICE_DIR/$gateway.service"
    fi
    mv "$file.tmp" "$file" && chmod 600 "$file" || { gtm_unlock; return 1; }
    gtm_relay_unit "$bin" "$file" "$P_NAME" > "$unit"
    [[ $P_TRANSPORT != wss || $P_ROLE != entrance ]] || sed -i "/After=network-online.target/a Wants=$gateway.service" "$unit"
    if ! { systemctl daemon-reload && systemctl enable --now "$id"; }; then
        systemctl disable --now "$id" 2>/dev/null
        [[ $P_TRANSPORT != wss || $P_ROLE != entrance ]] || { systemctl disable --now "$gateway" 2>/dev/null; rm -f "$GTM_SERVICE_DIR/$gateway.service" "$gateway_config"; }
        rm -f "$unit" "$file"; systemctl daemon-reload; gtm_unlock; return 1
    fi
    sleep 1
    if ! systemctl is-active --quiet "$id"; then
        journalctl -u "$id" -n 15 --no-pager
        systemctl disable --now "$id"
        [[ $P_TRANSPORT != wss || $P_ROLE != entrance ]] || { systemctl disable --now "$gateway" 2>/dev/null; rm -f "$GTM_SERVICE_DIR/$gateway.service" "$gateway_config"; }
        rm -f "$unit" "$file"; systemctl daemon-reload; gtm_unlock; return 1
    fi
    if [[ $P_TRANSPORT == wss && $P_ROLE == entrance ]] && ! systemctl is-active --quiet "$gateway"; then
        gtm_error 'FRP started but the TLS gateway failed. Check its journal.'
        systemctl disable --now "$id" "$gateway"; rm -f "$unit" "$file" "$GTM_SERVICE_DIR/$gateway.service" "$gateway_config"; systemctl daemon-reload; gtm_unlock; return 1
    fi
    gtm_unlock
    printf 'Connection service is running. Verify the public service from another host.\n'
}

gtm_frp_remove() {
    local file choice id index=0
    local -a files=()
    for file in "$GTM_SERVICE_DIR"/gtm-frp-*.service; do
        [[ -f $file && ${file##*/} =~ ^gtm-frp-(entrance|destination)-[a-zA-Z0-9_-]+\.service$ ]] || continue
        files+=("$file"); ((index+=1)); printf '  [%d] %s\n' "$index" "${file##*/}"
    done
    (( index > 0 )) || { printf 'No managed FRP connections.\n'; return; }
    gtm_read 'Remove row [0 cancels]: ' choice || return
    gtm_uint "$choice" 1 "$index" || return
    file=${files[$((10#$choice-1))]}; id=${file##*/}; id=${id%.service}
    printf 'Remove %s\n' "$id"
    gtm_confirm && gtm_prepare && gtm_lock || return
    if systemctl disable --now "$id"; then
        local gateway="gtm-gateway-${id#gtm-frp-entrance-}"
        if [[ $id == gtm-frp-entrance-* && -f $GTM_SERVICE_DIR/$gateway.service ]]; then
            systemctl disable --now "$gateway" || { gtm_unlock; return 1; }
            rm -f "$GTM_SERVICE_DIR/$gateway.service" "$GTM_CONFIG_DIR/$gateway.conf"
        fi
        rm -f "$file" "$GTM_CONFIG_DIR/$id.toml"; systemctl daemon-reload
    else gtm_error 'Could not stop service; files kept.'; fi
    gtm_unlock
}
