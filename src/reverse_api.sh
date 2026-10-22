# Reverse adapters share the existing renderers and instance ownership rules.
gtm_api_reverse() {
    local engine line extra keys public_key result
    IFS= read -r line || return 1
    [[ $line != *$'\r'* && ${#line} -le 4096 ]] || return 1
    IFS= read -r extra && return 1
    local name role host control public local_ip local_port proto transport mux token group key cert internal fields
    fields=${line//[^$'\t']/}; ((${#fields}==15)) || return 1
    IFS=$'\t' read -r engine name role host control public local_ip local_port proto transport mux token group key cert internal <<< "$line"
    [[ $name =~ ^[a-zA-Z0-9_-]{1,32}$ ]] || return 1
    gtm_prepare && gtm_lock || return 1
    case $engine in
        frp)
            P_NAME=$name; P_ROLE=$role; P_HOST=$host; P_CONTROL=$control; P_PUBLIC=$public
            P_LOCAL_IP=$local_ip; P_LOCAL_PORT=$local_port; P_PROTO=$proto; P_TRANSPORT=$transport
            P_MUX=$mux; P_TOKEN=$token; P_GROUP=$group; P_INTERNAL=$internal
            P_GATEWAY_CERT=$cert; P_TLS_CA=$cert
            gtm_frp_create; result=$?;;
        rathole)
            RATH_NAME=$name; RATH_ROLE=$role; RATH_HOST=$host; RATH_CONTROL=$control; RATH_PUBLIC=$public
            RATH_LOCAL_IP=$local_ip; RATH_LOCAL_PORT=$local_port; RATH_PROTO=$proto; RATH_TOKEN=$token; RATH_KEY=$key
            if [[ $role == entrance ]]; then
                keys=$(rathole --genkey) || { gtm_unlock; return 1; }
                RATH_KEY=$(awk '/^Private Key:/ {getline; print; exit}' <<< "$keys")
                public_key=$(awk '/^Public Key:/ {getline; print; exit}' <<< "$keys")
                gtm_rathole_key "$public_key" || { gtm_unlock; return 1; }
            fi
            gtm_rathole_create; result=$?
            if ((result==0)) && [[ $role == entrance ]]; then printf 'Noise public key: %s\n' "$public_key"; fi;;
        *) result=1;;
    esac
    unset RATH_KEY RATH_TOKEN P_TOKEN keys token key
    gtm_unlock
    return "$result"
}

# Caller holds the manager lock; used by both web and terminal flows.
gtm_frp_create() {
    local id="gtm-frp-$P_ROLE-$P_NAME" file unit bin gateway gateway_config result=0
    gtm_frp_validate || return 1
    [[ $P_NAME =~ ^[a-zA-Z0-9_-]{1,32}$ ]] || return 1
    file="$GTM_CONFIG_DIR/$id.toml"; unit="$GTM_SERVICE_DIR/$id.service"
    [[ ! -e $file && ! -L $file && ! -e $unit && ! -L $unit ]] || { gtm_error 'Reverse instance already exists.'; return 1; }
    if [[ $P_ROLE == entrance ]]; then
        gtm_local_address "$P_HOST" && gtm_port_available tcp "$P_HOST" "$P_CONTROL" && gtm_port_available "$P_PROTO" "$P_HOST" "$P_PUBLIC" || return 1
        [[ $P_TRANSPORT != quic ]] || gtm_port_available udp "$P_HOST" "$P_CONTROL" || return 1
        [[ $P_TRANSPORT != wss ]] || gtm_port_available tcp 127.0.0.1 "$P_INTERNAL" || return 1
        bin=$(command -v frps) || return 1
    else bin=$(command -v frpc) || return 1; fi
    gateway="gtm-gateway-$P_NAME"; gateway_config="$GTM_CONFIG_DIR/$gateway.conf"
    gtm_frp_render > "$file.tmp" && "$bin" verify -c "$file.tmp" || { rm -f "$file.tmp"; return 1; }
    if [[ $P_TRANSPORT == wss && $P_ROLE == entrance ]]; then
        [[ ! -e $GTM_SERVICE_DIR/$gateway.service && ! -e $gateway_config ]] || { rm -f "$file.tmp"; return 1; }
        gtm_wss_haproxy_render > "$gateway_config.tmp" && haproxy -c -f "$gateway_config.tmp" || { rm -f "$file.tmp" "$gateway_config.tmp"; return 1; }
        mv "$gateway_config.tmp" "$gateway_config" && chmod 600 "$gateway_config" || return 1
        gtm_relay_unit "$(command -v haproxy)" "$gateway_config" "$P_NAME" | sed "s|^ExecStart=.*|ExecStart=$(command -v haproxy) -Ws -f $gateway_config|; /After=network-online.target/a PartOf=$id.service\nAfter=$id.service" > "$GTM_SERVICE_DIR/$gateway.service" || return 1
    fi
    mv "$file.tmp" "$file" && chmod 600 "$file" && gtm_relay_unit "$bin" "$file" "$P_NAME" > "$unit" || return 1
    [[ $P_TRANSPORT != wss || $P_ROLE != entrance ]] || sed -i "/After=network-online.target/a Wants=$gateway.service" "$unit"
    systemctl daemon-reload && systemctl enable --now "$id" || result=1
    if ((result==0)); then
        sleep 1
        systemctl is-active --quiet "$id" || result=1
        [[ $P_TRANSPORT != wss || $P_ROLE != entrance ]] || systemctl is-active --quiet "$gateway" || result=1
    fi
    if ((result)); then gtm_reverse_delete "$id" || gtm_error 'Reverse cleanup needs attention; files kept.'; return 1; fi
    printf 'Reverse connection configured. Verify the peer separately.\n'
}

gtm_reverse_delete() {
    local id=$1 gateway
    [[ $id =~ ^gtm-(frp|rathole)-(entrance|destination)-[a-zA-Z0-9_-]{1,32}$ ]] || return 1
    [[ -f $GTM_SERVICE_DIR/$id.service && -f $GTM_CONFIG_DIR/$id.toml ]] || return 1
    if [[ $id == gtm-rathole-* ]]; then gtm_rathole_cleanup "$id"; return $?; fi
    systemctl disable --now "$id" || return 1
    if [[ $id == gtm-frp-entrance-* ]]; then
        gateway="gtm-gateway-${id#gtm-frp-entrance-}"
        if [[ -f $GTM_SERVICE_DIR/$gateway.service ]]; then
            systemctl disable --now "$gateway" || return 1
            rm -f "$GTM_SERVICE_DIR/$gateway.service" "$GTM_CONFIG_DIR/$gateway.conf" || return 1
        fi
    fi
    rm -f "$GTM_SERVICE_DIR/$id.service" "$GTM_CONFIG_DIR/$id.toml" && systemctl daemon-reload
}
