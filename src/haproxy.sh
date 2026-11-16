# HAProxy TCP adapter. All knobs have bounded values; no raw config snippets.
gtm_haproxy_defaults() {
    H_CONNECT=5; H_IDLE=3600; H_QUEUE=30; H_MAXCONN=16384; H_SERVER_MAXCONN=0
    H_CHECK_INTERVAL=3; H_CHECK_TIMEOUT=5; H_CHECK_FALL=3; H_CHECK_RISE=2; H_CHECK_PORT=0
    H_SLOWSTART=0; H_PROXY=off; H_LOG=connections
    H_CHECK_MODE=tcp; H_CHECK_PATH=/health; H_CHECK_HOST=localhost; H_CHECK_STATUS=200
    H_STICK=off; H_STICK_SIZE=16384; H_STICK_EXPIRE=1800
    H_FIN=0; H_TUNNEL=0; H_RETRIES=3
    gtm_routing_defaults
}

gtm_haproxy_values_validate() {
    gtm_uint "$H_CONNECT" 1 300 && gtm_uint "$H_IDLE" 10 604800 && gtm_uint "$H_QUEUE" 1 3600 &&
        gtm_uint "$H_MAXCONN" 0 1000000 && gtm_uint "$H_SERVER_MAXCONN" 0 1000000 &&
        gtm_uint "$H_CHECK_INTERVAL" 1 300 && gtm_uint "$H_CHECK_TIMEOUT" 1 300 &&
        gtm_uint "$H_CHECK_FALL" 1 20 && gtm_uint "$H_CHECK_RISE" 1 20 &&
        gtm_uint "$H_CHECK_PORT" 0 65535 && gtm_uint "$H_SLOWSTART" 0 3600 &&
        [[ $H_PROXY =~ ^(off|v1|v2)$ && $H_LOG =~ ^(connections|errors|off)$ ]] &&
        [[ $H_CHECK_MODE =~ ^(off|tcp|http)$ && $H_CHECK_PATH =~ ^/[a-zA-Z0-9/_.~-]{0,127}$ &&
            $H_CHECK_HOST =~ ^[a-zA-Z0-9]([a-zA-Z0-9.-]{0,251}[a-zA-Z0-9])?$ ]] &&
        gtm_uint "$H_CHECK_STATUS" 200 599 &&
        { [[ $H_CHECK_MODE != http ]] || ((10#$H_CHECK_PORT > 0)); } &&
        [[ $H_STICK == off || $H_STICK == source ]] && gtm_uint "$H_STICK_SIZE" 1024 1000000 && gtm_uint "$H_STICK_EXPIRE" 30 86400 &&
        gtm_uint "$H_FIN" 0 300 && gtm_uint "$H_TUNNEL" 0 604800 && gtm_uint "$H_RETRIES" 0 5
}

gtm_haproxy_options_validate() {
    local options=$1 pair key value
    local -a pairs=()
    local -A seen=()
    [[ -n $options && $options != ';'* && $options != *';' && $options != *';;'* ]] || return 1
    gtm_haproxy_defaults
    IFS=';' read -r -a pairs <<< "$options"
    ((${#pairs[@]} <= 32)) || return 1
    for pair in "${pairs[@]}"; do
        [[ $pair == *=* ]] || return 1
        key=${pair%%=*}; value=${pair#*=}
        [[ -n $key && -n $value && ! ${seen[$key]+set} ]] || return 1
        seen[$key]=1
        case $key in
            fin) H_FIN=$value;; tunnel) H_TUNNEL=$value;; retries) H_RETRIES=$value;;
            connect) H_CONNECT=$value;; idle) H_IDLE=$value;; queue) H_QUEUE=$value;;
            maxconn) H_MAXCONN=$value;; server_maxconn) H_SERVER_MAXCONN=$value;;
            check_interval) H_CHECK_INTERVAL=$value;; check_timeout) H_CHECK_TIMEOUT=$value;;
            check_fall) H_CHECK_FALL=$value;; check_rise) H_CHECK_RISE=$value;; check_port) H_CHECK_PORT=$value;;
            slowstart) H_SLOWSTART=$value;; proxy) H_PROXY=$value;; log) H_LOG=$value;;
            check_mode) H_CHECK_MODE=$value;; check_path) H_CHECK_PATH=$value;;
            check_host) H_CHECK_HOST=$value;; check_status) H_CHECK_STATUS=$value;;
            stick) H_STICK=$value;; stick_size) H_STICK_SIZE=$value;; stick_expire) H_STICK_EXPIRE=$value;; *) return 1;;
        esac
    done
    gtm_haproxy_values_validate
}

gtm_haproxy_socket() { gtm_id "$1" && printf '%s/haproxy/%s.sock' "$GTM_RUN_DIR" "$1"; }

gtm_haproxy_render() {
    local algorithm=$R_STRATEGY
    gtm_haproxy_values_validate || return 1
    case $algorithm in single|failover) algorithm=roundrobin;; esac
    printf 'global\n'
    [[ $H_LOG == off ]] || printf '    log stdout format raw local0\n'
    ((10#$H_MAXCONN == 0)) || printf '    maxconn %d\n' "$((10#$H_MAXCONN))"
    printf '    user nobody\n    group nogroup\n'
    printf '    stats socket %s mode 600 level user\n    stats timeout 3s\n' "$(gtm_haproxy_socket "$R_ID")"
    printf 'defaults\n    mode %s\n' "$([[ $H_ROUTE_MODE == http || $H_ROUTE_MODE == https ]] && printf http || printf tcp)"
    [[ $H_LOG == off ]] || printf '    log global\n    option %s\n' "$([[ $H_ROUTE_MODE == http || $H_ROUTE_MODE == https ]] && printf httplog || printf tcplog)"
    [[ $H_LOG != errors ]] || printf '    option dontlog-normal\n'
    printf '    option clitcpka\n    option srvtcpka\n    retries %d\n    option redispatch\n' "$((10#$H_RETRIES))"
    printf '    timeout connect %ds\n    timeout client %ds\n    timeout server %ds\n    timeout queue %ds\n    timeout check %ds\n' "$((10#$H_CONNECT))" "$((10#$H_IDLE))" "$((10#$H_IDLE))" "$((10#$H_QUEUE))" "$((10#$H_CHECK_TIMEOUT))"
    ((10#$H_FIN == 0)) || printf '    timeout client-fin %ds\n    timeout server-fin %ds\n' "$((10#$H_FIN))" "$((10#$H_FIN))"
    ((10#$H_TUNNEL == 0)) || printf '    timeout tunnel %ds\n' "$((10#$H_TUNNEL))"
    gtm_haproxy_frontend || return 1
    printf 'backend destinations\n    balance %s\n' "$algorithm"
    [[ $algorithm != source ]] || printf '    hash-type consistent\n'
    gtm_haproxy_servers 0 || return 1
    gtm_haproxy_route_backends
}

gtm_haproxy_servers() {
    local selected=${1:-0} target index=0
    local -a targets=()
    if [[ $H_STICK == source && $selected == 0 && $R_TARGETS == *,* ]]; then
        printf '    stick-table type ipv6 size %d expire %ds\n    stick on src\n' "$((10#$H_STICK_SIZE))" "$((10#$H_STICK_EXPIRE))"
    fi
    if [[ $H_CHECK_MODE == http ]]; then
        printf '    option httpchk\n    http-check send meth GET uri %s ver HTTP/1.1 hdr Host %s\n    http-check expect status %d\n' "$H_CHECK_PATH" "$H_CHECK_HOST" "$((10#$H_CHECK_STATUS))"
    fi
    IFS=, read -r -a targets <<< "$R_TARGETS"
    for target in "${targets[@]}"; do
        gtm_target "$target" || return 1; ((index+=1))
        ((selected==0 || index==10#$selected)) || continue
        printf '    server target%d %s weight %d' "$index" "$(gtm_address "$EP_IP" "$EP_PORT")" "$EP_WEIGHT"
        if [[ $H_CHECK_MODE != off ]]; then
            printf ' check inter %ds fall %d rise %d' "$((10#$H_CHECK_INTERVAL))" "$((10#$H_CHECK_FALL))" "$((10#$H_CHECK_RISE))"
            ((10#$H_CHECK_PORT == 0)) || printf ' port %d' "$((10#$H_CHECK_PORT))"
        fi
        ((10#$H_SERVER_MAXCONN == 0)) || printf ' maxconn %d' "$((10#$H_SERVER_MAXCONN))"
        ((10#$H_SLOWSTART == 0)) || printf ' slowstart %ds' "$((10#$H_SLOWSTART))"
        case $H_PROXY in v1) printf ' send-proxy';; v2) printf ' send-proxy-v2';; esac
        [[ $R_STRATEGY != failover || $index -le 1 || $selected != 0 ]] || printf ' backup'
        printf '\n'
    done
}

gtm_haproxy_unit() {
    local bin=$1 config=$2 id=$3
    local limit=$((2*10#$H_MAXCONN+2048))
    # An omitted maxconn delegates sizing to HAProxy and the inherited service
    # descriptor budget. Do not replace that budget with a small artificial cap.
    ((10#$H_MAXCONN != 0)) || limit=1048576
    cat <<EOF
# GTM HAProxy master-worker v1
[Unit]
Description=Traffic Manager HAProxy $id
Wants=network-online.target
After=network-online.target
[Service]
Type=simple
ExecStart=$bin -W -db -f $config
ExecReload=$bin -c -f $config
ExecReload=/bin/kill -USR2 \$MAINPID
KillMode=mixed
KillSignal=SIGUSR1
TimeoutStopSec=30
Restart=on-failure
RestartSec=5
LimitNOFILE=$limit
NoNewPrivileges=yes
ProtectHome=yes
ProtectSystem=strict
ReadWritePaths=$GTM_RUN_DIR
PrivateTmp=yes
RestrictSUIDSGID=yes
[Install]
WantedBy=multi-user.target
EOF
}

# Only read-only commands are exposed. No TCP admin/stats listener is created.
gtm_haproxy_query() {
    local id=$1 query=$2 socket
    [[ $query == 'show info' || $query == 'show stat' ]] || return 1
    socket=$(gtm_haproxy_socket "$id") || return 1
    [[ -S $socket ]] || { gtm_error "HAProxy socket unavailable: $socket"; return 1; }
    gtm_need socat && gtm_need timeout || return 1
    printf '%s\n' "$query" | timeout 5 socat -T 3 - "UNIX-CONNECT:$socket"
}

gtm_haproxy_pid() {
    local report pid
    report=$(gtm_haproxy_query "$1" 'show info') || return 1
    pid=$(awk -F': *' '$1 == "Pid" {gsub("\r", "", $2); print $2; exit}' <<< "$report")
    [[ $pid =~ ^[1-9][0-9]*$ ]] || return 1
    printf '%s' "$pid"
}

gtm_haproxy_wait() {
    local id=$1 previous=${2:-} pid attempt
    for ((attempt=0; attempt<15; attempt++)); do
        if systemctl is-active --quiet "gtm-$id" && pid=$(gtm_haproxy_pid "$id" 2>/dev/null) && [[ $pid != "$previous" ]]; then return 0; fi
        sleep 0.2
    done
    gtm_error "HAProxy did not expose a new ready worker: $id. Check its journal."
}

gtm_haproxy_status() {
    local id=$1 output
    gtm_id "$id" || return 1
    printf 'HAProxy %s / on-demand status\n' "$id"
    output=$(gtm_haproxy_query "$id" 'show stat') || return 1
    [[ $output == '# pxname,svname,'* ]] || { gtm_error 'Unexpected HAProxy stats response.'; return 1; }
    awk -F, 'NR == 1 {sub(/^# */, "", $1); for (i=1; i<=NF; i++) col[$i]=i; next}
        $1 == "destinations" && $2 != "BACKEND" {printf "  %-12s %-10s sessions=%s queued=%s total=%s check=%s\n", $2, $(col["status"]), $(col["scur"]), $(col["qcur"]), $(col["stot"]), $(col["check_status"])}' <<< "$output"
    printf 'Check results describe the configured TCP/HTTP readiness probe, not a VPN handshake. Counters reset on reload.\n'
}
