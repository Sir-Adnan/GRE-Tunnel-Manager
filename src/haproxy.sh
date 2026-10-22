# HAProxy TCP adapter. All knobs have bounded values; no raw config snippets.
gtm_haproxy_defaults() {
    H_CONNECT=5; H_IDLE=3600; H_QUEUE=30; H_MAXCONN=16384; H_SERVER_MAXCONN=0
    H_CHECK_INTERVAL=3; H_CHECK_TIMEOUT=5; H_CHECK_FALL=3; H_CHECK_RISE=2; H_CHECK_PORT=0
    H_SLOWSTART=0; H_PROXY=off; H_LOG=connections
}

gtm_haproxy_values_validate() {
    gtm_uint "$H_CONNECT" 1 300 && gtm_uint "$H_IDLE" 10 604800 && gtm_uint "$H_QUEUE" 1 3600 &&
        gtm_uint "$H_MAXCONN" 1 100000 && gtm_uint "$H_SERVER_MAXCONN" 0 100000 &&
        gtm_uint "$H_CHECK_INTERVAL" 1 300 && gtm_uint "$H_CHECK_TIMEOUT" 1 300 &&
        gtm_uint "$H_CHECK_FALL" 1 20 && gtm_uint "$H_CHECK_RISE" 1 20 &&
        gtm_uint "$H_CHECK_PORT" 0 65535 && gtm_uint "$H_SLOWSTART" 0 3600 &&
        [[ $H_PROXY =~ ^(off|v1|v2)$ && $H_LOG =~ ^(connections|errors|off)$ ]]
}

gtm_haproxy_options_validate() {
    local options=$1 pair key value
    local -a pairs=()
    local -A seen=()
    [[ -n $options && $options != ';'* && $options != *';' && $options != *';;'* ]] || return 1
    gtm_haproxy_defaults
    IFS=';' read -r -a pairs <<< "$options"
    ((${#pairs[@]} <= 13)) || return 1
    for pair in "${pairs[@]}"; do
        [[ $pair == *=* ]] || return 1
        key=${pair%%=*}; value=${pair#*=}
        [[ -n $key && -n $value && ! ${seen[$key]+set} ]] || return 1
        seen[$key]=1
        case $key in
            connect) H_CONNECT=$value;; idle) H_IDLE=$value;; queue) H_QUEUE=$value;;
            maxconn) H_MAXCONN=$value;; server_maxconn) H_SERVER_MAXCONN=$value;;
            check_interval) H_CHECK_INTERVAL=$value;; check_timeout) H_CHECK_TIMEOUT=$value;;
            check_fall) H_CHECK_FALL=$value;; check_rise) H_CHECK_RISE=$value;; check_port) H_CHECK_PORT=$value;;
            slowstart) H_SLOWSTART=$value;; proxy) H_PROXY=$value;; log) H_LOG=$value;; *) return 1;;
        esac
    done
    gtm_haproxy_values_validate
}

gtm_haproxy_options() {
    gtm_haproxy_values_validate || return 1
    printf 'connect=%d;idle=%d;queue=%d;maxconn=%d;server_maxconn=%d;check_interval=%d;check_timeout=%d;check_fall=%d;check_rise=%d;check_port=%d;slowstart=%d;proxy=%s;log=%s' \
        "$((10#$H_CONNECT))" "$((10#$H_IDLE))" "$((10#$H_QUEUE))" "$((10#$H_MAXCONN))" "$((10#$H_SERVER_MAXCONN))" \
        "$((10#$H_CHECK_INTERVAL))" "$((10#$H_CHECK_TIMEOUT))" "$((10#$H_CHECK_FALL))" "$((10#$H_CHECK_RISE))" \
        "$((10#$H_CHECK_PORT))" "$((10#$H_SLOWSTART))" "$H_PROXY" "$H_LOG"
}

gtm_haproxy_socket() { gtm_id "$1" && printf '%s/haproxy/%s.sock' "$GTM_RUN_DIR" "$1"; }

gtm_haproxy_render() {
    local target index=0 algorithm=$R_STRATEGY
    local -a targets=()
    gtm_haproxy_values_validate || return 1
    case $algorithm in single|failover) algorithm=roundrobin;; esac
    printf 'global\n'
    [[ $H_LOG == off ]] || printf '    log stdout format raw local0\n'
    printf '    maxconn %d\n    user nobody\n    group nogroup\n' "$((10#$H_MAXCONN))"
    printf '    stats socket %s mode 600 level user\n    stats timeout 3s\n' "$(gtm_haproxy_socket "$R_ID")"
    printf 'defaults\n    mode tcp\n'
    [[ $H_LOG == off ]] || printf '    log global\n    option tcplog\n'
    [[ $H_LOG != errors ]] || printf '    option dontlog-normal\n'
    printf '    option clitcpka\n    option srvtcpka\n    retries 3\n    option redispatch\n'
    printf '    timeout connect %ds\n    timeout client %ds\n    timeout server %ds\n    timeout queue %ds\n    timeout check %ds\n' "$((10#$H_CONNECT))" "$((10#$H_IDLE))" "$((10#$H_IDLE))" "$((10#$H_QUEUE))" "$((10#$H_CHECK_TIMEOUT))"
    printf 'frontend entrance\n    bind %s\n    maxconn %d\n    default_backend destinations\nbackend destinations\n    balance %s\n' "$(gtm_address "$R_BIND" "$((10#$R_PORT))")" "$((10#$H_MAXCONN))" "$algorithm"
    [[ $algorithm != source ]] || printf '    hash-type consistent\n'
    IFS=, read -r -a targets <<< "$R_TARGETS"
    for target in "${targets[@]}"; do
        gtm_endpoint "$target" || return 1; ((index+=1))
        printf '    server target%d %s weight %d check inter %ds fall %d rise %d' "$index" "$(gtm_address "$EP_IP" "$EP_PORT")" "$EP_WEIGHT" "$((10#$H_CHECK_INTERVAL))" "$((10#$H_CHECK_FALL))" "$((10#$H_CHECK_RISE))"
        ((10#$H_CHECK_PORT == 0)) || printf ' port %d' "$((10#$H_CHECK_PORT))"
        ((10#$H_SERVER_MAXCONN == 0)) || printf ' maxconn %d' "$((10#$H_SERVER_MAXCONN))"
        ((10#$H_SLOWSTART == 0)) || printf ' slowstart %ds' "$((10#$H_SLOWSTART))"
        case $H_PROXY in v1) printf ' send-proxy';; v2) printf ' send-proxy-v2';; esac
        [[ $R_STRATEGY != failover || $index -le 1 ]] || printf ' backup'
        printf '\n'
    done
}

gtm_haproxy_unit() {
    local bin=$1 config=$2 id=$3
    local limit=$((2*10#$H_MAXCONN+2048))
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
    printf 'Health checks establish TCP reachability, not application correctness. Counters are worker-local and reset on reload.\n'
}

gtm_haproxy_settings() {
    local choice line original id options replacement result
    local -a rows=()
    gtm_records || return 1
    for line in "${GTM_RECORDS[@]}"; do
        gtm_record_validate "$line" || return 1
        [[ $R_ENGINE == haproxy ]] || continue
        rows+=("$line"); printf '  [%d] %s / %s\n' "${#rows[@]}" "$R_ID" "$R_NAME"
    done
    ((${#rows[@]})) || { printf 'Create a HAProxy connection first.\n'; return; }
    gtm_read 'Connection row [0 cancels]: ' choice || return
    gtm_uint "$choice" 1 "${#rows[@]}" || return
    original=${rows[$((10#$choice-1))]}
    gtm_record_validate "$original" || return 1; id=$R_ID
    while true; do
        gtm_header "HAProxy / $id / Advanced Settings"
        printf '  Changes stay in this form until Save & apply.\n\n'
        gtm_option 1 'Reset defaults'
        gtm_option 2 'VPN preset' 'Long connections / fewer logs'
        gtm_option 3 Timeouts
        gtm_option 4 'Health checks'
        gtm_option 5 'Connection limits'
        gtm_option 6 'PROXY protocol / logs'
        gtm_option 7 'Server status'
        gtm_option 8 'Save & apply'
        gtm_option 0 Cancel
        gtm_read 'Choose: ' choice || return
        case $choice in
            1) gtm_haproxy_defaults;;
            2) H_IDLE=86400; H_LOG=errors;;
            3) gtm_default 'Connect timeout [1-300s]' H_CONNECT "$H_CONNECT" && gtm_default 'Idle timeout [10-604800s]' H_IDLE "$H_IDLE" && gtm_default 'Queue timeout [1-3600s]' H_QUEUE "$H_QUEUE" || return;;
            4) gtm_default 'Check interval [1-300s]' H_CHECK_INTERVAL "$H_CHECK_INTERVAL" && gtm_default 'Check timeout [1-300s]' H_CHECK_TIMEOUT "$H_CHECK_TIMEOUT" && gtm_default 'Failed checks before down [1-20]' H_CHECK_FALL "$H_CHECK_FALL" && gtm_default 'Successful checks before up [1-20]' H_CHECK_RISE "$H_CHECK_RISE" && gtm_default 'Check port [0 = service port]' H_CHECK_PORT "$H_CHECK_PORT" || return;;
            5) gtm_default 'Connection cap [1-100000; measure RAM/FD usage]' H_MAXCONN "$H_MAXCONN" && gtm_default 'Per-target cap [0 = unlimited]' H_SERVER_MAXCONN "$H_SERVER_MAXCONN" && gtm_default 'Slow start [0-3600s]' H_SLOWSTART "$H_SLOWSTART" || return;;
            6)
                printf '  PROXY adds a header. Enable it on the destination first; otherwise traffic breaks.\n  It passes client metadata; it does not preserve the network source address.\n'
                gtm_choose 'PROXY protocol' "$H_PROXY" Off off 'Version 1' v1 'Version 2' v2 || continue
                H_PROXY=$GTM_REPLY
                gtm_choose Logs "$H_LOG" Connections connections 'Errors only' errors Off off || continue
                H_LOG=$GTM_REPLY;;
            7) (gtm_haproxy_status "$id"); gtm_pause;;
            8) break;; 0) return;; *) continue;;
        esac
    done
    options=$(gtm_haproxy_options) || { gtm_error 'Invalid HAProxy values. Nothing was saved.'; return 1; }
    gtm_record_validate "$original" || return 1
    R_VERSION=2; R_OPTIONS=$options; replacement=$(gtm_record_emit) || return 1
    [[ $replacement != "$original" ]] || { printf 'No changes.\n'; return; }
    printf 'Apply TCP settings to %s. A unit/FD-limit upgrade or engine change requires restart; compatible config changes use verified worker reload.\n' "$id"
    gtm_confirm && gtm_prepare && gtm_lock || return
    if ! { gtm_load_records && gtm_replace_record "$original" "$replacement"; }; then gtm_unlock; return 1; fi
    gtm_commit; result=$?
    gtm_unlock; gtm_pause
    return "$result"
}
