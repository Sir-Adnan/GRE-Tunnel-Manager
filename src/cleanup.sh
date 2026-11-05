# Retirement of installations made before the record-based manager (v13.x
# scripts, Simple GRE, historical tuning files). Only generator-owned syntax
# is recognized; anything unknown is reported and kept for the operator.
FW_SCRIPT=/usr/local/bin/gre_custom_rules.sh
FW_SERVICE=/etc/systemd/system/gre-custom-rules.service
SYSCTL_FILE=/etc/sysctl.d/99-gre-tuning.conf
PERF_SYSCTL_FILE=/etc/sysctl.d/98-gre-highload.conf
PERF_MODULES_FILE=/etc/modules-load.d/gre-conntrack.conf
PERF_SCRIPT=/usr/local/bin/gre_perf.sh
PERF_SERVICE=/etc/systemd/system/gre-perf.service

# New listeners must not collide with forwards an old script still adds at boot.
gtm_legacy_listener_check() {
    local protocol=$1 bind=$2 port=$3 file line
    local -a words=()
    for file in "$FW_SCRIPT" /opt/simple_gre_script.sh; do
        [[ -r $file ]] || continue
        while IFS= read -r line; do
            read -r -a words <<< "$line"
            [[ ${#words[@]} == 13 && ${words[0]} =~ ^(iptables|ip6tables)$ && ${words[1]} == -t && ${words[2]} == nat && ${words[3]} == -A && ${words[4]} == PREROUTING && ${words[5]} == -p && ${words[7]} == --dport && ${words[9]} == -j && ${words[10]} == DNAT && ${words[11]} == --to-destination ]] || continue
            if [[ $bind == *:* ]]; then [[ ${words[0]} == ip6tables ]] || continue; else [[ ${words[0]} == iptables ]] || continue; fi
            [[ $protocol == both || $protocol == "${words[6]}" ]] || continue
            gtm_port "${words[8]}" || continue
            ((10#${words[8]} == 10#$port)) || continue
            gtm_error "An existing legacy forward already uses this entrance port. Retire it under Tools -> Retire old installation first."
            return 1
        done < "$file"
    done
    return 0
}

# Strictly recognize generator-owned legacy DNAT syntax. Unknown/manual lines stay.
gtm_legacy_delete_group() {
    local line cmd localport dest choice index=0 key file deleted=0 failed=0
    local -a keys=() lines=() keep=() args=()
    local -A seen=()
    [[ -f $FW_SCRIPT ]] || { printf 'No legacy rules file.\n'; return; }
    mapfile -t lines < "$FW_SCRIPT"
    for line in "${lines[@]}"; do
        read -r -a args <<< "$line"
        # The normal generated line has 13 words, including the destination.
        [[ ${#args[@]} == 13 && ${args[0]} =~ ^(iptables|ip6tables)$ && ${args[1]} == -t && ${args[2]} == nat && ${args[3]} == -A && ${args[4]} == PREROUTING && ${args[5]} == -p && ${args[6]} =~ ^(tcp|udp)$ && ${args[7]} == --dport && ${args[9]} == -j && ${args[10]} == DNAT && ${args[11]} == --to-destination ]] || continue
        gtm_port "${args[8]}" && gtm_endpoint "${args[12]}" || continue
        key="${args[0]}|${args[8]}|${args[12]}"
        [[ ${seen[$key]+set} ]] && continue
        seen[$key]=1; keys+=("$key"); ((index+=1)); printf '  [%d] %s -> %s (%s)\n' "$index" "${args[8]}" "${args[12]}" "${args[0]}"
    done
    ((index>0)) || { printf 'No recognized generated groups. Manual rules were kept.\n'; return; }
    gtm_read 'Delete group row [0 cancels]: ' choice || return
    gtm_uint "$choice" 1 "$index" || return
    key=${keys[$((10#$choice-1))]}; IFS='|' read -r cmd localport dest <<< "$key"
    gtm_need "$cmd" && "$cmd" -t nat -S PREROUTING >/dev/null || return 1
    gtm_endpoint "$dest" || return
    local dest_ip=$EP_IP dest_port=$EP_PORT proto shared=0 other other_cmd other_port other_dest
    for other in "${keys[@]}"; do
        [[ $other != "$key" ]] || continue
        IFS='|' read -r other_cmd other_port other_dest <<< "$other"
        [[ $other_cmd != "$cmd" || $other_dest != "$dest" ]] || shared=1
    done
    printf 'Remove both TCP/UDP forwarding for :%s -> %s\n' "$localport" "$dest"
    gtm_confirm || return
    cp "$FW_SCRIPT" "$GTM_CONFIG_DIR/backups/legacy-$(date -u +%Y%m%dT%H%M%S)-$$.sh" || return
    for line in "${lines[@]}"; do
        local owned=0
        for proto in tcp udp; do
            if [[ $line == "$cmd -t nat -A PREROUTING -p $proto --dport $localport -j DNAT --to-destination $dest" ]]; then owned=1; fi
            if ((shared==0)) && [[ $line == "$cmd -t nat -A POSTROUTING -d $dest_ip -p $proto --dport $dest_port -j MASQUERADE" || $line == "$cmd -I FORWARD -d $dest_ip -p $proto --dport $dest_port -j ACCEPT" ]]; then owned=1; fi
        done
        if ((owned)); then
            read -r -a args <<< "$line"
            for index in "${!args[@]}"; do [[ ${args[$index]} != -A && ${args[$index]} != -I ]] || { args[$index]=-D; break; }; done
            # Check existence, then require deletion to succeed; drain duplicates.
            local -a check=("${args[@]}")
            for index in "${!check[@]}"; do [[ ${check[$index]} != -D ]] || { check[$index]=-C; break; }; done
            while "$cmd" "${check[@]:1}" 2>/dev/null; do
                "$cmd" "${args[@]:1}" || { failed=1; break; }
                ((deleted+=1)); ((deleted<10000)) || { failed=1; break; }
            done
        else keep+=("$line"); fi
    done
    ((failed==0)) || { gtm_error 'Too many duplicate rules; configuration kept for inspection.'; return; }
    file=$(mktemp "${FW_SCRIPT}.XXXXXX") || return
    printf '%s\n' "${keep[@]}" > "$file" && chmod 700 "$file" && mv "$file" "$FW_SCRIPT"
    printf 'Removed legacy group and its duplicates.\n'
}

# Closed legacy inventory. Never execute a saved shell line or flush host tables.
gtm_legacy_inspect() {
    [[ -f $FW_SCRIPT && -r $FW_SCRIPT ]] || { printf 'No readable legacy forwarding file.\n'; return; }
    printf 'Legacy persistence / read only: %s\n' "$FW_SCRIPT"
    cat "$FW_SCRIPT"
    printf '\nUse grouped deletion or recognized-resource cleanup; add new connections in Traffic connections.\nRaw saved scripts are not executed by this inspection.\n'
    gtm_pause
}

gtm_legacy_dnat() {
    local line=$1
    read -r -a L_ARGS <<< "$line"
    [[ ${#L_ARGS[@]} == 13 && ${L_ARGS[0]} =~ ^(iptables|ip6tables)$ && ${L_ARGS[1]} == -t && ${L_ARGS[2]} == nat && ${L_ARGS[3]} == -A && ${L_ARGS[4]} == PREROUTING && ${L_ARGS[5]} == -p && ${L_ARGS[6]} =~ ^(tcp|udp)$ && ${L_ARGS[7]} == --dport && ${L_ARGS[9]} == -j && ${L_ARGS[10]} == DNAT && ${L_ARGS[11]} == --to-destination && ${L_ARGS[12]} != *@* ]] || return 1
    gtm_port "${L_ARGS[8]}" && gtm_endpoint "${L_ARGS[12]}" || return 1
    if [[ ${L_ARGS[0]} == iptables ]]; then [[ $EP_IP != *:* ]]; else [[ $EP_IP == *:* ]]; fi
}

gtm_legacy_drain_rule() {
    local line=$1 index count=0 status
    local -a args=() check=()
    read -r -a args <<< "$line"
    for index in "${!args[@]}"; do [[ ${args[$index]} != -A && ${args[$index]} != -I ]] || { args[$index]=-D; break; }; done
    check=("${args[@]}"); check[$index]=-C
    while true; do
        if "${check[@]}" 2>/dev/null; then
            "${args[@]}" || return 1
            ((count+=1)); ((count<10000)) || { gtm_error 'Rule duplicate limit exceeded; persistence was kept.'; return 1; }
        else
            status=$?
            ((status==1)) || { gtm_error 'Firewall check failed; persistence was kept.'; return 1; }
            break
        fi
    done
}

gtm_legacy_forward_unit() {
    cat <<EOF
[Unit]
Description=GRE Custom Forwarding Rules
After=network.target
[Service]
Type=oneshot
ExecStart=$FW_SCRIPT
RemainAfterExit=yes
[Install]
WantedBy=multi-user.target
EOF
}

gtm_simple_unit() {
    cat <<EOF
[Unit]
Description=Simple GRE Tunnel Setup
After=network.target
[Service]
Type=oneshot
ExecStart=$GTM_SIMPLE_SCRIPT
RemainAfterExit=yes
[Install]
WantedBy=multi-user.target
EOF
}

gtm_cleanup_backup() {
    local source=$1 unit=$2
    GTM_CLEANUP_BACKUP="$GTM_CONFIG_DIR/backups/cleanup-$(date -u +%Y%m%dT%H%M%S)-$$-$RANDOM"
    mkdir "$GTM_CLEANUP_BACKUP" && chmod 700 "$GTM_CLEANUP_BACKUP" && cp "$source" "$GTM_CLEANUP_BACKUP/source.sh" || return 1
    [[ ! -f $unit ]] || cp "$unit" "$GTM_CLEANUP_BACKUP/source.service" || return 1
    chmod 600 "$GTM_CLEANUP_BACKUP"/*
}

gtm_legacy_plan_all() {
    local line target proto cmd unknown=0
    local -a lines=()
    local -A target_rules=() commands=()
    L_RULES=()
    [[ -f $FW_SCRIPT && ! -L $FW_SCRIPT ]] || { gtm_error 'No regular legacy forwarding script.'; return 1; }
    grep -Fxq '# Custom GRE Forwarding Rules' "$FW_SCRIPT" || { gtm_error 'Legacy generator header missing; file kept.'; return 1; }
    mapfile -t lines < "$FW_SCRIPT"
    for line in "${lines[@]}"; do
        if gtm_legacy_dnat "$line"; then target_rules["${L_ARGS[0]}|${L_ARGS[6]}|$EP_IP|$EP_PORT"]=1; fi
    done
    for line in "${lines[@]}"; do
        [[ -n $line && $line != '#'* ]] || continue
        case $line in
            'sysctl -w net.ipv4.ip_forward=1 >/dev/null 2>&1'|'sysctl -w net.ipv6.conf.all.forwarding=1 >/dev/null 2>&1'|'[ -f /etc/sysctl.d/98-gre-highload.conf ] || sysctl -w net.netfilter.nf_conntrack_max=262144 >/dev/null 2>&1') continue;;
        esac
        if gtm_legacy_dnat "$line"; then commands["$line"]=1; continue; fi
        local matched=0 ip port
        for target in "${!target_rules[@]}"; do
            IFS='|' read -r cmd proto ip port <<< "$target"
            if [[ $line == "$cmd -t nat -A POSTROUTING -d $ip -p $proto --dport $port -j MASQUERADE" || $line == "$cmd -I FORWARD -d $ip -p $proto --dport $port -j ACCEPT" ]]; then commands["$line"]=1; matched=1; break; fi
        done
        if ((matched==0)); then ((unknown+=1)); printf 'Unrecognized line retained: %s\n' "$line"; fi
    done
    ((unknown==0)) || { gtm_error 'Bulk cleanup refused because the file contains unknown/manual commands. Use grouped deletion for recognized forwards.'; return 1; }
    mapfile -t L_RULES < <(if ((${#commands[@]})); then printf '%s\n' "${!commands[@]}" | LC_ALL=C sort; fi)
    if [[ -e $FW_SERVICE || -L $FW_SERVICE ]]; then
        [[ -f $FW_SERVICE && ! -L $FW_SERVICE ]] && cmp -s "$FW_SERVICE" <(gtm_legacy_forward_unit) || { gtm_error 'Legacy unit was customized; files and live rules were kept.'; return 1; }
    fi
    printf 'Recognized legacy forwarding commands: %d\n' "${#L_RULES[@]}"
    printf '  Remove %s and %s; standard GRE and modern connections stay.\n' "$FW_SCRIPT" "$FW_SERVICE"
}

gtm_legacy_cleanup_all() {
    local line cmd
    [[ -e $FW_SCRIPT || -L $FW_SCRIPT ]] || { printf 'No legacy forwarding script.\n'; return; }
    gtm_legacy_plan_all || return 1
    for line in "${L_RULES[@]}"; do
        cmd=${line%% *}; gtm_need "$cmd" && "$cmd" -t nat -S PREROUTING >/dev/null || return 1
    done
    gtm_confirm && gtm_cleanup_backup "$FW_SCRIPT" "$FW_SERVICE" || return 1
    # A verified oneshot unit has no ExecStop; stopping prevents an in-flight replay.
    [[ ! -f $FW_SERVICE ]] || systemctl stop gre-custom-rules.service || return 1
    for line in "${L_RULES[@]}"; do
        if ! gtm_legacy_drain_rule "$line"; then
            gtm_error "Cleanup incomplete; persistence and backup kept: $GTM_CLEANUP_BACKUP"; return 1
        fi
    done
    [[ ! -f $FW_SERVICE ]] || systemctl disable gre-custom-rules.service || return 1
    rm -f "$FW_SCRIPT" "$FW_SERVICE" && systemctl daemon-reload || return 1
    printf 'Removed recognized legacy forwarding and duplicates. Backup: %s\n' "$GTM_CLEANUP_BACKUP"
    printf 'Existing conntrack sessions can retain their old mapping until expiry.\n'
}

gtm_simple_plan() {
    local line local_port='' remote_port='' proto role='' tunnels=0 links=0 addresses=0 sysctls=0 masquerades=0 dnats=0 forwards=0 signature=0
    local -a words=()
    L_RULES=(); L_SIMPLE_LOCAL=''; L_SIMPLE_REMOTE=''
    [[ -f $GTM_SIMPLE_SCRIPT && ! -L $GTM_SIMPLE_SCRIPT ]] || return 1
    while IFS= read -r line || [[ -n $line ]]; do
        [[ $line != '# Generated by GRE Master - Simple Mode v12' ]] || signature=1
        [[ -n $line && $line != '#'* ]] || continue
        read -r -a words <<< "$line"
        if [[ ${#words[@]} == 12 && ${words[*]:0:7} == 'ip tunnel add gre_simp mode gre local' && ${words[8]} == remote && ${words[10]} == ttl && ${words[11]} == 255 ]]; then
            gtm_ipv4 "${words[7]}" && gtm_ipv4 "${words[9]}" || return 1
            L_SIMPLE_LOCAL=${words[7]}; L_SIMPLE_REMOTE=${words[9]}; ((tunnels+=1)); continue
        fi
        case $line in
            'ip addr add 172.16.200.1/30 dev gre_simp') role=sender; ((addresses+=1)); continue;;
            'ip addr add 172.16.200.2/30 dev gre_simp') role=receiver; ((addresses+=1)); continue;;
            'ip link set gre_simp up') ((links+=1)); continue;;
            'sysctl -w net.ipv4.ip_forward=1') ((sysctls+=1)); continue;;
            'iptables -t nat -A POSTROUTING -o gre_simp -j MASQUERADE') L_RULES+=("$line"); ((masquerades+=1)); continue;;
        esac
        if gtm_legacy_dnat "$line" && [[ ${L_ARGS[0]} == iptables && $EP_IP == 172.16.200.2 ]]; then
            [[ -z $local_port || $local_port == "${L_ARGS[8]}" ]] && [[ -z $remote_port || $remote_port == "$EP_PORT" ]] || return 1
            local_port=${L_ARGS[8]}; remote_port=$EP_PORT; L_RULES+=("$line"); ((dnats+=1)); continue
        fi
        local matched=0
        for proto in tcp udp; do
            if [[ -n $remote_port && $line == "iptables -C FORWARD -d 172.16.200.2 -p $proto --dport $remote_port -j ACCEPT 2>/dev/null || iptables -I FORWARD -d 172.16.200.2 -p $proto --dport $remote_port -j ACCEPT" ]]; then
                L_RULES+=("iptables -I FORWARD -d 172.16.200.2 -p $proto --dport $remote_port -j ACCEPT"); ((forwards+=1)); matched=1; break
            fi
        done
        ((matched)) || { gtm_error 'Simple GRE script contains an unrecognized command; nothing removed.'; return 1; }
    done < "$GTM_SIMPLE_SCRIPT"
    ((signature==1 && tunnels==1 && addresses==1 && links==1)) || return 1
    if [[ $role == sender ]]; then ((dnats==2 && forwards==2 && sysctls==1 && masquerades==1)) || return 1
    else ((dnats==0 && forwards==0 && sysctls==0 && masquerades==0)) || return 1; fi
    if [[ -e $GTM_SIMPLE_UNIT || -L $GTM_SIMPLE_UNIT ]]; then
        [[ -f $GTM_SIMPLE_UNIT && ! -L $GTM_SIMPLE_UNIT ]] && cmp -s "$GTM_SIMPLE_UNIT" <(gtm_simple_unit) || { gtm_error 'Simple GRE unit was customized; nothing removed.'; return 1; }
    fi
    printf 'Recognized Simple GRE: %s -> %s (%s), %d forwarding commands.\n' "$L_SIMPLE_LOCAL" "$L_SIMPLE_REMOTE" "$role" "${#L_RULES[@]}"
}

gtm_simple_dependencies() {
    local line target
    local -a targets=()
    gtm_load_records || return 1
    for line in "${GTM_RECORDS[@]}"; do
        gtm_record_validate "$line" || return 1
        [[ $R_IFACE != gre_simp ]] || { gtm_error "Simple GRE is referenced by $R_ID."; return 1; }
        IFS=, read -r -a targets <<< "$R_TARGETS"; targets+=("$(gtm_address "$R_BIND" "$R_PORT")")
        for target in "${targets[@]}"; do
            gtm_endpoint "$target" || return 1
            [[ $EP_IP != 172.16.200.[0-3] ]] || { gtm_error "Simple GRE address is referenced by $R_ID (disabled records count)."; return 1; }
        done
    done
    if [[ -r $FW_SCRIPT ]]; then
        while IFS= read -r line || [[ -n $line ]]; do
            if gtm_legacy_dnat "$line" && [[ $EP_IP == 172.16.200.[0-3] ]]; then gtm_error 'A legacy forward depends on Simple GRE; remove it first.'; return 1; fi
        done < "$FW_SCRIPT"
    fi
}

gtm_simple_cleanup() {
    local line description local_ip remote_ip
    [[ -e $GTM_SIMPLE_SCRIPT || -L $GTM_SIMPLE_SCRIPT ]] || { printf 'No Simple GRE script.\n'; return; }
    gtm_simple_plan && gtm_simple_dependencies && gtm_need ip || return 1
    if ip link show dev gre_simp >/dev/null 2>&1; then
        description=$(ip tunnel show gre_simp) || return 1
        local_ip=$(awk '{for(i=1;i<NF;i++) if($i=="local") print $(i+1)}' <<< "$description")
        remote_ip=$(awk '{for(i=1;i<NF;i++) if($i=="remote") print $(i+1)}' <<< "$description")
        [[ $local_ip == "$L_SIMPLE_LOCAL" && $remote_ip == "$L_SIMPLE_REMOTE" && $description == 'gre_simp: gre/ip '* ]] || { gtm_error 'gre_simp does not match the saved peer; interface kept.'; return 1; }
    fi
    printf 'Custom routes/manual references need separate review. Global firewall/sysctls are retained.\n'
    gtm_confirm && gtm_cleanup_backup "$GTM_SIMPLE_SCRIPT" "$GTM_SIMPLE_UNIT" || return 1
    [[ ! -f $GTM_SIMPLE_UNIT ]] || systemctl stop simple-gre.service || return 1
    for line in "${L_RULES[@]}"; do gtm_legacy_drain_rule "$line" || { gtm_error "Cleanup incomplete; source and backup kept: $GTM_CLEANUP_BACKUP"; return 1; }; done
    if ip link show dev gre_simp >/dev/null 2>&1; then ip link delete gre_simp || return 1; fi
    [[ ! -f $GTM_SIMPLE_UNIT ]] || systemctl disable simple-gre.service || return 1
    rm -f "$GTM_SIMPLE_SCRIPT" "$GTM_SIMPLE_UNIT" && systemctl daemon-reload || return 1
    printf 'Removed Simple GRE. Backup: %s\n' "$GTM_CLEANUP_BACKUP"
}

gtm_legacy_sysctl_owned() {
    local source=$1 kind=$2 key value extra count=0
    local -A seen=()
    [[ -f $source && ! -L $source ]] || return 1
    while IFS='=' read -r key value extra || [[ -n $key ]]; do
        key=$(awk '{$1=$1;print}' <<< "$key"); value=$(awk '{$1=$1;print}' <<< "$value")
        [[ -n $key && $key != '#'* ]] || continue
        [[ -z $extra && ! ${seen[$key]+set} ]] || return 1
        seen[$key]=1; ((count+=1))
        case "$kind|$key|$value" in
            'tcp|net.ipv4.ip_forward|1'|'tcp|net.ipv6.conf.all.forwarding|1'|'tcp|net.core.default_qdisc|fq'|'tcp|net.ipv4.tcp_congestion_control|bbr'|'tcp|net.core.rmem_max|16777216'|'tcp|net.core.wmem_max|16777216'|'tcp|net.ipv4.tcp_rmem|4096 87380 16777216'|'tcp|net.ipv4.tcp_wmem|4096 65536 16777216') :;;
            'capacity|net.netfilter.nf_conntrack_max|524288'|'capacity|net.netfilter.nf_conntrack_max|1048576'|'capacity|net.netfilter.nf_conntrack_buckets|131072'|'capacity|net.netfilter.nf_conntrack_buckets|262144'|'capacity|net.netfilter.nf_conntrack_tcp_timeout_established|7200'|'capacity|net.netfilter.nf_conntrack_tcp_timeout_time_wait|30'|'capacity|net.netfilter.nf_conntrack_tcp_timeout_fin_wait|30'|'capacity|net.ipv4.ip_local_port_range|1024 65535'|'capacity|net.core.somaxconn|65535'|'capacity|net.core.netdev_max_backlog|16384'|'capacity|net.ipv4.tcp_max_syn_backlog|8192'|'capacity|net.ipv4.tcp_slow_start_after_idle|0'|'capacity|net.ipv4.tcp_mtu_probing|1') :;;
            *) return 1;;
        esac
    done < "$source"
    if [[ $kind == tcp ]]; then ((count==8)); else ((count==11)); fi
}

gtm_legacy_retire_tuning() {
    local file index=0 backup
    local -a files=()
    for file in "$SYSCTL_FILE" "$PERF_SYSCTL_FILE" "$PERF_MODULES_FILE" "$PERF_SCRIPT" "$PERF_SERVICE"; do
        [[ -e $file || -L $file ]] || continue
        [[ -f $file && ! -L $file ]] || { gtm_error "Not a regular owned file: $file"; return 1; }
        case $file in
            "$SYSCTL_FILE") gtm_legacy_sysctl_owned "$file" tcp || { gtm_error "Custom tuning file kept: $file"; return 1; };;
            "$PERF_SYSCTL_FILE") gtm_legacy_sysctl_owned "$file" capacity || { gtm_error "Custom tuning file kept: $file"; return 1; };;
            "$PERF_MODULES_FILE") [[ $(cat "$file") == nf_conntrack ]] || return 1;;
            "$PERF_SCRIPT") [[ $(sha256sum "$file" | awk '{print $1}') == 93562fcaae0586a4152e6d9c30cb71a02c228524a55c543fdc1c041d657070fc ]] || { gtm_error 'Historical performance script differs from the known generator; kept.'; return 1; };;
            "$PERF_SERVICE") cmp -s "$file" <(printf '[Unit]\nDescription=GRE Manager High-Load Tuning (RPS + NOTRACK)\nAfter=network.target\n[Service]\nType=simple\nExecStart=%s boot\n[Install]\nWantedBy=multi-user.target\n' "$PERF_SCRIPT") || { gtm_error 'Historical performance unit was customized; kept.'; return 1; };;
        esac
        files+=("$file"); printf '  Retire: %s\n' "$file"
    done
    ((${#files[@]})) || { printf 'No recognized historical tuning files.\n'; return; }
    printf 'Previous runtime values were not recorded. Runtime sysctls/RPS/untagged NOTRACK stay; no guessed defaults are written.\n'
    printf 'Retirement prevents these files from reapplying at boot; review remaining host policy before reboot.\n'
    gtm_confirm || return
    backup="$GTM_CONFIG_DIR/backups/retired-tuning-$(date -u +%Y%m%dT%H%M%S)-$$-$RANDOM"
    mkdir "$backup" && chmod 700 "$backup" || return 1
    for file in "${files[@]}"; do cp "$file" "$backup/$index-${file##*/}" || return 1; ((index+=1)); done
    [[ ! -f $PERF_SERVICE ]] || systemctl disable --now gre-perf.service || return 1
    for file in "${files[@]}"; do rm -f "$file" || return 1; done
    systemctl daemon-reload || return 1
    printf 'Historical tuning persistence retired. Backup: %s\n' "$backup"
}

gtm_legacy_cleanup_menu() {
    local choice
    gtm_header 'Retire old installation / preview before removal'
    gtm_option 1 'Remove all recognized v13.x forwards' 'Refuses unknown/manual commands'
    gtm_option 2 'Remove one v13.x forward group' 'TCP and UDP by entrance + destination'
    gtm_option 3 'Remove Simple GRE' 'Checks saved script, unit, peer and known dependencies'
    gtm_option 4 'Retire old tuning files' 'Backup first; unknown runtime values stay'
    gtm_option 0 Back
    gtm_read 'Choose: ' choice || return
    case $choice in 1) gtm_legacy_cleanup_all;; 2) gtm_legacy_delete_group;; 3) gtm_simple_cleanup;; 4) gtm_legacy_retire_tuning;; esac
}
