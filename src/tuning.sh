# Explicit global sysctls, with a data-only before/applied journal. Caller locks.
gtm_tuning_key() {
    case $1 in
        net.core.default_qdisc|net.ipv4.tcp_congestion_control|net.core.rmem_max|net.core.wmem_max|net.ipv4.tcp_rmem|net.ipv4.tcp_wmem|net.netfilter.nf_conntrack_max|net.core.somaxconn|net.core.netdev_max_backlog|net.ipv4.tcp_max_syn_backlog) return 0;;
        *) return 1;;
    esac
}

gtm_tuning_value() {
    local key=$1 value=$2
    gtm_tuning_key "$key" || return 1
    case $key in
        net.core.default_qdisc|net.ipv4.tcp_congestion_control) [[ $value =~ ^[a-zA-Z0-9_-]{1,32}$ ]];;
        net.ipv4.tcp_rmem|net.ipv4.tcp_wmem) [[ $value =~ ^[0-9]{1,10}\ [0-9]{1,10}\ [0-9]{1,10}$ ]];;
        *) [[ $value =~ ^[0-9]{1,10}$ ]];;
    esac
}

gtm_tuning_read() {
    local value
    value=$(sysctl -n "$1") || return 1
    value=$(awk '{$1=$1; print}' <<< "$value")
    gtm_tuning_value "$1" "$value" || return 1
    printf '%s' "$value"
}

gtm_tuning_can_write() {
    local key=$1 value=$2 count
    [[ $key == net.netfilter.nf_conntrack_max ]] || return 0
    count=$(sysctl -n net.netfilter.nf_conntrack_count) || { gtm_error 'Cannot inspect active conntrack usage; limit change refused.'; return 1; }
    [[ $count =~ ^[0-9]{1,10}$ ]] || return 1
    ((10#$value >= 10#$count)) || { gtm_error 'Requested conntrack limit is below the active flow count; existing limit kept.'; return 1; }
}

gtm_tuning_write() { gtm_tuning_can_write "$1" "$2" && sysctl -w "$1=$2"; }

gtm_tuning_load() {
    local key before applied extra
    local -A seen=()
    GTM_TUNING_ROWS=()
    [[ -e $GTM_TUNING_STATE || -L $GTM_TUNING_STATE ]] || return 0
    [[ -f $GTM_TUNING_STATE && -r $GTM_TUNING_STATE ]] || return 1
    while IFS=$'\t' read -r key before applied extra || [[ -n $key ]]; do
        [[ -n $key && $key != '#'* ]] || continue
        [[ -z $extra && ! ${seen[$key]+set} ]] && gtm_tuning_value "$key" "$before" && gtm_tuning_value "$key" "$applied" || { gtm_error 'Invalid tuning journal. No sysctl was changed.'; return 1; }
        seen[$key]=1; GTM_TUNING_ROWS+=("$key"$'\t'"$before"$'\t'"$applied")
    done < "$GTM_TUNING_STATE"
}

gtm_tuning_render() {
    local row key before applied
    printf '# Traffic Manager owned tuning; restore through the manager.\n'
    for row in "${GTM_TUNING_ROWS[@]}"; do
        IFS=$'\t' read -r key before applied <<< "$row"
        gtm_tuning_value "$key" "$applied" || return 1
        printf '%s = %s\n' "$key" "$applied"
    done
}

gtm_tuning_save_journal() {
    local temp
    temp=$(mktemp "$GTM_CONFIG_DIR/tuning.XXXXXX") || return 1
    { printf '# Traffic Manager tuning v1: key / before / applied\n'; printf '%s\n' "${GTM_TUNING_ROWS[@]}"; } > "$temp"
    chmod 600 "$temp" && mv "$temp" "$GTM_TUNING_STATE" || { rm -f "$temp"; return 1; }
}

gtm_tuning_save_dropin() {
    local temp
    [[ -d $GTM_SYSCTL_DIR ]] || return 1
    temp=$(mktemp "$GTM_SYSCTL_DIR/.gre-manager.XXXXXX") || return 1
    gtm_tuning_render > "$temp" && chmod 600 "$temp" && mv "$temp" "$GTM_TUNING_FILE" || { rm -f "$temp"; return 1; }
}

gtm_tuning_snapshot() {
    GTM_TUNING_BACKUP="$GTM_CONFIG_DIR/backups/tuning-$(date -u +%Y%m%dT%H%M%S)-$$-$RANDOM"
    mkdir "$GTM_TUNING_BACKUP" && chmod 700 "$GTM_TUNING_BACKUP" || return 1
    [[ ! -f $GTM_TUNING_STATE ]] || cp "$GTM_TUNING_STATE" "$GTM_TUNING_BACKUP/before.tsv" || return 1
    [[ ! -f $GTM_TUNING_FILE ]] || cp "$GTM_TUNING_FILE" "$GTM_TUNING_BACKUP/before.conf" || return 1
}

gtm_tuning_apply() {
    local profile=$1 capacity=${2:-524288} pair key value before current row old_applied failed=0 recovery=0
    local -a wanted=() planned=() attempts=() previous=()
    local -A baseline=() applied=()
    if [[ -e $SYSCTL_FILE || -e $PERF_SYSCTL_FILE ]]; then
        gtm_error 'Retire the old tuning drop-ins first. Their previous runtime values are unknown.'; return 1
    fi
    case $profile in
        capacity)
            [[ $capacity == 524288 || $capacity == 1048576 ]] || return 1
            wanted=("net.netfilter.nf_conntrack_max=$capacity" 'net.core.somaxconn=65535' 'net.core.netdev_max_backlog=16384' 'net.ipv4.tcp_max_syn_backlog=8192');;
        tcp)
            [[ " $(sysctl -n net.ipv4.tcp_available_congestion_control) " == *' bbr '* ]] || { gtm_error 'BBR is not available in this kernel. No setting changed.'; return 1; }
            wanted=('net.core.default_qdisc=fq' 'net.ipv4.tcp_congestion_control=bbr' 'net.core.rmem_max=16777216' 'net.core.wmem_max=16777216' 'net.ipv4.tcp_rmem=4096 87380 16777216' 'net.ipv4.tcp_wmem=4096 65536 16777216');;
        *) return 1;;
    esac
    gtm_tuning_load || return 1
    previous=("${GTM_TUNING_ROWS[@]}")
    if [[ -e $GTM_TUNING_FILE || -L $GTM_TUNING_FILE ]]; then
        [[ -f $GTM_TUNING_FILE ]] && cmp -s "$GTM_TUNING_FILE" <(gtm_tuning_render) || { gtm_error 'Tuning drop-in was changed outside the manager. Keep it for inspection.'; return 1; }
    fi
    for row in "${previous[@]}"; do
        IFS=$'\t' read -r key before old_applied <<< "$row"
        current=$(gtm_tuning_read "$key") || return 1
        [[ $current == "$old_applied" ]] || { gtm_error "Administrator changed $key. Restore/release tracked tuning before reapplying."; return 1; }
        baseline[$key]=$before; applied[$key]=$old_applied
    done
    printf '\nGlobal host changes (not user-count or throughput guarantees):\n'
    for pair in "${wanted[@]}"; do
        key=${pair%%=*}; value=${pair#*=}
        gtm_tuning_value "$key" "$value" || return 1
        gtm_tuning_can_write "$key" "$value" || return 1
        current=$(gtm_tuning_read "$key") || { gtm_error "Cannot capture the previous value: $key"; return 1; }
        printf '  %s: %s -> %s\n' "$key" "$current" "$value"
        baseline[$key]=${baseline[$key]:-$current}; applied[$key]=$value
        attempts+=("$key"$'\t'"$current"$'\t'"$value")
    done
    for key in "${!baseline[@]}"; do planned+=("$key"$'\t'"${baseline[$key]}"$'\t'"${applied[$key]}"); done
    # Stable order keeps previews/drop-in comparisons reproducible.
    mapfile -t GTM_TUNING_ROWS < <(printf '%s\n' "${planned[@]}" | LC_ALL=C sort)
    gtm_confirm && gtm_tuning_snapshot && gtm_tuning_save_journal || return 1
    # The before/applied record is durable before the first live write.
    for row in "${attempts[@]}"; do
        IFS=$'\t' read -r key before value <<< "$row"
        if ! gtm_tuning_write "$key" "$value"; then failed=1; break; fi
    done
    if ((failed==0)) && gtm_tuning_save_dropin; then
        printf 'Applied explicit tuning. Restore point: %s\n' "$GTM_TUNING_BACKUP"; return 0
    fi
    gtm_error 'Tuning apply failed. Recovering values still owned by this attempt.'
    for row in "${attempts[@]}"; do
        IFS=$'\t' read -r key before value <<< "$row"
        current=$(gtm_tuning_read "$key") || { recovery=1; continue; }
        [[ $current == "$value" ]] || continue
        gtm_tuning_write "$key" "$before" || recovery=1
    done
    if ((recovery==0)); then GTM_TUNING_ROWS=("${previous[@]}"); gtm_tuning_save_journal || recovery=1; fi
    ((recovery==0)) || gtm_error "Recovery needs attention; journal and backup retained: $GTM_TUNING_BACKUP"
    return 1
}

gtm_tuning_restore() {
    local row key before applied current failed=0
    local -a remaining=()
    gtm_tuning_load || return 1
    ((${#GTM_TUNING_ROWS[@]})) || { printf 'No tracked tuning. Unknown historical values are never guessed.\n'; return; }
    if [[ -e $GTM_TUNING_FILE || -L $GTM_TUNING_FILE ]]; then
        [[ -f $GTM_TUNING_FILE ]] && cmp -s "$GTM_TUNING_FILE" <(gtm_tuning_render) || { gtm_error 'Drop-in was edited outside the manager; no restoration attempted.'; return 1; }
    fi
    printf 'Restore saved values only when the current value still equals this manager\047s applied value.\n'
    gtm_confirm && gtm_tuning_snapshot || return 1
    for row in "${GTM_TUNING_ROWS[@]}"; do
        IFS=$'\t' read -r key before applied <<< "$row"
        current=$(gtm_tuning_read "$key") || { remaining+=("$row"); failed=1; continue; }
        if [[ $current != "$applied" ]]; then printf 'Preserved external change: %s = %s\n' "$key" "$current"; continue; fi
        if ! gtm_tuning_write "$key" "$before"; then remaining+=("$row"); failed=1; fi
    done
    GTM_TUNING_ROWS=("${remaining[@]}")
    gtm_tuning_save_journal || return 1
    if ((${#remaining[@]})); then gtm_tuning_save_dropin || return 1
    else rm -f "$GTM_TUNING_FILE" || return 1; fi
    ((failed==0)) || { gtm_error 'Some values could not be restored. Their journal entries were kept for retry.'; return 1; }
    printf 'Tracked tuning restored/released. External changes were preserved.\n'
}

gtm_legacy_no_auto_tuning() {
    printf 'GRE setup does not rewrite TCP buffers, BBR, conntrack or IPv6 forwarding.\nUse Legacy -> Performance for explicit journaled tuning; configure IPv6 routing/RA separately.\n'
    [[ ! -f $SYSCTL_FILE ]] || printf 'Historical drop-in still exists: %s. Review it in Legacy tuning retirement.\n' "$SYSCTL_FILE"
    return 0
}

gtm_tuning_guide() {
    printf '\nCapacity is measured in flows, packets/s and memory, not VPN users.\n'
    printf 'TCP tuning affects local TCP endpoints such as HAProxy; it does not change the congestion control of transit TCP flows.\n'
    printf 'Larger conntrack limits can increase memory use under load. Benchmark before changing them.\n'
    printf 'New profiles do not change hash buckets, IPv6 RA, idle conntrack timeouts, RPS or NOTRACK.\n'
    printf 'A historical install has no reliable before-values; retirement preserves unknown runtime values.\n'
    gtm_pause
}

gtm_tuning_restore_menu() { gtm_tuning_restore; }

gtm_tuning_menu() {
    local choice capacity
    while true; do
        gtm_header 'Explicit host tuning / journaled changes'
        gtm_help tuning
        gtm_option 1 'Inspect tracked values' 'Before / applied; read only'
        gtm_option 2 'Conntrack & queue capacity' 'Explicit flow limit; no user-count promise'
        gtm_option 3 'Local TCP preset' 'BBR / fq / buffers; global, opt-in'
        gtm_option 4 'Restore tracked values' 'Preserve settings changed by the administrator'
        gtm_option 5 'Retire historical tuning files' 'Backup first; unknown runtime values stay'
        gtm_option 6 'Capacity guide'
        gtm_option 0 Back
        gtm_read 'Choose: ' choice || return
        case $choice in
            1) gtm_tuning_load && printf '%s\n' "${GTM_TUNING_ROWS[@]}"; gtm_pause;;
            2) gtm_default 'Conntrack entries [524288/1048576]' capacity 524288 || return; gtm_tuning_apply capacity "$capacity"; gtm_pause;;
            3) gtm_tuning_apply tcp; gtm_pause;; 4) gtm_tuning_restore; gtm_pause;;
            5) gtm_legacy_retire_tuning; gtm_pause;; 6) gtm_tuning_guide;; 0) return;;
        esac
    done
}
