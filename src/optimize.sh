# Server optimization: opt-in sysctl groups for tunnel and forwarding servers.
# Nothing changes until a group is applied. Every applied key is journaled
# with its value from before the manager first changed it, each apply/remove
# saves an undo step, and Reset returns every key and removes every file.
# The drop-in sorts after other drop-ins (zz-), so these values win at boot;
# other files that set the same keys are reported, never edited. Caller locks.

gtm_optimize_paths() {
    GTM_OPT_DIR="$GTM_CONFIG_DIR/optimize"
    GTM_OPT_JOURNAL="$GTM_OPT_DIR/journal.tsv"
    GTM_OPT_STEPS="$GTM_OPT_DIR/steps"
    GTM_OPT_FILE="$GTM_SYSCTL_DIR/zz-gre-manager-optimize.conf"
    GTM_OPT_MODULES="$GTM_MODULES_DIR/gre-manager-optimize.conf"
    # Files written by the tuning menu of v1.3.7 and earlier; imported once.
    GTM_OPT_OLD_JOURNAL="$GTM_CONFIG_DIR/tuning.tsv"
    GTM_OPT_OLD_FILE="$GTM_SYSCTL_DIR/99-z-gre-manager-owned.conf"
}

# group|key|value|mode|reason. No mode ever makes the server's own value
# worse, including the provider's image defaults: the live value is compared
# first and kept when it is already as good.
#   raise   only grow (limits, queues, buffers)
#   lower   only shrink (timeouts)
#   raise3  "min default max" triples, each field only grows
#   prefer=A,B  keep the live value when it is one of the listed equivalents
#   loose   reverse-path filter: strict (1) becomes loose (2); off (0) stays
#   set     exact value (only where every other value is worse for relays)
# Conntrack sizes are computed per host.
gtm_optimize_catalog() {
    local memory limit=131072 buckets
    memory=$(gtm_optimize_memory) || memory=0
    # About 350 bytes per tracked flow, within 8 % of memory, as a power of two.
    while ((limit * 2 <= memory * 8 / 100 / 350 && limit < 4194304)); do limit=$((limit * 2)); done
    buckets=$(( limit / 2 > 2097152 ? 2097152 : limit / 2 ))
    printf '%s\n' \
        "conntrack|net.netfilter.nf_conntrack_max|$limit|raise|flow-limit" \
        "conntrack|net.netfilter.nf_conntrack_buckets|$buckets|raise|flow-buckets" \
        'conntrack|net.netfilter.nf_conntrack_tcp_timeout_established|3600|lower|idle-tcp' \
        'conntrack|net.netfilter.nf_conntrack_tcp_timeout_time_wait|30|lower|closing-tcp' \
        'conntrack|net.netfilter.nf_conntrack_tcp_timeout_fin_wait|30|lower|closing-tcp' \
        'conntrack|net.netfilter.nf_conntrack_tcp_timeout_close_wait|30|lower|closing-tcp' \
        'conntrack|net.netfilter.nf_conntrack_udp_timeout|60|raise|udp' \
        'conntrack|net.netfilter.nf_conntrack_udp_timeout_stream|180|raise|udp-stream' \
        'queues|net.core.netdev_max_backlog|16384|raise|backlog' \
        'queues|net.core.netdev_budget|600|raise|budget' \
        'queues|net.core.netdev_budget_usecs|8000|raise|budget' \
        'queues|net.core.somaxconn|8192|raise|accept-queue' \
        'queues|net.ipv4.tcp_max_syn_backlog|8192|raise|syn-queue' \
        'relay|net.core.default_qdisc|fq|prefer=fq,cake,fq_pie|pacing' \
        'relay|net.ipv4.tcp_congestion_control|bbr|prefer=bbr,bbr2,bbr3|bbr' \
        'relay|net.core.rmem_max|33554432|raise|buffers' \
        'relay|net.core.wmem_max|33554432|raise|buffers' \
        'relay|net.ipv4.tcp_rmem|4096 131072 33554432|raise3|buffers' \
        'relay|net.ipv4.tcp_wmem|4096 65536 33554432|raise3|buffers' \
        'relay|net.ipv4.tcp_notsent_lowat|131072|lower|notsent' \
        'relay|net.ipv4.tcp_mtu_probing|1|raise|mtu-probing' \
        'relay|net.ipv4.tcp_slow_start_after_idle|0|lower|idle-restart' \
        'relay|net.ipv4.tcp_keepalive_time|600|lower|keepalive' \
        'relay|net.ipv4.tcp_keepalive_intvl|30|lower|keepalive' \
        'relay|net.ipv4.tcp_keepalive_probes|5|lower|keepalive' \
        'relay|net.ipv4.tcp_fin_timeout|15|lower|fin-timeout' \
        'relay|net.ipv4.tcp_tw_reuse|1|prefer=1|tw-reuse' \
        'routing|net.ipv4.conf.all.rp_filter|2|loose|rp-filter' \
        'routing|net.ipv4.conf.default.rp_filter|2|loose|rp-filter' \
        'routing|net.ipv4.conf.all.send_redirects|0|lower|redirects' \
        'routing|net.ipv4.conf.default.send_redirects|0|lower|redirects' \
        'routing|net.ipv4.conf.all.accept_redirects|0|lower|accept-redirects' \
        'routing|net.ipv4.conf.default.accept_redirects|0|lower|accept-redirects'
}

# Keys this module may write: the catalog plus keys imported from v1.3.7.
gtm_optimize_key() {
    case $1 in
        net.netfilter.nf_conntrack_max|net.netfilter.nf_conntrack_buckets|net.netfilter.nf_conntrack_tcp_timeout_established|\
        net.netfilter.nf_conntrack_tcp_timeout_time_wait|net.netfilter.nf_conntrack_tcp_timeout_fin_wait|\
        net.netfilter.nf_conntrack_tcp_timeout_close_wait|net.netfilter.nf_conntrack_udp_timeout|\
        net.netfilter.nf_conntrack_udp_timeout_stream|net.core.netdev_max_backlog|net.core.netdev_budget|\
        net.core.netdev_budget_usecs|net.core.somaxconn|net.ipv4.tcp_max_syn_backlog|net.core.default_qdisc|\
        net.ipv4.tcp_congestion_control|net.core.rmem_max|net.core.wmem_max|net.ipv4.tcp_rmem|net.ipv4.tcp_wmem|\
        net.ipv4.tcp_mtu_probing|net.ipv4.tcp_slow_start_after_idle|net.ipv4.tcp_keepalive_time|\
        net.ipv4.tcp_keepalive_intvl|net.ipv4.tcp_keepalive_probes|net.ipv4.tcp_fin_timeout|net.ipv4.tcp_tw_reuse|\
        net.ipv4.tcp_notsent_lowat|net.ipv4.conf.all.rp_filter|net.ipv4.conf.default.rp_filter|\
        net.ipv4.conf.all.send_redirects|net.ipv4.conf.default.send_redirects|\
        net.ipv4.conf.all.accept_redirects|net.ipv4.conf.default.accept_redirects) return 0;;
    esac
    return 1
}

gtm_optimize_value() {
    gtm_optimize_key "$1" || return 1
    case $1 in
        net.core.default_qdisc|net.ipv4.tcp_congestion_control) [[ $2 =~ ^[a-z0-9_]{1,16}$ ]];;
        net.ipv4.tcp_rmem|net.ipv4.tcp_wmem) [[ $2 =~ ^[0-9]{1,10}\ [0-9]{1,10}\ [0-9]{1,10}$ ]];;
        *) [[ $2 =~ ^[0-9]{1,10}$ ]];;
    esac
}

gtm_optimize_memory() { awk '$1 == "MemTotal:" {printf "%d", $2 * 1024; found=1; exit} END {exit !found}' "${GTM_MEMINFO:-/proc/meminfo}" 2>/dev/null; }

gtm_optimize_read() {
    local value
    value=$(sysctl -n "$1" 2>/dev/null) || return 1
    value=$(awk '{$1=$1; print}' <<< "$value")
    gtm_optimize_value "$1" "$value" || return 1
    printf '%s' "$value"
}

# The flow limit may never drop below the flows tracked right now.
gtm_optimize_write() {
    local count
    if [[ $1 == net.netfilter.nf_conntrack_max ]]; then
        count=$(sysctl -n net.netfilter.nf_conntrack_count 2>/dev/null) && [[ $count =~ ^[0-9]{1,10}$ ]] || { gtm_error 'Cannot read the tracked flow count; limit kept.'; return 1; }
        ((10#$2 >= 10#$count)) || { gtm_error "Flow limit $2 is below the $count tracked flows; limit kept."; return 1; }
    fi
    sysctl -w "$1=$2" >/dev/null
}

# Journal rows: key, before, applied, group. Loads into GTM_OPT_ROWS.
gtm_optimize_load() {
    local file=${1:-$GTM_OPT_JOURNAL} key before applied group extra
    local -A seen=()
    GTM_OPT_ROWS=()
    [[ -e $file || -L $file ]] || return 0
    [[ -f $file && ! -L $file ]] || { gtm_error 'Optimization journal is not a regular file.'; return 1; }
    while IFS=$'\t' read -r key before applied group extra || [[ -n $key ]]; do
        [[ -n $key && $key != '#'* ]] || continue
        if [[ -n $extra || ${seen[$key]+set} || ! $group =~ ^(conntrack|queues|relay|routing|previous)$ ]] || ! gtm_optimize_value "$key" "$before" || ! gtm_optimize_value "$key" "$applied"; then
            gtm_error 'Invalid optimization journal. Nothing was changed.'; return 1
        fi
        seen[$key]=1; GTM_OPT_ROWS+=("$key"$'\t'"$before"$'\t'"$applied"$'\t'"$group")
    done < "$file"
}

gtm_optimize_save_rows() {
    local target=$1 temp
    mkdir -p "${target%/*}" && chmod 700 "$GTM_OPT_DIR" || return 1
    temp=$(mktemp "${target%/*}/.journal.XXXXXX") || return 1
    { printf '# Traffic Manager optimization v2: key / before / applied / group\n'
      ((${#GTM_OPT_ROWS[@]} == 0)) || printf '%s\n' "${GTM_OPT_ROWS[@]}" | LC_ALL=C sort; } > "$temp"
    chmod 600 "$temp" && mv "$temp" "$target" || { rm -f "$temp"; return 1; }
}

gtm_optimize_render() {
    local row key before applied group
    printf '# Traffic Manager owned. Change or remove it from the panel (Optimization).\n'
    while IFS=$'\t' read -r key before applied group; do
        [[ -n $key ]] && printf '%s = %s\n' "$key" "$applied"
    done < <(((${#GTM_OPT_ROWS[@]} == 0)) || printf '%s\n' "${GTM_OPT_ROWS[@]}" | LC_ALL=C sort)
}

gtm_optimize_modules_render() {
    local row needs_conntrack=0 needs_bbr=0
    for row in "${GTM_OPT_ROWS[@]}"; do
        [[ $row != net.netfilter.* ]] || needs_conntrack=1
        [[ $row != net.ipv4.tcp_congestion_control$'\t'*$'\t'bbr$'\t'* ]] || needs_bbr=1
    done
    ((needs_conntrack || needs_bbr)) || return 0
    printf '# Traffic Manager owned: load modules before sysctl at boot.\n'
    ((needs_conntrack == 0)) || printf 'nf_conntrack\n'
    ((needs_bbr == 0)) || printf 'tcp_bbr\n'
}

# Writes (or removes) an owned file unless someone edited it since.
gtm_optimize_owned_file() {
    local path=$1 content=$2 previous=$3 temp
    if [[ -e $path || -L $path ]]; then
        [[ -f $path && ! -L $path ]] && cmp -s "$path" <(printf '%s' "$previous") || { gtm_error "Kept the edited file $path; reconcile it by hand."; return 1; }
    fi
    if [[ -z $content ]]; then rm -f "$path"; return; fi
    [[ -d ${path%/*} ]] || return 0
    temp=$(mktemp "${path%/*}/.gre-manager.XXXXXX") || return 1
    printf '%s' "$content" > "$temp" && chmod 644 "$temp" && mv "$temp" "$path" || { rm -f "$temp"; return 1; }
}

# Persists GTM_OPT_ROWS: journal, drop-in and module list. GTM_OPT_PREVIOUS
# holds the rows the files on disk were rendered from.
gtm_optimize_persist() {
    local -a next=("${GTM_OPT_ROWS[@]}") prior=(${GTM_OPT_PREVIOUS[@]+"${GTM_OPT_PREVIOUS[@]}"})
    local conf='' modules='' old_conf old_modules
    GTM_OPT_ROWS=("${prior[@]}"); old_conf=''; old_modules=$(gtm_optimize_modules_render)
    ((${#prior[@]} == 0)) || old_conf=$(gtm_optimize_render; printf x); old_conf=${old_conf%x}
    GTM_OPT_ROWS=("${next[@]}"); modules=$(gtm_optimize_modules_render)
    ((${#next[@]} == 0)) || conf=$(gtm_optimize_render; printf x); conf=${conf%x}
    [[ -z $modules ]] || modules+=$'\n'; [[ -z $old_modules ]] || old_modules+=$'\n'
    gtm_optimize_save_rows "$GTM_OPT_JOURNAL" && gtm_optimize_owned_file "$GTM_OPT_FILE" "$conf" "$old_conf" &&
        gtm_optimize_owned_file "$GTM_OPT_MODULES" "$modules" "$old_modules"
}

# Saves the journal as the newest undo step; keeps the last 20.
gtm_optimize_push_step() {
    local name file
    mkdir -p "$GTM_OPT_STEPS" && chmod 700 "$GTM_OPT_DIR" "$GTM_OPT_STEPS" || return 1
    name=$(date -u +%Y%m%dT%H%M%S)-$$-$RANDOM
    GTM_OPT_ROWS=(${GTM_OPT_PREVIOUS[@]+"${GTM_OPT_PREVIOUS[@]}"})
    gtm_optimize_save_rows "$GTM_OPT_STEPS/$name.tsv" || return 1
    while IFS= read -r file; do rm -f "$file"; done < <(ls -1 "$GTM_OPT_STEPS"/*.tsv 2>/dev/null | LC_ALL=C sort | head -n -20)
}

gtm_optimize_last_step() { ls -1 "$GTM_OPT_STEPS"/*.tsv 2>/dev/null | LC_ALL=C sort | tail -n 1; }

# Imports the v1.3.7 tuning journal once: its original values stay the
# baseline, its drop-in is replaced by ours. Unknown edits stop the import.
gtm_optimize_import() {
    local row key before applied backup
    local -a imported=()
    [[ -f $GTM_OPT_OLD_JOURNAL ]] || return 0
    while IFS=$'\t' read -r key before applied || [[ -n $key ]]; do
        [[ -n $key && $key != '#'* ]] || continue
        gtm_optimize_value "$key" "$before" && gtm_optimize_value "$key" "$applied" || { gtm_error "The old tuning journal has an unknown entry ($key); review $GTM_OPT_OLD_JOURNAL."; return 1; }
        imported+=("$key"$'\t'"$before"$'\t'"$applied"$'\tprevious')
    done < "$GTM_OPT_OLD_JOURNAL"
    gtm_optimize_load || return 1
    for row in "${GTM_OPT_ROWS[@]}"; do [[ " ${imported[*]%%$'\t'*} " != *" ${row%%$'\t'*} "* ]] && imported+=("$row"); done
    backup="$GTM_CONFIG_DIR/backups/tuning-import-$(date -u +%Y%m%dT%H%M%S)-$$"
    mkdir -p "$backup" && chmod 700 "$backup" && cp "$GTM_OPT_OLD_JOURNAL" "$backup/" || return 1
    [[ ! -f $GTM_OPT_OLD_FILE ]] || cp "$GTM_OPT_OLD_FILE" "$backup/" || return 1
    GTM_OPT_PREVIOUS=(${GTM_OPT_ROWS[@]+"${GTM_OPT_ROWS[@]}"}); GTM_OPT_ROWS=("${imported[@]}")
    gtm_optimize_persist || return 1
    rm -f "$GTM_OPT_OLD_FILE" "$GTM_OPT_OLD_JOURNAL" "$GTM_CONFIG_DIR/tuning-previous.tsv"
    printf 'Imported the earlier tuning; its original values remain the reset target. Backup: %s\n' "$backup"
}

# Fills GTM_OPT_OTHERS[key]="file<TAB>value" with the last other drop-in that
# sets key. Ours sorts after them, so ours wins at boot; they are only shown.
gtm_optimize_others() {
    local LC_ALL=C dir file name line key ours
    local -A first=()
    declare -gA GTM_OPT_OTHERS=()
    ours=${GTM_OPT_FILE##*/}
    for dir in $GTM_SYSCTL_SCAN; do
        for file in "$dir"/*.conf; do
            [[ -f $file ]] || continue
            name=${file##*/}
            [[ $name == "$ours" || ${first[$name]+set} ]] || first[$name]=$file
        done
    done
    while IFS= read -r name; do
        [[ -n $name ]] || continue
        while IFS= read -r line || [[ -n $line ]]; do
            [[ $line =~ ^[[:space:]]*-?([a-z0-9_./]+)[[:space:]]*=[[:space:]]*(.*[^[:space:]])[[:space:]]*$ ]] || continue
            key=${BASH_REMATCH[1]//\//.}
            gtm_optimize_key "$key" && GTM_OPT_OTHERS[$key]="${first[$name]}"$'\t'"${BASH_REMATCH[2]}"
        done < "${first[$name]}"
    done < <(printf '%s\n' "${!first[@]}" | sort)
}

# ServerTools (github.com/Sir-Adnan/server-tools) tunes the same subsystems.
gtm_optimize_servertools() {
    local file
    for file in "$GTM_SYSCTL_DIR"/99-zz-server-tools*.conf "$GTM_MODULES_DIR/server-tools.conf"; do
        [[ ! -f $file ]] || printf '%s\n' "$file"
    done
}

# The recommended value for key given its live value and mode: never worse
# than what the server already has.
gtm_optimize_better() {
    local current=$1 wanted=$2 mode=$3 a b out='' index
    local -a have=() want=()
    case $mode in
        raise) ((10#$current >= 10#$wanted)) && printf '%s' "$current" || printf '%s' "$wanted";;
        lower) ((10#$current <= 10#$wanted)) && printf '%s' "$current" || printf '%s' "$wanted";;
        raise3)
            read -r -a have <<< "$current"; read -r -a want <<< "$wanted"
            for index in 0 1 2; do
                a=${have[$index]}; b=${want[$index]}
                out+="$(( 10#$a > 10#$b ? 10#$a : 10#$b ))"; ((index == 2)) || out+=' '
            done
            printf '%s' "$out";;
        prefer=*) [[ ",${mode#prefer=}," == *",$current,"* ]] && printf '%s' "$current" || printf '%s' "$wanted";;
        loose) [[ $current == 1 ]] && printf 2 || printf '%s' "$current";;
        *) printf '%s' "$wanted";;
    esac
}

# Sets GTM_OPT_PLAN rows "group key current value reason note" for groups.
# Note: change, same (already the recommendation), kept (the server's own
# value is already better and stays) or missing (no such key or algorithm).
gtm_optimize_compute() {
    local groups=" $* " group key wanted value mode reason current note
    GTM_OPT_PLAN=()
    # BBR may be a module that is not loaded yet; loading it changes nothing else.
    if [[ ${GTM_OPT_READONLY:-0} == 0 && $groups == *' relay '* && " $(sysctl -n net.ipv4.tcp_available_congestion_control 2>/dev/null) " != *' bbr '* ]]; then
        command -v modprobe >/dev/null 2>&1 && modprobe tcp_bbr 2>/dev/null
    fi
    while IFS='|' read -r group key wanted mode reason; do
        [[ $groups == *" $group "* ]] || continue
        value=$wanted; note=change
        if ! current=$(gtm_optimize_read "$key"); then
            current=-; note=missing
        elif [[ $key == net.ipv4.tcp_congestion_control && " $(sysctl -n net.ipv4.tcp_available_congestion_control 2>/dev/null) " != *" $wanted "* && $mode != *",$current"* && $mode != *"=$current"* ]]; then
            note=missing
        else
            value=$(gtm_optimize_better "$current" "$wanted" "$mode")
            if [[ $value == "$current" ]]; then
                note=kept; [[ $current != "$wanted" ]] || note=same
            fi
        fi
        GTM_OPT_PLAN+=("$group"$'\t'"$key"$'\t'"$current"$'\t'"$value"$'\t'"$reason"$'\t'"$note")
    done < <(gtm_optimize_catalog)
}

gtm_optimize_groups_valid() {
    local group
    (($#)) || return 1
    for group in "$@"; do [[ $group =~ ^(conntrack|queues|relay|routing)$ ]] || return 1; done
}

# Read-only preview: one "change" row per catalog key of the groups.
gtm_optimize_plan() {
    local row key
    gtm_optimize_groups_valid "$@" || { gtm_error 'Unknown optimization group.'; return 2; }
    gtm_optimize_paths
    gtm_optimize_compute "$@"
    gtm_optimize_others
    for row in "${GTM_OPT_PLAN[@]}"; do
        key=$(cut -f2 <<< "$row")
        printf 'change\t%s\t%s\n' "$row" "${GTM_OPT_OTHERS[$key]:-$'-\t-'}"
    done
}

# Read-only state: host facts, owned files, undo depth and every catalog key
# with its recommendation for this server (value, reason, note).
gtm_optimize_status() {
    local row key before applied group current steps=0 file value reason note
    local -A journal=() advice=()
    gtm_optimize_paths
    gtm_optimize_load || return 1
    for row in "${GTM_OPT_ROWS[@]}"; do IFS=$'\t' read -r key before applied group <<< "$row"; journal[$key]="$before"$'\t'"$applied"$'\t'"$group"; done
    printf 'meta\tmemory\t%s\n' "$(gtm_optimize_memory || printf 0)"
    printf 'meta\tflows\t%s\n' "$(sysctl -n net.netfilter.nf_conntrack_count 2>/dev/null || printf -)"
    printf 'meta\tcongestion\t%s\n' "$(sysctl -n net.ipv4.tcp_available_congestion_control 2>/dev/null || printf -)"
    [[ -d $GTM_OPT_STEPS ]] && steps=$(ls -1 "$GTM_OPT_STEPS"/*.tsv 2>/dev/null | wc -l)
    printf 'meta\tsteps\t%d\n' "$steps"
    printf 'meta\tfile\t%s\n' "$GTM_OPT_FILE"
    [[ ! -f $GTM_OPT_OLD_JOURNAL ]] || printf 'meta\timport\t%s\n' "$GTM_OPT_OLD_JOURNAL"
    while IFS= read -r file; do [[ -z $file ]] || printf 'meta\tservertools\t%s\n' "$file"; done < <(gtm_optimize_servertools)
    gtm_optimize_others
    GTM_OPT_READONLY=1 gtm_optimize_compute conntrack queues relay routing
    for row in "${GTM_OPT_PLAN[@]}"; do
        IFS=$'\t' read -r group key current value reason note <<< "$row"
        advice[$key]="$current"$'\t'"$value"$'\t'"$reason"$'\t'"$note"
    done
    while IFS='|' read -r group key _; do
        IFS=$'\t' read -r current value reason note <<< "${advice[$key]}"
        printf 'key\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' "$group" "$key" "$current" "${journal[$key]:-$'-\t-\t-'}" "${GTM_OPT_OTHERS[$key]:-$'-\t-'}" "$value" "$reason" "$note"
        unset 'journal[$key]'
    done < <(gtm_optimize_catalog)
    # Imported keys outside the catalog stay visible until reset.
    for key in "${!journal[@]}"; do
        current=$(gtm_optimize_read "$key") || current=-
        printf 'key\tprevious\t%s\t%s\t%s\t-\t-\t-\t-\t-\n' "$key" "$current" "${journal[$key]}"
    done
}

# Rows whose live value differs from what the manager applied were changed
# by someone else: those keys are released (left as they are), not reverted.
gtm_optimize_check_live() {
    local row key before applied group current
    GTM_OPT_LIVE=()
    GTM_OPT_RELEASED=()
    for row in "${GTM_OPT_ROWS[@]}"; do
        IFS=$'\t' read -r key before applied group <<< "$row"
        current=$(gtm_optimize_read "$key") || current=-
        if [[ $current == "$applied" ]]; then GTM_OPT_LIVE+=("$row")
        else GTM_OPT_RELEASED+=("$key"); printf 'Left %s = %s; it was changed outside the panel.\n' "$key" "$current"; fi
    done
}

gtm_optimize_apply() {
    local row group key current value reason note failed=0 written=0
    local -a attempts=() done_rows=()
    local -A rows=()
    gtm_optimize_groups_valid "$@" || { gtm_error 'Unknown optimization group.'; return 2; }
    gtm_optimize_paths
    gtm_optimize_import && gtm_optimize_load || return 1
    GTM_OPT_PREVIOUS=(${GTM_OPT_ROWS[@]+"${GTM_OPT_ROWS[@]}"})
    gtm_optimize_check_live
    for row in ${GTM_OPT_LIVE[@]+"${GTM_OPT_LIVE[@]}"}; do rows[${row%%$'\t'*}]=$row; done
    gtm_optimize_compute "$@"
    printf 'Server-wide settings (they do not promise a number of users):\n'
    for row in "${GTM_OPT_PLAN[@]}"; do
        IFS=$'\t' read -r group key current value reason note <<< "$row"
        case $note in
            same) printf '  %s = %s (already set)\n' "$key" "$current"; continue;;
            kept) printf '  %s = %s (the server value is already better; kept)\n' "$key" "$current"; continue;;
            missing) printf '  %s: not available on this kernel; skipped\n' "$key"; continue;;
        esac
        printf '  %s: %s -> %s\n' "$key" "$current" "$value"
        attempts+=("$key"$'\t'"$current"$'\t'"$value"$'\t'"$group")
    done
    ((${#attempts[@]})) || { printf 'Nothing to change.\n'; return 0; }
    gtm_confirm || return 1
    # The undo step and journal are durable before the first live write.
    for row in "${attempts[@]}"; do
        IFS=$'\t' read -r key current value group <<< "$row"
        if [[ ${rows[$key]+set} ]]; then IFS=$'\t' read -r _ current _ _ <<< "${rows[$key]}"; fi
        rows[$key]="$key"$'\t'"$current"$'\t'"$value"$'\t'"$group"
    done
    GTM_OPT_ROWS=(); for key in "${!rows[@]}"; do GTM_OPT_ROWS+=("${rows[$key]}"); done
    local -a planned=("${GTM_OPT_ROWS[@]}")
    gtm_optimize_push_step && GTM_OPT_ROWS=("${planned[@]}") && gtm_optimize_save_rows "$GTM_OPT_JOURNAL" || return 1
    for row in "${attempts[@]}"; do
        IFS=$'\t' read -r key current value group <<< "$row"
        if gtm_optimize_write "$key" "$value"; then done_rows+=("$row"); ((written+=1)); else failed=1; break; fi
    done
    if ((failed == 0)) && GTM_OPT_ROWS=("${planned[@]}") && gtm_optimize_persist; then
        printf 'Applied %d setting(s). Undo or Reset restores them.\n' "$written"; return 0
    fi
    gtm_error 'Applying stopped; reverting the settings written in this step.'
    for row in ${done_rows[@]+"${done_rows[@]}"}; do
        IFS=$'\t' read -r key current value group <<< "$row"
        [[ $(gtm_optimize_read "$key") != "$value" ]] || gtm_optimize_write "$key" "$current" || failed=2
    done
    GTM_OPT_ROWS=(${GTM_OPT_PREVIOUS[@]+"${GTM_OPT_PREVIOUS[@]}"})
    gtm_optimize_save_rows "$GTM_OPT_JOURNAL" && rm -f "$(gtm_optimize_last_step)" || failed=2
    ((failed < 2)) || gtm_error "Recovery needs attention; see $GTM_OPT_DIR."
    return 1
}

# Moves live values to the target rows: a key in target takes its applied
# value; a key only in the current journal returns to its original value.
gtm_optimize_move() {
    local -n wanted_rows=$1
    local row key before applied group goal failed=0
    local -A goal_of=() released=()
    local -a kept=()
    for row in ${wanted_rows[@]+"${wanted_rows[@]}"}; do IFS=$'\t' read -r key before applied group <<< "$row"; goal_of[$key]=$applied; done
    GTM_OPT_PREVIOUS=(${GTM_OPT_ROWS[@]+"${GTM_OPT_ROWS[@]}"})
    gtm_optimize_check_live
    for key in ${GTM_OPT_RELEASED[@]+"${GTM_OPT_RELEASED[@]}"}; do released[$key]=1; done
    for row in ${GTM_OPT_LIVE[@]+"${GTM_OPT_LIVE[@]}"}; do
        IFS=$'\t' read -r key before applied group <<< "$row"
        goal=${goal_of[$key]-$before}
        [[ $goal == "$applied" ]] || gtm_optimize_write "$key" "$goal" || { kept+=("$row"); failed=1; }
    done
    GTM_OPT_ROWS=()
    for row in ${wanted_rows[@]+"${wanted_rows[@]}"}; do [[ ${released[${row%%$'\t'*}]+set} ]] || GTM_OPT_ROWS+=("$row"); done
    for row in ${kept[@]+"${kept[@]}"}; do
        key=${row%%$'\t'*}
        local -a filtered=()
        for applied in "${GTM_OPT_ROWS[@]}"; do [[ ${applied%%$'\t'*} == "$key" ]] || filtered+=("$applied"); done
        GTM_OPT_ROWS=(${filtered[@]+"${filtered[@]}"} "$row")
    done
    gtm_optimize_persist || return 1
    return "$failed"
}

gtm_optimize_undo() {
    local step
    local -a earlier=()
    gtm_optimize_paths
    gtm_optimize_load || return 1
    step=$(gtm_optimize_last_step)
    [[ -n $step ]] || { gtm_error 'There is no step to undo.'; return 1; }
    local -a current=("${GTM_OPT_ROWS[@]}")
    gtm_optimize_load "$step" || return 1
    earlier=(${GTM_OPT_ROWS[@]+"${GTM_OPT_ROWS[@]}"}); GTM_OPT_ROWS=(${current[@]+"${current[@]}"})
    gtm_confirm || return 1
    gtm_optimize_move earlier || { gtm_error 'Some settings could not be reverted; they stay tracked. Try again.'; return 1; }
    rm -f "$step"
    printf 'Undid the last step.\n'
}

# Returns one group's keys (or every key with "all") to their original values.
gtm_optimize_remove() {
    local which=$1 row
    local -a remaining=()
    [[ $which =~ ^(conntrack|queues|relay|routing|previous|all)$ ]] || { gtm_error 'Unknown optimization group.'; return 2; }
    gtm_optimize_paths
    gtm_optimize_import && gtm_optimize_load || return 1
    ((${#GTM_OPT_ROWS[@]})) || { printf 'Nothing is applied.\n'; [[ $which != all ]] || rm -rf "$GTM_OPT_STEPS"; return 0; }
    for row in "${GTM_OPT_ROWS[@]}"; do [[ $which != all && ${row##*$'\t'} != "$which" ]] && remaining+=("$row"); done
    gtm_confirm || return 1
    GTM_OPT_PREVIOUS=("${GTM_OPT_ROWS[@]}")
    if [[ $which != all ]]; then gtm_optimize_push_step || return 1; GTM_OPT_ROWS=("${GTM_OPT_PREVIOUS[@]}"); fi
    gtm_optimize_move remaining || { gtm_error 'Some settings could not be restored; they stay tracked. Try again.'; return 1; }
    if [[ $which == all ]]; then
        rm -rf "$GTM_OPT_STEPS"; rm -f "$GTM_OPT_JOURNAL"
        printf 'Every setting is back to its original value; the panel files were removed.\n'
    else
        printf 'Settings of %s are back to their original values.\n' "$which"
    fi
}

gtm_optimize_menu() {
    local choice
    local -a groups=(conntrack queues relay routing)
    gtm_optimize_paths
    while true; do
        gtm_header 'Server optimization / opt-in, reversible'
        gtm_help tuning
        gtm_option 1 'Show settings' 'Current, original and applied values'
        gtm_option 2 'Connection tracking' 'Recommended for forwarders: fixes rising latency'
        gtm_option 3 'Packet queues' 'High packet rates'
        gtm_option 4 'Relay TCP' 'HAProxy / Realm / FRP: BBR, buffers, keepalive'
        gtm_option 5 'Tunnels & routing' 'Loose reverse-path filter, no ICMP redirects'
        gtm_option 6 'Undo last step'
        gtm_option 7 'Reset everything' 'Original values; remove panel files'
        gtm_option 0 Back
        gtm_read 'Choose: ' choice || return
        case $choice in
            1) gtm_optimize_status | awk -F '\t' '$1 == "key" {printf "  %-52s %-22s (original %s)\n", $3, $4, $5}'; gtm_pause;;
            2|3|4|5) gtm_prepare && gtm_lock || return; gtm_optimize_apply "${groups[$((choice-2))]}"; gtm_unlock; gtm_pause;;
            6) gtm_prepare && gtm_lock || return; gtm_optimize_undo; gtm_unlock; gtm_pause;;
            7) gtm_prepare && gtm_lock || return; gtm_optimize_remove all; gtm_unlock; gtm_pause;;
            0) return;;
        esac
    done
}
