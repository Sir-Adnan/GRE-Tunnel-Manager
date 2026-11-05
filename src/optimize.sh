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
    # Link settings (queue length, packet steering) are not sysctls: a
    # oneshot unit replays them at boot.
    GTM_OPT_LINK_SCRIPT="${GTM_RUNTIME%/*}/optimize-links.sh"
    GTM_OPT_LINK_UNIT="$GTM_SERVICE_DIR/gre-manager-optimize.service"
    GTM_SYSFS_NET=${GTM_SYSFS_NET:-/sys/class/net}
}

# Uplinks: interfaces of the IPv4/IPv6 default routes, at most four.
gtm_optimize_links() {
    local name
    {
        awk '$2 == "00000000" && $8 == "00000000" {print $1}' "${GTM_PROC_ROUTE:-/proc/net/route}" 2>/dev/null
        awk '$1 == "00000000000000000000000000000000" && $2 == "00" && $10 != "lo" {print $10}' "${GTM_PROC_ROUTE6:-/proc/net/ipv6_route}" 2>/dev/null
    } | awk '!seen[$0]++' | head -n 4 | while IFS= read -r name; do
        [[ $name =~ ^[A-Za-z0-9_.-]{1,15}$ && $name != lo && $name != gre* && -d $GTM_SYSFS_NET/$name ]] && printf '%s\n' "$name"
    done
}

gtm_optimize_cpus() {
    local cpus=${GTM_CPUS:-}
    [[ -n $cpus ]] || cpus=$(nproc 2>/dev/null) || cpus=1
    [[ $cpus =~ ^[0-9]{1,4}$ ]] || cpus=1
    printf '%d' "$((10#$cpus))"
}

# The CPU mask of every CPU, in lowercase hex without separators.
gtm_optimize_mask() {
    local cpus=$1 out='' index
    ((cpus % 4 == 0)) || out=$(printf '%x' "$(( (1 << (cpus % 4)) - 1 ))")
    for ((index = 0; index < cpus / 4; index++)); do out+=f; done
    printf '%s' "$out"
}

# Prints the receive queue count of a link.
gtm_optimize_rx_queues() {
    local queue count=0
    for queue in "$GTM_SYSFS_NET/$1"/queues/rx-*; do [[ ! -d $queue ]] || ((count+=1)); done
    printf '%d' "$count"
}

# group|key|value|mode|reason for the chosen profile (GTM_OPT_LEVEL and
# GTM_OPT_GOAL). No mode ever makes the server's own value worse, including
# the provider's image defaults: the original value is compared first and
# kept when it is already as good.
#   raise   only grow (limits, queues, buffers)
#   lower   only shrink (timeouts)
#   raise3  "min default max" triples, each field only grows
#   range   "low high" port range: low only drops, high only grows
#   prefer=A,B  keep the value when it is one of the listed equivalents
#   loose   reverse-path filter: strict (1) becomes loose (2); off (0) stays
#   rps     a CPU mask: kept when the server already steers packets
# A value of "-" means the profile leaves the key at its original value.
# Every profile lists the same keys, so switching profiles can return a key.
GTM_OPT_LEVELS='conservative balanced aggressive'
GTM_OPT_GOALS='general users latency'
# Below this, aggressive keeps balanced table and buffer sizes (a "2 GB" plan
# reports about 1.9 GiB, so it is not capped).
GTM_OPT_SMALL=$((1792 * 1048576))
declare -gA GTM_OPT_SET=()

gtm_optimize_profile_valid() {
    [[ $1 =~ ^[a-z]+$ && $2 =~ ^[a-z]+$ && " $GTM_OPT_LEVELS " == *" $1 "* && " $GTM_OPT_GOALS " == *" $2 "* ]]
}

# Prints 1 when the aggressive level is capped on this host.
gtm_optimize_capped() {
    local memory
    [[ ${GTM_OPT_LEVEL:-balanced} == aggressive ]] || { printf 0; return; }
    memory=$(gtm_optimize_memory) || memory=0
    if ((memory < GTM_OPT_SMALL)); then printf 1; else printf 0; fi
}

gtm_optimize_catalog() {
    local level=${GTM_OPT_LEVEL:-balanced} goal=${GTM_OPT_GOAL:-general}
    local memory limit=131072 cap=4194304 bucket_cap=2097152 buckets percent
    local established close backlog budget usecs somax syn buffer rmem wmem notsent ka kai kap fin
    local udp=60 stream=180 tw=- ports=-
    memory=$(gtm_optimize_memory) || memory=0
    case $level in
        conservative)
            percent=4 established=7200 close=60 backlog=8192 budget=400 usecs=4000 somax=4096 syn=4096
            buffer=16777216 rmem='4096 131072 16777216' wmem='4096 65536 16777216' notsent=-
            ka=1800 kai=60 kap=6 fin=30;;
        aggressive)
            percent=16 cap=8388608 bucket_cap=4194304 established=1800 close=15 backlog=65536 budget=1000 usecs=8000
            somax=65535 syn=65535 buffer=67108864 rmem='8192 262144 67108864' wmem='8192 131072 67108864'
            notsent=131072 ka=300 kai=15 kap=5 fin=10
            if [[ $(gtm_optimize_capped) == 1 ]]; then
                percent=8 cap=4194304 bucket_cap=2097152 backlog=32768
                buffer=33554432 rmem='4096 131072 33554432' wmem='4096 65536 33554432'
            fi;;
        *)
            percent=8 established=3600 close=30 backlog=16384 budget=600 usecs=8000 somax=8192 syn=8192
            buffer=33554432 rmem='4096 131072 33554432' wmem='4096 65536 33554432' notsent=131072
            ka=600 kai=30 kap=5 fin=15;;
    esac
    case $goal in
        users)
            ((somax >= 16384)) || somax=16384
            ((syn >= 16384)) || syn=16384
            ports='16384 65535'
            case $level in conservative) tw=262144;; aggressive) tw=1048576;; *) tw=524288;; esac;;
        latency) notsent=16384 udp=120 stream=300;;
    esac
    # About 350 bytes per tracked flow, within the level's share of memory, as a power of two.
    while ((limit * 2 <= memory * percent / 100 / 350 && limit < cap)); do limit=$((limit * 2)); done
    buckets=$(( limit / 2 > bucket_cap ? bucket_cap : limit / 2 ))
    printf '%s\n' \
        "conntrack|net.netfilter.nf_conntrack_max|$limit|raise|flow-limit" \
        "conntrack|net.netfilter.nf_conntrack_buckets|$buckets|raise|flow-buckets" \
        "conntrack|net.netfilter.nf_conntrack_tcp_timeout_established|$established|lower|idle-tcp" \
        "conntrack|net.netfilter.nf_conntrack_tcp_timeout_time_wait|$close|lower|closing-tcp" \
        "conntrack|net.netfilter.nf_conntrack_tcp_timeout_fin_wait|$close|lower|closing-tcp" \
        "conntrack|net.netfilter.nf_conntrack_tcp_timeout_close_wait|$close|lower|closing-tcp" \
        "conntrack|net.netfilter.nf_conntrack_udp_timeout|$udp|raise|udp" \
        "conntrack|net.netfilter.nf_conntrack_udp_timeout_stream|$stream|raise|udp-stream" \
        "queues|net.core.netdev_max_backlog|$backlog|raise|backlog" \
        "queues|net.core.netdev_budget|$budget|raise|budget" \
        "queues|net.core.netdev_budget_usecs|$usecs|raise|budget" \
        "queues|net.core.somaxconn|$somax|raise|accept-queue" \
        "queues|net.ipv4.tcp_max_syn_backlog|$syn|raise|syn-queue" \
        'relay|net.core.default_qdisc|fq|prefer=fq,cake,fq_pie|pacing' \
        'relay|net.ipv4.tcp_congestion_control|bbr|prefer=bbr,bbr2,bbr3|bbr' \
        "relay|net.core.rmem_max|$buffer|raise|buffers" \
        "relay|net.core.wmem_max|$buffer|raise|buffers" \
        "relay|net.ipv4.tcp_rmem|$rmem|raise3|buffers" \
        "relay|net.ipv4.tcp_wmem|$wmem|raise3|buffers" \
        "relay|net.ipv4.tcp_notsent_lowat|$notsent|lower|notsent" \
        'relay|net.ipv4.tcp_mtu_probing|1|raise|mtu-probing' \
        'relay|net.ipv4.tcp_slow_start_after_idle|0|lower|idle-restart' \
        "relay|net.ipv4.tcp_keepalive_time|$ka|lower|keepalive" \
        "relay|net.ipv4.tcp_keepalive_intvl|$kai|lower|keepalive" \
        "relay|net.ipv4.tcp_keepalive_probes|$kap|lower|keepalive" \
        "relay|net.ipv4.tcp_fin_timeout|$fin|lower|fin-timeout" \
        'relay|net.ipv4.tcp_tw_reuse|1|prefer=1|tw-reuse' \
        "relay|net.ipv4.ip_local_port_range|$ports|range|ports" \
        "relay|net.ipv4.tcp_max_tw_buckets|$tw|raise|tw-buckets" \
        'routing|net.ipv4.conf.all.rp_filter|2|loose|rp-filter' \
        'routing|net.ipv4.conf.default.rp_filter|2|loose|rp-filter' \
        'routing|net.ipv4.conf.all.send_redirects|0|lower|redirects' \
        'routing|net.ipv4.conf.default.send_redirects|0|lower|redirects' \
        'routing|net.ipv4.conf.all.accept_redirects|0|lower|accept-redirects' \
        'routing|net.ipv4.conf.default.accept_redirects|0|lower|accept-redirects'
    gtm_optimize_links_catalog
}

# A longer transmit queue absorbs bursts on fast uplinks; Low latency keeps
# the server's queue. Packet steering (RPS) spreads receive work of a
# single-queue card across every CPU; it is listed only where it helps.
gtm_optimize_links_catalog() {
    local level=${GTM_OPT_LEVEL:-balanced} goal=${GTM_OPT_GOAL:-general} link cpus txq rps
    cpus=$(gtm_optimize_cpus)
    case $level in conservative) txq=2000 rps=-;; aggressive) txq=10000 rps='';; *) txq=5000 rps='';; esac
    [[ $goal != latency ]] || txq=-
    while IFS= read -r link; do
        [[ -n $link ]] || continue
        [[ ! -f $GTM_SYSFS_NET/$link/tx_queue_len ]] || printf 'nic|link.%s.txqueuelen|%s|raise|txqueuelen\n' "$link" "$txq"
        if ((cpus >= 2 && cpus <= 1024)) && [[ $(gtm_optimize_rx_queues "$link") == 1 && -f $GTM_SYSFS_NET/$link/queues/rx-0/rps_cpus ]]; then
            printf 'nic|link.%s.rps|%s|rps|rps\n' "$link" "${rps:-$(gtm_optimize_mask "$cpus")}"
        fi
    done < <(gtm_optimize_links)
}

# Custom-value bounds: "n MIN MAX" (number), "n3 MIN MAX" (each field of a
# triple, ascending), "n2 MIN MAX" (low below high) or "c A,B" (choices).
gtm_optimize_bounds() {
    local memory flows
    case $1 in
        net.netfilter.nf_conntrack_max)
            memory=$(gtm_optimize_memory) || memory=0
            flows=$((memory / 4 / 350))
            ((flows <= 16777216)) || flows=16777216
            ((flows >= 65536)) || flows=65536
            printf 'n 32768 %d' "$flows";;
        net.netfilter.nf_conntrack_buckets) printf 'n 8192 4194304';;
        net.netfilter.nf_conntrack_tcp_timeout_established) printf 'n 300 432000';;
        net.netfilter.nf_conntrack_tcp_timeout_*) printf 'n 5 300';;
        net.netfilter.nf_conntrack_udp_timeout) printf 'n 10 600';;
        net.netfilter.nf_conntrack_udp_timeout_stream) printf 'n 30 3600';;
        net.core.netdev_max_backlog) printf 'n 1000 262144';;
        net.core.netdev_budget) printf 'n 300 5000';;
        net.core.netdev_budget_usecs) printf 'n 2000 32000';;
        net.core.somaxconn) printf 'n 128 65535';;
        net.ipv4.tcp_max_syn_backlog) printf 'n 128 262144';;
        net.core.default_qdisc) printf 'c fq,cake,fq_pie,fq_codel,pfifo_fast';;
        net.ipv4.tcp_congestion_control)
            printf 'c %s' "$(sysctl -n net.ipv4.tcp_available_congestion_control 2>/dev/null | awk '{$1=$1; gsub(/ /, ","); print}')";;
        net.core.rmem_max|net.core.wmem_max) printf 'n 212992 268435456';;
        net.ipv4.tcp_rmem|net.ipv4.tcp_wmem) printf 'n3 4096 268435456';;
        net.ipv4.tcp_notsent_lowat) printf 'n 16384 4294967295';;
        net.ipv4.tcp_mtu_probing|net.ipv4.tcp_tw_reuse|net.ipv4.conf.all.rp_filter|net.ipv4.conf.default.rp_filter) printf 'n 0 2';;
        net.ipv4.tcp_slow_start_after_idle|net.ipv4.conf.*.send_redirects|net.ipv4.conf.*.accept_redirects) printf 'n 0 1';;
        net.ipv4.tcp_keepalive_time) printf 'n 60 7200';;
        net.ipv4.tcp_keepalive_intvl) printf 'n 5 120';;
        net.ipv4.tcp_keepalive_probes) printf 'n 3 10';;
        net.ipv4.tcp_fin_timeout) printf 'n 5 60';;
        net.ipv4.ip_local_port_range) printf 'n2 1024 65535';;
        net.ipv4.tcp_max_tw_buckets) printf 'n 4096 4194304';;
        link.*.txqueuelen) printf 'n 100 100000';;
        link.*.rps) printf 'c 0,%s' "$(gtm_optimize_mask "$(gtm_optimize_cpus)")";;
        *) return 1;;
    esac
}

# A custom value is valid for its key and inside its bounds.
gtm_optimize_custom_valid() {
    local key=$1 value=$2 bounds kind low high field previous=-1
    local -a fields=()
    gtm_optimize_value "$key" "$value" || return 1
    bounds=$(gtm_optimize_bounds "$key") || return 1
    read -r kind low high <<< "$bounds"
    case $kind in
        c) [[ -n $low && ",$low," == *",$value,"* ]];;
        n) ((10#$value >= low && 10#$value <= high));;
        n2|n3)
            read -r -a fields <<< "$value"
            for field in "${fields[@]}"; do
                ((10#$field >= low && 10#$field <= high)) || return 1
                if [[ $kind == n2 ]]; then ((10#$field > previous)) || return 1; else ((10#$field >= previous)) || return 1; fi
                previous=$((10#$field))
            done;;
        *) return 1;;
    esac
}

# Reads "key=value" custom values into GTM_OPT_SET; refuses unknown keys or
# values outside their bounds.
gtm_optimize_custom() {
    local pair key value
    declare -gA GTM_OPT_SET=()
    (($# <= 40)) || { gtm_error 'Too many custom values.'; return 2; }
    for pair in "$@"; do
        [[ $pair == *=* ]] || { gtm_error 'Custom values are key=value.'; return 2; }
        key=${pair%%=*} value=${pair#*=}
        gtm_optimize_custom_valid "$key" "$value" || { gtm_error "Custom value for $key is outside its allowed range."; return 2; }
        GTM_OPT_SET[$key]=$value
    done
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
        net.ipv4.conf.all.accept_redirects|net.ipv4.conf.default.accept_redirects|\
        net.ipv4.ip_local_port_range|net.ipv4.tcp_max_tw_buckets) return 0;;
    esac
    [[ $1 =~ ^link\.[A-Za-z0-9_.-]{1,15}\.(txqueuelen|rps)$ ]]
}

gtm_optimize_value() {
    gtm_optimize_key "$1" || return 1
    case $1 in
        net.core.default_qdisc|net.ipv4.tcp_congestion_control) [[ $2 =~ ^[a-z0-9_]{1,16}$ ]];;
        net.ipv4.tcp_rmem|net.ipv4.tcp_wmem) [[ $2 =~ ^[0-9]{1,10}\ [0-9]{1,10}\ [0-9]{1,10}$ ]];;
        net.ipv4.ip_local_port_range) [[ $2 =~ ^[0-9]{1,5}\ [0-9]{1,5}$ ]];;
        link.*.txqueuelen) [[ $2 =~ ^[0-9]{1,6}$ ]];;
        link.*.rps) [[ $2 =~ ^(0|[1-9a-f][0-9a-f]{0,255})$ ]];;
        *) [[ $2 =~ ^[0-9]{1,10}$ ]];;
    esac
}

gtm_optimize_memory() { awk '$1 == "MemTotal:" {printf "%d", $2 * 1024; found=1; exit} END {exit !found}' "${GTM_MEMINFO:-/proc/meminfo}" 2>/dev/null; }

gtm_optimize_link_of() { local key=${1#link.}; printf '%s' "${key%.*}"; }

gtm_optimize_read() {
    local value link
    if [[ $1 == link.* ]]; then
        gtm_optimize_key "$1" || return 1
        link=$(gtm_optimize_link_of "$1")
        if [[ $1 == *.txqueuelen ]]; then
            value=$(cat "$GTM_SYSFS_NET/$link/tx_queue_len" 2>/dev/null) || return 1
        else
            # sysfs prints comma-separated 32-bit groups with leading zeros.
            value=$(cat "$GTM_SYSFS_NET/$link/queues/rx-0/rps_cpus" 2>/dev/null) || return 1
            value=$(tr -d ', \n' <<< "$value" | tr 'A-F' 'a-f' | sed 's/^0*//')
            value=${value:-0}
        fi
        value=$(awk '{$1=$1; print}' <<< "$value")
        gtm_optimize_value "$1" "$value" || return 1
        printf '%s' "$value"; return 0
    fi
    value=$(sysctl -n "$1" 2>/dev/null) || return 1
    value=$(awk '{$1=$1; print}' <<< "$value")
    gtm_optimize_value "$1" "$value" || return 1
    printf '%s' "$value"
}

# The flow limit may never drop below the flows tracked right now.
# A CPU mask in the comma-separated 32-bit groups sysfs expects.
gtm_optimize_mask_groups() {
    local mask=$1 out=''
    while ((${#mask} > 8)); do out=",${mask: -8}$out"; mask=${mask:0:${#mask}-8}; done
    printf '%s%s' "$mask" "$out"
}

gtm_optimize_write_link() {
    local link queue
    link=$(gtm_optimize_link_of "$1")
    if [[ $1 == *.txqueuelen ]]; then
        printf '%s' "$2" > "$GTM_SYSFS_NET/$link/tx_queue_len" 2>/dev/null; return
    fi
    for queue in "$GTM_SYSFS_NET/$link"/queues/rx-*/rps_cpus; do
        [[ -f $queue ]] || return 1
        printf '%s' "$(gtm_optimize_mask_groups "$2")" > "$queue" 2>/dev/null || return 1
    done
}

gtm_optimize_write() {
    local count
    [[ $1 != link.* ]] || { gtm_optimize_write_link "$1" "$2"; return; }
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
        if [[ -n $extra || ${seen[$key]+set} || ! $group =~ ^(conntrack|queues|relay|routing|nic|previous)$ ]] || ! gtm_optimize_value "$key" "$before" || ! gtm_optimize_value "$key" "$applied"; then
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
        [[ -n $key && $key != link.* ]] && printf '%s = %s\n' "$key" "$applied"
    done < <(((${#GTM_OPT_ROWS[@]} == 0)) || printf '%s\n' "${GTM_OPT_ROWS[@]}" | LC_ALL=C sort)
}

# The boot script for link rows; empty when none are applied. Link names
# and values are validated, so they are safe inside double quotes.
gtm_optimize_links_render() {
    local key before applied group link found=0
    while IFS=$'\t' read -r key before applied group; do
        [[ $key == link.* ]] || continue
        ((found)) || printf '#!/bin/sh\n# Traffic Manager owned. Change or remove it from the panel (Optimization).\nn=%s\n' "$GTM_SYSFS_NET"
        found=1; link=$(gtm_optimize_link_of "$key")
        if [[ $key == *.txqueuelen ]]; then
            printf '[ -w "$n/%s/tx_queue_len" ] && printf %%s %s > "$n/%s/tx_queue_len"\n' "$link" "$applied" "$link"
        else
            printf 'for q in "$n/%s"/queues/rx-*/rps_cpus; do [ -w "$q" ] && printf %%s %s > "$q"; done\n' "$link" "$(gtm_optimize_mask_groups "$applied")"
        fi
    done < <(((${#GTM_OPT_ROWS[@]} == 0)) || printf '%s\n' "${GTM_OPT_ROWS[@]}" | LC_ALL=C sort)
    ((found == 0)) || printf 'exit 0\n'
}

gtm_optimize_unit_render() {
    printf '%s\n' '[Unit]' 'Description=Traffic Manager link optimization (queue length, packet steering)' \
        'After=network-online.target' 'Wants=network-online.target' '' '[Service]' 'Type=oneshot' \
        "ExecStart=/bin/sh $GTM_OPT_LINK_SCRIPT" 'RemainAfterExit=yes' '' '[Install]' 'WantedBy=multi-user.target'
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
    local conf='' modules='' old_conf old_modules links old_links unit='' old_unit=''
    GTM_OPT_ROWS=("${prior[@]}"); old_conf=''; old_modules=$(gtm_optimize_modules_render); old_links=$(gtm_optimize_links_render)
    ((${#prior[@]} == 0)) || old_conf=$(gtm_optimize_render; printf x); old_conf=${old_conf%x}
    GTM_OPT_ROWS=("${next[@]}"); modules=$(gtm_optimize_modules_render); links=$(gtm_optimize_links_render)
    ((${#next[@]} == 0)) || conf=$(gtm_optimize_render; printf x); conf=${conf%x}
    [[ -z $modules ]] || modules+=$'\n'; [[ -z $old_modules ]] || old_modules+=$'\n'
    [[ -z $links ]] || { links+=$'\n'; unit=$(gtm_optimize_unit_render)$'\n'; }
    [[ -z $old_links ]] || { old_links+=$'\n'; old_unit=$(gtm_optimize_unit_render)$'\n'; }
    [[ -z $links ]] || mkdir -p "${GTM_OPT_LINK_SCRIPT%/*}" || return 1
    gtm_optimize_save_rows "$GTM_OPT_JOURNAL" && gtm_optimize_owned_file "$GTM_OPT_FILE" "$conf" "$old_conf" &&
        gtm_optimize_owned_file "$GTM_OPT_MODULES" "$modules" "$old_modules" &&
        gtm_optimize_owned_file "$GTM_OPT_LINK_SCRIPT" "$links" "$old_links" || return 1
    [[ -n $unit || -n $old_unit ]] || return 0
    gtm_optimize_owned_file "$GTM_OPT_LINK_UNIT" "$unit" "$old_unit" || return 1
    [[ -z $unit || -z $old_unit ]] || return 0
    command -v systemctl >/dev/null 2>&1 || return 0
    if [[ -n $unit ]]; then systemctl daemon-reload && systemctl enable gre-manager-optimize.service >/dev/null 2>&1
    else systemctl disable gre-manager-optimize.service >/dev/null 2>&1; systemctl daemon-reload; fi ||
        printf 'Warning: the boot unit for link settings could not be updated; the settings apply until reboot.\n' >&2
    return 0
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
        range)
            read -r -a have <<< "$current"; read -r -a want <<< "$wanted"
            printf '%d %d' "$(( 10#${have[0]} < 10#${want[0]} ? 10#${have[0]} : 10#${want[0]} ))" "$(( 10#${have[1]} > 10#${want[1]} ? 10#${have[1]} : 10#${want[1]} ))";;
        prefer=*) [[ ",${mode#prefer=}," == *",$current,"* ]] && printf '%s' "$current" || printf '%s' "$wanted";;
        loose) [[ $current == 1 ]] && printf 2 || printf '%s' "$current";;
        rps) [[ $current != 0 ]] && printf '%s' "$current" || printf '%s' "$wanted";;
        *) printf '%s' "$wanted";;
    esac
}

# A wider port range never takes a port a service listens on right now: the
# low end then stays where it is.
gtm_optimize_ports() {
    local now_low now_high low high port
    read -r now_low now_high <<< "$1"; read -r low high <<< "$2"
    if ((10#$low < 10#$now_low)); then
        while IFS= read -r port; do
            [[ $port =~ ^[0-9]{1,5}$ ]] && ((10#$port >= 10#$low && 10#$port < 10#$now_low)) && { low=$now_low; break; }
        done < <(ss -Hltnu 2>/dev/null | awk '{n = split($5, part, ":"); print part[n]}')
    fi
    printf '%s %s' "$low" "$high"
}

# Sets GTM_OPT_PLAN rows "group key current value reason note" for groups.
# Note: change, same (already the recommendation), kept (the server's own
# value is already better and stays), off (the profile leaves the key at its
# original value), custom (a custom value), worse (a custom value worse than
# the original) or missing (no such key or algorithm). Keys the panel applied
# compare against their original value, so a lighter profile can return them.
gtm_optimize_compute() {
    local groups=" $* " group key wanted value mode reason current note base row before applied
    local -A before_of=() applied_of=()
    GTM_OPT_PLAN=()
    for row in ${GTM_OPT_ROWS[@]+"${GTM_OPT_ROWS[@]}"}; do
        IFS=$'\t' read -r key before applied group <<< "$row"
        before_of[$key]=$before applied_of[$key]=$applied
    done
    # BBR may be a module that is not loaded yet; loading it changes nothing else.
    if [[ ${GTM_OPT_READONLY:-0} == 0 && $groups == *' relay '* && " $(sysctl -n net.ipv4.tcp_available_congestion_control 2>/dev/null) " != *' bbr '* ]]; then
        command -v modprobe >/dev/null 2>&1 && modprobe tcp_bbr 2>/dev/null
    fi
    while IFS='|' read -r group key wanted mode reason; do
        [[ $groups == *" $group "* ]] || continue
        value=$wanted; note=change
        if ! current=$(gtm_optimize_read "$key"); then
            current=-; note=missing
        else
            # Only while the live value is still what the panel applied.
            base=$current
            [[ ${applied_of[$key]-} != "$current" ]] || base=${before_of[$key]}
            if [[ ${GTM_OPT_SET[$key]+set} ]]; then
                value=${GTM_OPT_SET[$key]} note=custom
                [[ $(gtm_optimize_better "$base" "$value" "$mode") == "$value" ]] || note=worse
                [[ $value != "$current" ]] || note=same
            elif [[ $wanted == - ]]; then
                value=$base
                [[ $value != "$current" ]] || note=off
            elif [[ $key == net.ipv4.tcp_congestion_control && " $(sysctl -n net.ipv4.tcp_available_congestion_control 2>/dev/null) " != *" $wanted "* && $mode != *",$current"* && $mode != *"=$current"* ]]; then
                note=missing
            else
                value=$(gtm_optimize_better "$base" "$wanted" "$mode")
                [[ $key != net.ipv4.ip_local_port_range ]] || value=$(gtm_optimize_ports "$current" "$value")
                if [[ $value == "$current" ]]; then
                    note=kept; [[ $current != "$wanted" ]] || note=same
                fi
            fi
        fi
        GTM_OPT_PLAN+=("$group"$'\t'"$key"$'\t'"$current"$'\t'"$value"$'\t'"$reason"$'\t'"$note")
    done < <(gtm_optimize_catalog)
}

# The profile last applied ("level goal"); balanced general before any.
gtm_optimize_saved_profile() {
    local level goal
    [[ -f $GTM_OPT_DIR/profile ]] && read -r level goal < "$GTM_OPT_DIR/profile" && gtm_optimize_profile_valid "$level" "$goal" ||
        { level=balanced goal=general; }
    printf '%s %s' "$level" "$goal"
}

# Selects the profile for this call: "LEVEL GOAL", or the saved one for "-".
gtm_optimize_use_profile() {
    local level=$1 goal=$2
    gtm_optimize_paths
    [[ $level != - ]] || read -r level goal <<< "$(gtm_optimize_saved_profile)"
    gtm_optimize_profile_valid "$level" "$goal" || { gtm_error 'Unknown optimization profile.'; return 2; }
    GTM_OPT_LEVEL=$level GTM_OPT_GOAL=$goal
}

gtm_optimize_groups_valid() {
    local group
    (($#)) || return 1
    for group in "$@"; do [[ $group =~ ^(conntrack|queues|relay|routing|nic)$ ]] || return 1; done
}

# Read-only preview: one "change" row per catalog key of the groups.
gtm_optimize_plan() {
    local row key
    gtm_optimize_groups_valid "$@" || { gtm_error 'Unknown optimization group.'; return 2; }
    gtm_optimize_paths
    gtm_optimize_load || return 1
    gtm_optimize_compute "$@"
    gtm_optimize_others
    for row in "${GTM_OPT_PLAN[@]}"; do
        key=$(cut -f2 <<< "$row")
        printf 'change\t%s\t%s\t%s\n' "$row" "${GTM_OPT_OTHERS[$key]:-$'-\t-'}" "$(gtm_optimize_bounds "$key" || printf -)"
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
    file=$(gtm_optimize_last_step)
    [[ -z $file ]] || printf 'meta\tlast\t%s\n' "$(stat -c %Y "$file" 2>/dev/null || printf 0)"
    printf 'meta\tprofile\t%s\n' "$(gtm_optimize_saved_profile)"
    printf 'meta\tview\t%s %s\n' "${GTM_OPT_LEVEL:-balanced}" "${GTM_OPT_GOAL:-general}"
    printf 'meta\tcapped\t%s\n' "$(gtm_optimize_capped)"
    printf 'meta\tcpus\t%s\n' "$(gtm_optimize_cpus)"
    while IFS= read -r file; do [[ -z $file ]] || printf 'meta\tlink\t%s %s\n' "$file" "$(gtm_optimize_rx_queues "$file")"; done < <(gtm_optimize_links)
    printf 'meta\tfile\t%s\n' "$GTM_OPT_FILE"
    [[ ! -f $GTM_OPT_OLD_JOURNAL ]] || printf 'meta\timport\t%s\n' "$GTM_OPT_OLD_JOURNAL"
    while IFS= read -r file; do [[ -z $file ]] || printf 'meta\tservertools\t%s\n' "$file"; done < <(gtm_optimize_servertools)
    gtm_optimize_others
    GTM_OPT_READONLY=1 gtm_optimize_compute conntrack queues relay routing nic
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
    printf 'Profile %s / %s. Server-wide settings (they do not promise a number of users):\n' "${GTM_OPT_LEVEL:-balanced}" "${GTM_OPT_GOAL:-general}"
    for row in "${GTM_OPT_PLAN[@]}"; do
        IFS=$'\t' read -r group key current value reason note <<< "$row"
        case $note in
            same) printf '  %s = %s (already set)\n' "$key" "$current"; continue;;
            kept) printf '  %s = %s (the server value is already better; kept)\n' "$key" "$current"; continue;;
            off) continue;;
            missing) printf '  %s: not available on this kernel; skipped\n' "$key"; continue;;
            worse) [[ ${GTM_OPT_ALLOW_WORSE:-0} == 1 ]] || { gtm_error "The custom value for $key is worse than the server's original value; confirm it to apply."; return 1; }
                printf '  %s: %s -> %s (custom; worse than the original value)\n' "$key" "$current" "$value";;
            *) printf '  %s: %s -> %s\n' "$key" "$current" "$value";;
        esac
        attempts+=("$key"$'\t'"$current"$'\t'"$value"$'\t'"$group")
    done
    ((${#attempts[@]})) || { printf 'Nothing to change.\n'; return 0; }
    gtm_confirm || return 1
    # The undo step and journal are durable before the first live write. A
    # key that returns to its original value is no longer tracked.
    for row in "${attempts[@]}"; do
        IFS=$'\t' read -r key current value group <<< "$row"
        if [[ ${rows[$key]+set} ]]; then IFS=$'\t' read -r _ current _ _ <<< "${rows[$key]}"; fi
        if [[ $value == "$current" ]]; then unset 'rows[$key]'; continue; fi
        rows[$key]="$key"$'\t'"$current"$'\t'"$value"$'\t'"$group"
    done
    GTM_OPT_ROWS=(); for key in "${!rows[@]}"; do GTM_OPT_ROWS+=("${rows[$key]}"); done
    local -a planned=(${GTM_OPT_ROWS[@]+"${GTM_OPT_ROWS[@]}"})
    gtm_optimize_push_step && GTM_OPT_ROWS=(${planned[@]+"${planned[@]}"}) && gtm_optimize_save_rows "$GTM_OPT_JOURNAL" || return 1
    for row in "${attempts[@]}"; do
        IFS=$'\t' read -r key current value group <<< "$row"
        if gtm_optimize_write "$key" "$value"; then done_rows+=("$row"); ((written+=1)); else failed=1; break; fi
    done
    if ((failed == 0)) && GTM_OPT_ROWS=(${planned[@]+"${planned[@]}"}) && gtm_optimize_persist; then
        printf '%s %s\n' "${GTM_OPT_LEVEL:-balanced}" "${GTM_OPT_GOAL:-general}" > "$GTM_OPT_DIR/profile" && chmod 600 "$GTM_OPT_DIR/profile"
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
    [[ $which =~ ^(conntrack|queues|relay|routing|nic|previous|all)$ ]] || { gtm_error 'Unknown optimization group.'; return 2; }
    gtm_optimize_paths
    gtm_optimize_import && gtm_optimize_load || return 1
    ((${#GTM_OPT_ROWS[@]})) || { printf 'Nothing is applied.\n'; [[ $which != all ]] || rm -rf "$GTM_OPT_STEPS" "$GTM_OPT_DIR/profile"; return 0; }
    for row in "${GTM_OPT_ROWS[@]}"; do [[ $which != all && ${row##*$'\t'} != "$which" ]] && remaining+=("$row"); done
    gtm_confirm || return 1
    GTM_OPT_PREVIOUS=("${GTM_OPT_ROWS[@]}")
    if [[ $which != all ]]; then gtm_optimize_push_step || return 1; GTM_OPT_ROWS=("${GTM_OPT_PREVIOUS[@]}"); fi
    gtm_optimize_move remaining || { gtm_error 'Some settings could not be restored; they stay tracked. Try again.'; return 1; }
    if [[ $which == all ]]; then
        rm -rf "$GTM_OPT_STEPS"; rm -f "$GTM_OPT_JOURNAL" "$GTM_OPT_DIR/profile"
        printf 'Every setting is back to its original value; the panel files were removed.\n'
    else
        printf 'Settings of %s are back to their original values.\n' "$which"
    fi
}

gtm_optimize_menu() {
    local choice level goal
    local -a groups=(conntrack queues relay routing nic)
    gtm_optimize_use_profile - - || return
    while true; do
        gtm_header 'Server optimization / opt-in, reversible'
        gtm_help tuning
        printf '  Profile: %s / %s\n\n' "$GTM_OPT_LEVEL" "$GTM_OPT_GOAL"
        gtm_option 1 'Show settings' 'Current, original and applied values'
        gtm_option 2 'Connection tracking' 'Recommended for forwarders: fixes rising latency'
        gtm_option 3 'Packet queues' 'High packet rates'
        gtm_option 4 'Relay TCP' 'HAProxy / Realm / FRP: BBR, buffers, keepalive'
        gtm_option 5 'Tunnels & routing' 'Loose reverse-path filter, no ICMP redirects'
        gtm_option 6 'Network card' 'Transmit queue length; spread receive work across CPUs (RPS)'
        gtm_option 7 'Undo last step'
        gtm_option 8 'Reset everything' 'Original values; remove panel files'
        gtm_option 9 'Change profile' 'conservative / balanced / aggressive; general / users / latency'
        gtm_option 0 Back
        gtm_read 'Choose: ' choice || return
        case $choice in
            1) gtm_optimize_status | awk -F '\t' '$1 == "key" {printf "  %-52s %-22s (original %s)\n", $3, $4, $5}'; gtm_pause;;
            2|3|4|5|6) gtm_prepare && gtm_lock || return; gtm_optimize_apply "${groups[$((choice-2))]}"; gtm_unlock; gtm_pause;;
            7) gtm_prepare && gtm_lock || return; gtm_optimize_undo; gtm_unlock; gtm_pause;;
            8) gtm_prepare && gtm_lock || return; gtm_optimize_remove all; gtm_unlock; gtm_pause;;
            9) gtm_read 'Level (conservative, balanced, aggressive): ' level || continue
               gtm_read 'Goal (general, users, latency): ' goal || continue
               gtm_optimize_use_profile "$level" "$goal" || gtm_pause;;
            0) return;;
        esac
    done
}
