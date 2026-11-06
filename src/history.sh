# Change history: the automatic restore points gtm_commit writes before every
# forwarding change, newest first, and restoring one through the normal
# commit path. A restore saves the current state as a new restore point
# first, so it can be undone the same way.

gtm_history_name_valid() { [[ $1 =~ ^[0-9]{8}T[0-9]{6}-[0-9]+-[0-9]+\.tsv$ ]]; }

# New names contain a locked monotonic nanosecond sequence. Historical PID/random
# names use their write time as a best-effort tie-breaker within the named second.
gtm_history_points() {
    local file name modified
    for file in "$GTM_CONFIG_DIR"/backups/*.tsv; do
        [[ -f $file && ! -L $file ]] && gtm_history_name_valid "${file##*/}" || continue
        name=${file##*/}
        if [[ $name =~ ^[0-9]{8}T[0-9]{6}-([0-8][0-9]{18})-[0-9]+\.tsv$ ]]; then
            modified=${BASH_REMATCH[1]: -9}
        else
            modified=$(stat -c '%y' -- "$file") || return 1
            modified=${modified#*.}; modified=${modified:0:9}
        fi
        printf '%s\t%s\t%s\n' "${name:0:15}" "$modified" "$file"
    done | LC_ALL=C sort -r | cut -f 3-
}

# Read-only: "revision", "total", then per point "point NAME" followed by
# "row RECORD" lines (normalized records) or "invalid NAME".
gtm_history() {
    local limit=${1:-30} file line
    local -a points=()
    gtm_uint "$limit" 1 100 || { gtm_error 'History limit must be 1-100.'; return 2; }
    mapfile -t points < <(gtm_history_points)
    printf 'revision\t%s\n' "$(gtm_recovery_revision)"
    printf 'total\t%d\n' "${#points[@]}"
    for file in "${points[@]:0:10#$limit}"; do
        if ! gtm_load_records "$file" 2>/dev/null; then printf 'invalid\t%s\n' "${file##*/}"; continue; fi
        printf 'point\t%s\n' "${file##*/}"
        for line in ${GTM_RECORDS[@]+"${GTM_RECORDS[@]}"}; do printf 'row\t%s\n' "$line"; done
    done
}

# Restores one point when the configuration still has the reviewed revision.
gtm_history_restore() {
    local name=$1 expected=$2 file actual result=1
    gtm_history_name_valid "$name" && [[ $expected =~ ^[a-f0-9]{64}$ ]] || { gtm_error 'Invalid restore point.'; return 2; }
    file="$GTM_CONFIG_DIR/backups/$name"
    [[ -f $file && ! -L $file ]] || { gtm_error 'Restore point not found.'; return 1; }
    gtm_prepare && gtm_lock || return 1
    actual=$(gtm_recovery_revision) && [[ $actual == "$expected" ]] || { gtm_error 'Configuration changed; review the restore again.'; gtm_unlock; return 1; }
    if gtm_load_records "$file"; then gtm_commit; result=$?; fi
    gtm_unlock
    return "$result"
}
