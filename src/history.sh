# Change history: the automatic restore points gtm_commit writes before every
# forwarding change, newest first, and restoring one through the normal
# commit path. A restore saves the current state as a new restore point
# first, so it can be undone the same way.

gtm_history_name_valid() { [[ $1 =~ ^[0-9]{8}T[0-9]{6}-[0-9]+-[0-9]+\.tsv$ ]]; }

# Restore point paths, newest first (names start with a UTC timestamp).
gtm_history_points() {
    local file
    for file in "$GTM_CONFIG_DIR"/backups/*.tsv; do
        [[ -f $file && ! -L $file ]] && gtm_history_name_valid "${file##*/}" && printf '%s\n' "$file"
    done | LC_ALL=C sort -r
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
