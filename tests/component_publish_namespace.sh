#!/usr/bin/env bash
# File-transaction fixture only: a private mount shadows /usr/local/bin.
# No downloaded binary is executed and no host service is contacted.
set -euo pipefail
cd "$(dirname "$0")/.."
if [[ ${GTM_COMPONENT_TEST_MOUNT:-0} != 1 ]]; then
    exec unshare -m env GTM_COMPONENT_TEST_MOUNT=1 bash "$0"
fi
mount --make-rprivate /
test_dir=$(mktemp -d /tmp/gtm-component-test.XXXXXX)
mkdir "$test_dir/bin" "$test_dir/source" "$test_dir/config"
mount --bind "$test_dir/bin" /usr/local/bin
cleanup() {
    local status=$?
    umount /usr/local/bin || return 1
    [[ $test_dir == /tmp/gtm-component-test.* && -d $test_dir && ! -L $test_dir ]] || return 1
    find "$test_dir" -mindepth 1 -depth -delete
    rmdir "$test_dir"
    return "$status"
}
trap cleanup EXIT
source ./gre.sh
GTM_CONFIG_DIR="$test_dir/config"; gtm_paths
printf old-realm > /usr/local/bin/realm
printf old-frpc > /usr/local/bin/frpc
printf new-realm > "$test_dir/source/realm"
printf new-frpc > "$test_dir/source/frpc"
gtm_component_publish "$test_dir/source" realm frpc
[[ $(cat /usr/local/bin/realm) == new-realm && $(cat /usr/local/bin/frpc) == new-frpc ]]
backup=("$GTM_CONFIG_DIR"/engine-backups/update.*/realm)
[[ ${#backup[@]} == 1 && $(cat "${backup[0]}") == old-realm ]]

# Every requested binary must stage before any target changes.
printf should-not-publish > "$test_dir/source/realm"
if gtm_component_publish "$test_dir/source" realm frps; then exit 1; fi
[[ $(cat /usr/local/bin/realm) == new-realm ]]

# Failure publishing the second binary restores the first and removes candidates.
printf newer-frpc > "$test_dir/source/frpc"
printf new-frps > "$test_dir/source/frps"
mv() { [[ ${*: -1} != /usr/local/bin/frps ]] && command mv "$@"; }
if gtm_component_publish "$test_dir/source" frpc frps; then exit 1; fi
[[ $(cat /usr/local/bin/frpc) == new-frpc && ! -e /usr/local/bin/frps ]]
if compgen -G '/usr/local/bin/.gtm-engine-*.tmp' >/dev/null; then exit 1; fi
printf 'PASS: pinned engine staging, retained backup and failed-pair publication recovery.\n'
