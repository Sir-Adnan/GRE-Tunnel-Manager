"""v1.4.1 engine features: network card optimization, change history and guided diagnosis."""
from pathlib import Path
import tempfile
import unittest

from test_manager import ROOT, bash, record
import test_advanced
from test_advanced import OPT_MOCK, paths

(ROOT / '.work').mkdir(exist_ok=True)

LINKS = r'''
GTM_MEMINFO=$GTM_CONFIG_DIR/meminfo GTM_SYSFS_NET=$GTM_CONFIG_DIR/net GTM_PROC_ROUTE=$GTM_CONFIG_DIR/route
GTM_PROC_ROUTE6=$GTM_CONFIG_DIR/route6 GTM_CPUS=${GTM_CPUS:-6} GTM_RUNTIME=$GTM_CONFIG_DIR/lib/apply.sh
systemctl() { printf '%s\n' "$*" >> "$GTM_CONFIG_DIR/calls"; }
mkdir -p "$GTM_SYSFS_NET/eth0/queues/rx-0" "$GTM_SYSFS_NET/lo"
printf '1000\n' > "$GTM_SYSFS_NET/eth0/tx_queue_len"; printf '00000000\n' > "$GTM_SYSFS_NET/eth0/queues/rx-0/rps_cpus"
printf 'Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\nlo\t0000007F\t0\t1\t0\t0\t0\t000000FF\neth0\t00000000\t0101A8C0\t3\t0\t0\t0\t00000000\n' > "$GTM_PROC_ROUTE"
value() { gtm_optimize_read "$1"; }
'''


class FeatureTests(unittest.TestCase):
    def optimize(self, folder, code):
        (folder/'sysctls.tsv').write_text(test_advanced.AdvancedTests.HOST_DB, newline='\n')
        (folder/'meminfo').write_text('MemTotal:        4194304 kB\n', newline='\n')
        return bash(paths(folder)+OPT_MOCK+LINKS+code)

    def test_network_card_steering_queue_and_boot_unit(self):
        with tempfile.TemporaryDirectory(dir=ROOT/'.work') as directory:
            folder = Path(directory)
            result = self.optimize(folder, r"""
gtm_optimize_paths
[[ $(gtm_optimize_links) == eth0 ]] || exit 9
gtm_optimize_catalog | grep -qx 'nic|link.eth0.txqueuelen|5000|raise|txqueuelen' || exit 10
gtm_optimize_catalog | grep -qx 'nic|link.eth0.rps|3f|rps|rps' || exit 11
GTM_OPT_LEVEL=conservative gtm_optimize_catalog | grep -qx 'nic|link.eth0.rps|-|rps|rps' || exit 12
GTM_OPT_GOAL=latency gtm_optimize_catalog | grep -qx 'nic|link.eth0.txqueuelen|-|raise|txqueuelen' || exit 13
gtm_optimize_apply nic || exit 14
[[ $(value link.eth0.txqueuelen) == 5000 && $(value link.eth0.rps) == 3f ]] || exit 15
grep -q 'printf %s 3f > "$q"' "$GTM_OPT_LINK_SCRIPT" && grep -q 'printf %s 5000' "$GTM_OPT_LINK_SCRIPT" || exit 16
grep -q "ExecStart=/bin/sh $GTM_OPT_LINK_SCRIPT" "$GTM_OPT_LINK_UNIT" || exit 17
grep -qx 'enable gre-manager-optimize.service' "$GTM_CONFIG_DIR/calls" || exit 18
! grep -q link "$GTM_OPT_FILE" || exit 19
gtm_optimize_status | grep -qx $'meta\tlink\teth0 1' || exit 20
# Never worse: a mask the server already set is kept.
gtm_optimize_remove all || exit 21
[[ $(value link.eth0.txqueuelen) == 1000 && $(value link.eth0.rps) == 0 ]] || exit 22
[[ ! -e $GTM_OPT_LINK_SCRIPT && ! -e $GTM_OPT_LINK_UNIT ]] || exit 23
grep -qx 'disable gre-manager-optimize.service' "$GTM_CONFIG_DIR/calls" || exit 24
printf '00000003\n' > "$GTM_SYSFS_NET/eth0/queues/rx-0/rps_cpus"
gtm_optimize_plan nic | grep -q $'\tlink.eth0.rps\t3\t3\trps\tkept' || exit 25
gtm_optimize_custom link.eth0.rps=0 && gtm_optimize_plan nic | grep -q $'\tlink.eth0.rps\t3\t0\trps\tworse' || exit 26
gtm_optimize_custom 'link.eth0.rps=ff' && exit 27
gtm_optimize_custom 'link.eth0.txqueuelen=50' && exit 28
gtm_optimize_custom 'link.eth0;id.txqueuelen=5000' && exit 29
[[ $(gtm_optimize_mask_groups 3ffffffffff) == 3ff,ffffffff && $(gtm_optimize_mask 40) == ffffffffff ]] || exit 30
exit 0
""")
            self.assertEqual(result.returncode, 0, result.stdout+result.stderr)

    def test_network_card_is_skipped_for_one_cpu_or_multiqueue(self):
        with tempfile.TemporaryDirectory(dir=ROOT/'.work') as directory:
            folder = Path(directory)
            result = self.optimize(folder, r"""
gtm_optimize_paths
GTM_CPUS=1 gtm_optimize_catalog | grep -q 'link.eth0.rps' && exit 9
mkdir -p "$GTM_SYSFS_NET/eth0/queues/rx-1"
gtm_optimize_catalog | grep -q 'link.eth0.rps' && exit 10
gtm_optimize_catalog | grep -q 'link.eth0.txqueuelen' || exit 11
gtm_api optimize-plan balanced general nic,relay,routing,queues,conntrack > /dev/null || exit 12
exit 0
""")
            self.assertEqual(result.returncode, 0, result.stdout+result.stderr)

    def test_history_lists_points_and_restores_only_the_reviewed_revision(self):
        with tempfile.TemporaryDirectory(dir=ROOT/'.work') as directory:
            folder = Path(directory)
            backups = folder/'backups'
            backups.mkdir()
            (backups/'20260101T020000-11-1.tsv').write_text('# Traffic Manager state v1\n', newline='\n')
            (backups/'20260102T020000-12-2.tsv').write_text(record()+'\n', newline='\n')
            (backups/'cleanup-old.tsv').write_text('ignored\n', newline='\n')
            (folder/'connections.tsv').write_text(record()+'\n'+record(id='F000002', port='8443')+'\n', newline='\n')
            result = bash(paths(folder)+r"""
out=$(gtm_api history) || exit 9
printf '%s\n' "$out" > "$GTM_CONFIG_DIR/out"
[[ $(grep -c $'^point\t' <<< "$out") == 2 && $(grep -c $'^total\t2$' <<< "$out") == 1 ]] || exit 10
[[ $(sed -n '3p' <<< "$out") == $'point\t20260102T020000-12-2.tsv' ]] || exit 11
grep -q 'cleanup-old' <<< "$out" && exit 12
revision=$(gtm_recovery_revision)
gtm_prepare() { :; }; gtm_lock() { :; }; gtm_unlock() { :; }
gtm_commit() { printf '%s\n' "${GTM_RECORDS[@]}" > "$GTM_CONFIG_DIR/committed"; }
gtm_api history-restore 20260102T020000-12-2.tsv "$(printf 'a%.0s' {1..64})" && exit 13
gtm_api history-restore ../connections.tsv "$revision" && exit 14
gtm_api history-restore 20260102T020000-12-2.tsv "$revision" || exit 15
[[ $(wc -l < "$GTM_CONFIG_DIR/committed") == 1 ]] || exit 16
exit 0
""")
            self.assertEqual(result.returncode, 0, result.stdout+result.stderr)

    def test_diagnosis_reports_connection_and_gre_checks(self):
        with tempfile.TemporaryDirectory(dir=ROOT/'.work') as directory:
            folder = Path(directory)
            (folder/'connections.tsv').write_text(record(strategy='roundrobin', targets='203.0.113.20:443@1,203.0.113.21:443@1')+'\n'+record(id='F000002', engine='realm', port='8443')+'\n', newline='\n')
            (folder/'gre-tun-7.service').write_text('ExecStart=/sbin/ip tunnel add gre-out-7 mode gre remote 198.51.100.5 local 192.0.2.10 ttl 255 key 7\n', newline='\n')
            mocks = r"""
sysctl() { case $2 in net.ipv4.ip_forward) echo 1;; net.netfilter.nf_conntrack_count) echo 95;; net.netfilter.nf_conntrack_max) echo 100;; *) return 1;; esac; }
nft() { printf 'add rule ... comment "gtm-F000001"\nadd rule ... comment "gtm-F000001"\n'; }
systemctl() { [[ $2 == gtm-F000002 ]] && echo active || echo failed; }
ss() { :; }
ip() { [[ $* == *'route get'* ]] && echo "$4 via 192.0.2.1 dev eth0 src 192.0.2.10"; }
iptables() { [[ $1 == -S ]] && printf -- '-P INPUT DROP\n-A INPUT -i lo -j ACCEPT\n'; }
"""
            result = bash(paths(folder)+mocks+r"""
out=$(gtm_api diagnose F000001) || exit 9
printf '%s\n' "$out" > "$GTM_CONFIG_DIR/f1"
grep -qx $'check\tenabled\tok\t' <<< "$out" && grep -qx $'check\tforwarding\tok\tIPv4' <<< "$out" || exit 10
grep -qx $'check\trules\tok\t2' <<< "$out" && grep -qx $'check\tconntrack\tfail\t95/100' <<< "$out" || exit 11
[[ $(grep -c $'^probe\ttcp\t203.0.113.2[01]\t443\tdestination$' <<< "$out") == 2 ]] || exit 12
out=$(gtm_api diagnose F000002) || exit 13
grep -qx $'check\tservice\tok\tgtm-F000002' <<< "$out" && grep -qx $'check\tlistener\tfail\ttcp/8443' <<< "$out" || exit 14
out=$(gtm_api diagnose gre-tun-7) || exit 15
printf '%s\n' "$out" > "$GTM_CONFIG_DIR/gre"
grep -q $'^check\tservice\tfail' <<< "$out" && grep -qx $'check\tgre-input\twarn\tINPUT policy DROP' <<< "$out" || exit 16
grep -qx $'probe\ticmp\t10.0.7.1\t0\tpeer-inner' <<< "$out" && grep -qx $'probe\ticmp\t198.51.100.5\t0\tpeer-public' <<< "$out" || exit 17
gtm_api diagnose 'F000001;id' && exit 18
gtm_api diagnose gre-tun-999 && exit 19
gtm_api diagnose F000009 && exit 20
exit 0
""")
            self.assertEqual(result.returncode, 0, result.stdout+result.stderr)


if __name__ == '__main__':
    unittest.main()
