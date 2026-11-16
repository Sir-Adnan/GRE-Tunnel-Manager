"""v1.6.0 firewall: access rules, abuse protection, tagged UFW openings and automatic revert."""
from pathlib import Path
import tempfile
import unittest

from test_manager import ROOT, bash, record
from test_advanced import paths

(ROOT / '.work').mkdir(exist_ok=True)

# Stubs: nft accepts every batch; systemd-run/systemctl and ufw log their calls.
# The UFW stub keeps rules in a file, prints "ufw status" from it and refuses
# duplicates the way UFW skips an existing rule.
STUBS = r'''
gtm_root() { :; }; gtm_prepare() { :; }; gtm_lock() { :; }; gtm_unlock() { :; }
gtm_install_runner() { :; }
gtm_guard_uplinks() { printf 'eth0\n'; }
gtm_guard_auto_exceptions() { printf '10.202.10.10\n203.0.113.20\n'; }
nft() { printf 'nft %s\n' "$*" >> "$GTM_CONFIG_DIR/calls"; [[ $1 != list ]] || [[ -f $GTM_CONFIG_DIR/table ]]; [[ $1 != -f ]] || touch "$GTM_CONFIG_DIR/table"; [[ $1 != delete ]] || rm -f "$GTM_CONFIG_DIR/table"; return 0; }
systemctl() { printf 'systemctl %s\n' "$*" >> "$GTM_CONFIG_DIR/calls"; }
systemd-run() { printf 'systemd-run %s\n' "$*" >> "$GTM_CONFIG_DIR/calls"; }
ufw() {
    local rules=$GTM_CONFIG_DIR/ufw-rules
    printf 'ufw %s\n' "$*" >> "$GTM_CONFIG_DIR/calls"
    case $1 in
        status) printf 'Status: active\n\nTo                         Action      From\n--                         ------      ----\n'; cat "$rules" 2>/dev/null ;;
        allow) local line; line=$(printf '%-26s ALLOW       Anywhere                   # %s' "$7/$3" "$9")
               grep -q "^$7/$3 " "$rules" 2>/dev/null && return 0; printf '%s\n' "$line" >> "$rules" ;;
        delete) grep -v "^$8/$4 " "$rules" > "$rules.new"; mv "$rules.new" "$rules" ;;
    esac
}
'''


class FirewallTests(unittest.TestCase):
    def run_in(self, code, rows=()):
        with tempfile.TemporaryDirectory(dir=ROOT/'.work') as directory:
            folder = Path(directory)
            if rows:
                (folder/'connections.tsv').write_text('\n'.join(rows)+'\n', newline='\n')
            return bash(paths(folder)+STUBS+code)

    def test_cidrs_and_settings_validate(self):
        result = self.run_in(r'''
for ok in 203.0.113.0/24 203.0.113.7 2001:db8::/32 2001:db8::1 10.0.0.0/8 2001:db8:8000::/33; do gtm_guard_cidr "$ok" || { echo "rejected $ok"; exit 9; }; done
for bad in 203.0.113.1/24 0.0.0.0/0 10.0.0.0/33 2001:db8::1/32 2001:db8:c000::/33 example.com 1.2.3.4/x; do gtm_guard_cidr "$bad" && { echo "accepted $bad"; exit 10; }; done
gtm_guard_line_valid $'access\tF000001\tallow\t0\t0\t203.0.113.0/24,2001:db8::/32' || exit 11
gtm_guard_line_valid $'access\tF000001\tallow\t0\t0\t-' && exit 12
gtm_guard_line_valid $'access\tF000001\toff\t50\t20\t-' || exit 13
gtm_guard_line_valid $'access\tF000001\tdeny\t0\t0\t1.2.3.0/24,' && exit 14
gtm_guard_line_valid $'protect\tprivate\t1' && gtm_guard_line_valid $'except\t10.202.10.0/24' && gtm_guard_line_valid $'ufw\tF000002' || exit 15
gtm_guard_line_valid $'protect\tall\t1' && exit 16
gtm_guard_line_valid $'access\tF000001\tallow\t0\t0\t1.2.3.4\textra' && exit 17
exit 0
''')
        self.assertEqual(result.returncode, 0, result.stdout+result.stderr)

    def test_change_checks_revision_family_and_known_connections(self):
        result = self.run_in(r'''
gtm_guard_change 0 <<< $'0000000000000000000000000000000000000000000000000000000000000000\nprotect\tprivate\t1' 2>/dev/null && exit 9
gtm_guard_change 0 <<< $'none\naccess\tF000009\tdeny\t0\t0\t1.2.3.4' 2> "$GTM_CONFIG_DIR/err" && exit 10
grep -q 'no longer exists' "$GTM_CONFIG_DIR/err" || exit 11
# An IPv4 connection's allow list needs an IPv4 source.
gtm_guard_change 0 <<< $'none\naccess\tF000001\tallow\t0\t0\t2001:db8::/32' 2> "$GTM_CONFIG_DIR/err" && exit 12
grep -q 'address family' "$GTM_CONFIG_DIR/err" && [[ ! -e $GTM_CONFIG_DIR/firewall.tsv ]] || exit 13
gtm_guard_change 10 <<< $'none\nprotect\tprivate\t1' 2>/dev/null && exit 14
gtm_guard_change 0 <<< $'none\naccess\tF000001\tallow\t0\t0\t203.0.113.0/24\nprotect\tsmtp\t1' || exit 15
grep -qx $'access\tF000001\tallow\t0\t0\t203.0.113.0/24' "$GTM_CONFIG_DIR/firewall.tsv" && grep -qx $'protect\tsmtp\t1' "$GTM_CONFIG_DIR/firewall.tsv" || exit 16
grep -q '^nft -f ' "$GTM_CONFIG_DIR/calls" || exit 17
# Clearing every setting removes the owned table.
gtm_guard_change 0 <<< "$(gtm_guard_revision)" || exit 18
grep -qx 'nft delete table inet gtm_guard' "$GTM_CONFIG_DIR/calls" || exit 19
exit 0
''', [record(bind='0.0.0.0', port='2000')])
        self.assertEqual(result.returncode, 0, result.stdout+result.stderr)

    def test_render_scopes_rules_to_the_connection_and_its_family(self):
        result = self.run_in(r'''
gtm_load_records || exit 9
GTM_GUARD_PRIVATE=1 GTM_GUARD_SMTP=0 GTM_GUARD_EXCEPT=(10.99.0.0/16)
declare -gA GTM_GUARD_ACCESS=([F000001]='allow|50|20|203.0.113.0/24,2001:db8::/32' [F000002]='deny|0|0|2001:db8:1::/48') GTM_GUARD_UFW=()
out=$(gtm_guard_render) || exit 10
grep -q 'a_F000001 { type ipv4_addr; flags interval; auto-merge; elements = { 203.0.113.0/24 }; }' <<< "$out" || exit 11
grep -q 'meta nfproto ipv4 fib daddr type local meta l4proto tcp th dport 2000-2002 ip saddr != @a_F000001 counter drop comment "gtm-F000001-allow"' <<< "$out" || exit 12
grep -q 'meta l4proto udp th dport 2000-2002 ct state new add @c_F000001 { ip saddr ct count over 50 }' <<< "$out" || exit 13
grep -q 'add @r_F000001 { ip saddr limit rate over 20/second burst 20 packets }' <<< "$out" || exit 14
grep -q 'ip6 daddr 2001:db8::1 iifname "eth1" meta l4proto tcp th dport 443 ip6 saddr @a_F000002 counter drop' <<< "$out" || exit 15
# Exceptions: configured ones plus private gateways, resolvers and destinations.
grep -q 'except4 { type ipv4_addr; flags interval; auto-merge; elements = { 10.99.0.0/16, 10.202.10.10 }; }' <<< "$out" || exit 16
grep -q 'egress_out oifname { "eth0" } ct state new ip daddr @private4 ip daddr != @except4 counter drop' <<< "$out" || exit 17
grep -q 'gtm-smtp' <<< "$out" && exit 18
# A disabled connection keeps its settings but loses its rules.
GTM_RECORDS[0]=${GTM_RECORDS[0]/$'\tsingle\t1\t'/$'\tsingle\t0\t'}
gtm_guard_render | grep -q F000001 && exit 19
exit 0
''', [record(bind='0.0.0.0', port='2000-2002', protocol='both', targets='203.0.113.5:3000-3002@1'),
      record(id='F000002', bind='2001:db8::1', port='443', interface='eth1', targets='[2001:db8::20]:443@1')])
        self.assertEqual(result.returncode, 0, result.stdout+result.stderr)

    def test_revert_is_armed_confirmed_and_restores_the_confirmed_settings(self):
        result = self.run_in(r'''
gtm_guard_change 0 <<< $'none\nprotect\tsmtp\t1' || exit 9
confirmed=$(cat "$GTM_CONFIG_DIR/firewall.tsv")
gtm_guard_change 60 <<< "$(gtm_guard_revision)"$'\nprotect\tprivate\t1' || exit 10
grep -q 'systemd-run --quiet --unit gre-manager-firewall-revert --on-active=60s' "$GTM_CONFIG_DIR/calls" || exit 11
[[ -f $GTM_CONFIG_DIR/firewall.tsv.revert && -f $GTM_CONFIG_DIR/firewall.revert-at ]] || exit 12
gtm_guard_status | grep -q $'^pending\t[0-9]' || exit 13
# A second unconfirmed change keeps the first snapshot.
gtm_guard_change 60 <<< "$(gtm_guard_revision)"$'\nprotect\tprivate\t1\nexcept\t10.9.0.0/16' || exit 14
[[ $(cat "$GTM_CONFIG_DIR/firewall.tsv.revert") == "$confirmed" ]] || exit 15
gtm_api firewall-revert || exit 16
[[ $(cat "$GTM_CONFIG_DIR/firewall.tsv") == "$confirmed" && ! -e $GTM_CONFIG_DIR/firewall.tsv.revert ]] || exit 17
grep -q 'systemctl stop gre-manager-firewall-revert.timer' "$GTM_CONFIG_DIR/calls" || exit 18
gtm_guard_change 60 <<< "$(gtm_guard_revision)"$'\nprotect\tprivate\t1' && gtm_api firewall-confirm || exit 19
[[ ! -e $GTM_CONFIG_DIR/firewall.tsv.revert ]] && grep -qx $'protect\tprivate\t1' "$GTM_CONFIG_DIR/firewall.tsv" || exit 20
gtm_guard_status | grep -q '^pending' && exit 21
# The boot runner exposes the revert for the timer.
gtm_install_runner() { :; }
declare -f gtm_guard_restore_prev >/dev/null || exit 22
exit 0
''', [record(bind='0.0.0.0', port='2000')])
        self.assertEqual(result.returncode, 0, result.stdout+result.stderr)

    def test_ufw_openings_are_tagged_skipped_when_open_and_closed_with_the_connection(self):
        result = self.run_in(r'''
# The operator already opened 8443/tcp; that rule must never be removed.
printf '8443/tcp                   ALLOW       Anywhere\n' > "$GTM_CONFIG_DIR/ufw-rules"
gtm_guard_change 0 <<< $'none\nufw\tF000001\nufw\tF000002' || exit 9
grep -q '^2000:2002/tcp .*# gtm-F000001$' "$GTM_CONFIG_DIR/ufw-rules" && grep -q '^2000:2002/udp .*# gtm-F000001$' "$GTM_CONFIG_DIR/ufw-rules" || exit 10
[[ $(grep -c '^8443/tcp' "$GTM_CONFIG_DIR/ufw-rules") == 1 ]] && ! grep -q 'gtm-F000002' "$GTM_CONFIG_DIR/ufw-rules" || exit 11
gtm_guard_status > "$GTM_CONFIG_DIR/status" || exit 12
grep -qx $'port\tF000001\ttcp\t2000:2002\ttagged' "$GTM_CONFIG_DIR/status" && grep -qx $'port\tF000002\ttcp\t8443\topen' "$GTM_CONFIG_DIR/status" || exit 13
# Deleting the connection closes its tagged ports at the next apply.
GTM_RECORDS=("${GTM_RECORDS[1]}"); gtm_write_records "$GTM_STATE"
gtm_guard_apply || exit 14
! grep -q 'gtm-F000001' "$GTM_CONFIG_DIR/ufw-rules" && grep -q '^8443/tcp' "$GTM_CONFIG_DIR/ufw-rules" || exit 15
[[ ! -s $GTM_CONFIG_DIR/ufw-opened.tsv ]] || exit 16
exit 0
''', [record(bind='0.0.0.0', port='2000-2002', protocol='both', targets='203.0.113.5:3000-3002@1'),
      record(id='F000002', engine='nftables', bind='0.0.0.0', port='8443', targets='203.0.113.6:443@1')])
        self.assertEqual(result.returncode, 0, result.stdout+result.stderr)

    def test_ufw_coverage_reads_ranges_lists_and_sources(self):
        result = self.run_in(r'''
status='Status: active

To                         Action      From
--                         ------      ----
22/tcp                     ALLOW       Anywhere
8000:8100/tcp              ALLOW       Anywhere
443                        ALLOW IN    Anywhere
53,853/udp                 ALLOW       Anywhere
9000/tcp                   ALLOW       203.0.113.0/24
9443/tcp                   DENY        Anywhere
22/tcp (v6)                ALLOW       Anywhere (v6)'
gtm_ufw_covers tcp 8050:8060 <<< "$status" && gtm_ufw_covers udp 443 <<< "$status" && gtm_ufw_covers udp 853 <<< "$status" || exit 9
gtm_ufw_covers tcp 8050:8200 <<< "$status" && exit 10
gtm_ufw_covers tcp 9000 <<< "$status" && exit 11
gtm_ufw_covers tcp 9443 <<< "$status" && exit 12
gtm_ufw_covers udp 22 <<< "$status" && exit 13
exit 0
''')
        self.assertEqual(result.returncode, 0, result.stdout+result.stderr)


if __name__ == '__main__':
    unittest.main()
