"""v1.5.0 engine: kernel port ranges, domain destinations, server DNS and portfw coexistence."""
from pathlib import Path
import tempfile
import unittest

from test_manager import ROOT, bash, record, load_state
from test_advanced import paths

(ROOT / '.work').mkdir(exist_ok=True)

# Resolver stub: a.example has two IPv4 addresses, v6.example one IPv6 address.
LOOKUP = r'''
lookup() {
    [[ -f $GTM_CONFIG_DIR/dns-down ]] && return 2
    case $1/$2 in
        a.example/4) cat "$GTM_CONFIG_DIR/answer" 2>/dev/null || printf '203.0.113.11 STREAM a.example\n203.0.113.10 STREAM\n203.0.113.10 DGRAM\n127.0.0.1 STREAM\n';;
        v6.example/6) printf '2001:db8::7 STREAM v6.example\n';;
        *) return 2;;
    esac
}
GTM_DNS_LOOKUP=lookup
'''


class RangeTests(unittest.TestCase):
    def test_range_records_validate_by_engine_and_mapping(self):
        ok = [
            record(port='2000-2999', targets='203.0.113.20:2000-2999@1'),
            record(port='2000-2999', targets='203.0.113.20:3000-3999@1'),
            record(port='2000-2999', targets='203.0.113.20:443@1'),
            record(engine='iptables', port='2000-2999', targets='203.0.113.20:2000-2999@1'),
            record(engine='iptables', port='2000-2999', targets='203.0.113.20:443@1'),
            record(port='1-4096', targets='203.0.113.20:1-4096@1'),
        ]
        bad = [
            record(engine='realm', port='2000-2001', targets='203.0.113.20:2000-2001@1'),
            record(engine='haproxy', port='2000-2001', targets='203.0.113.20:443@1'),
            record(engine='iptables', port='2000-2999', targets='203.0.113.20:3000-3999@1'),
            record(port='2000-2999', targets='203.0.113.20:3000-3500@1'),
            record(port='443', targets='203.0.113.20:443-444@1'),
            record(port='2000-1999'), record(port='1-4097', targets='203.0.113.20:1-4097@1'),
            record(port='2000-2001', bind='192.0.2.10', targets='192.0.2.10:2001-2002@1'),
        ]
        for line in ok:
            self.assertEqual(bash(f'gtm_record_validate {sh(line)}').returncode, 0, line)
        for line in bad:
            self.assertNotEqual(bash(f'gtm_record_validate {sh(line)}').returncode, 0, line)

    def test_range_listeners_conflict_with_ports_inside_them(self):
        base = record(port='2000-2999', targets='203.0.113.20:2000-2999@1')
        self.assertNotEqual(load_state(base+'\n'+record(id='F000002', port='2500')+'\n').returncode, 0)
        self.assertNotEqual(load_state(record(id='F000002', port='2999')+'\n'+base+'\n').returncode, 0)
        self.assertNotEqual(load_state(base+'\n'+record(id='F000002', port='2990-3010', targets='203.0.113.21:443@1')+'\n').returncode, 0)
        self.assertEqual(load_state(base+'\n'+record(id='F000002', port='3000-3010', targets='203.0.113.21:443@1')+'\n'+record(id='F000003', port='1999')+'\n').returncode, 0)
        # UDP beside TCP and disabled records do not conflict.
        self.assertEqual(load_state(base+'\n'+record(id='F000002', protocol='udp', port='2500')+'\n'+record(id='F000003', port='2500', enabled='0')+'\n').returncode, 0)

    def test_range_rules_render_maps_same_port_and_fixed_port(self):
        rows = [record(port='2000-2002', targets='203.0.113.5:3000-3002@1'),
                record(id='F000002', port='4000-4999', targets='203.0.113.5:4000-4999@1'),
                record(id='F000003', port='5000-5010', protocol='udp', targets='203.0.113.5:443@1'),
                record(id='F000004', engine='iptables', port='6000-6999', targets='203.0.113.6:6000-6999@1')]
        result = bash('GTM_RECORDS=("$@"); gtm_return_marks() { :; }; gtm_return_family_marks() { :; }\n'
                      'gtm_nft_render; printf -- "--\\n"; gtm_iptables_render 4 nat; gtm_iptables_render 4 filter'.replace('"$@"', ' '.join(sh(r) for r in rows)))
        self.assertEqual(result.returncode, 0, result.stderr)
        out = result.stdout
        self.assertIn('tcp dport 2000-2002 counter dnat ip to tcp dport map { 2000 : 203.0.113.5 . 3000, 2001 : 203.0.113.5 . 3001, 2002 : 203.0.113.5 . 3002 }', out)
        self.assertIn('tcp dport 4000-4999 counter dnat ip to 203.0.113.5 comment', out)
        self.assertIn('udp dport 5000-5010 counter dnat ip to 203.0.113.5:443', out)
        self.assertIn('ct original proto-dst 2000-2002', out)
        self.assertIn('--dport 6000:6999 -m comment --comment gtm-F000004 -j DNAT --to-destination 203.0.113.6\n', out)
        self.assertIn('--ctorigdstport 6000:6999', out)


def sh(value):
    return "$'" + value.replace('\\', '\\\\').replace("'", "\\'").replace('\t', '\\t') + "'"


class DomainTests(unittest.TestCase):
    def run_in(self, code, rows=()):
        with tempfile.TemporaryDirectory(dir=ROOT/'.work') as directory:
            folder = Path(directory)
            if rows:
                (folder/'connections.tsv').write_text('\n'.join(rows)+'\n', newline='\n')
            return bash(paths(folder)+LOOKUP+code)

    def test_domain_targets_validate_and_reject_lookalikes(self):
        for target in ('a.example:443@1', 'api-1.svc.example.org:8443@2', 'a.example:2000-2999@1'):
            port = '2000-2999' if '-2999' in target else '443'
            self.assertEqual(bash(f'gtm_record_validate {sh(record(targets=target, port=port))}').returncode, 0, target)
        for target in ('A.example:443@1', '1.2.3:443@1', 'localhost:443@1', 'a..example:443@1', '-a.example:443@1', 'a.example.123:443@1', 'a_b.example:443@1'):
            self.assertNotEqual(bash(f'gtm_record_validate {sh(record(targets=target))}').returncode, 0, target)
        # HAProxy routing records name destinations by position.
        self.assertEqual(bash('gtm_hostname a.example && ! gtm_hostname 10.0.0.1 && ! gtm_hostname example').returncode, 0)

    def test_names_resolve_to_cached_addresses_and_expand_destinations(self):
        result = self.run_in(r'''
[[ $(gtm_dns_lookup a.example 4 | paste -sd, -) == 203.0.113.10,203.0.113.11 ]] || exit 9
gtm_dns_lookup nope.example 4 && exit 10
gtm_load_records || exit 11
gtm_dns_ensure || exit 12
grep -q $'^a.example\t4\t[0-9]*\t203.0.113.10,203.0.113.11$' "$GTM_CONFIG_DIR/dns-cache.tsv" || exit 13
gtm_record_validate "${GTM_RECORDS[0]}" && gtm_resolve_targets || exit 14
[[ $R_TARGETS == 203.0.113.10:443@2,203.0.113.11:443@2,198.51.100.9:443@1 && $R_STRATEGY == random ]] || exit 15
gtm_dns_policy_set a.example 10 first || exit 16
GTM_DNS_LOADED=''; gtm_record_validate "${GTM_RECORDS[0]}" && gtm_resolve_targets || exit 17
[[ $R_TARGETS == 203.0.113.10:443@2,198.51.100.9:443@1 ]] || exit 18
gtm_record_validate "${GTM_RECORDS[1]}" && gtm_resolve_targets || exit 19
[[ $R_TARGETS == '[2001:db8::7]:8443@1' && $R_STRATEGY == single ]] || exit 20
GTM_RECORDS+=($'F000003\tx\tnftables\ttcp\t0.0.0.0\t9000\tsingle\t1\tmasquerade\tany\tmissing.example:443@1\t1')
gtm_dns_ensure 2> "$GTM_CONFIG_DIR/err" && exit 21
grep -q 'Cannot resolve missing.example' "$GTM_CONFIG_DIR/err" || exit 22
exit 0
''', [record(strategy='random', targets='a.example:443@2,198.51.100.9:443@1'),
      record(id='F000002', bind='::', port='8443', targets='v6.example:8443@1')])
        self.assertEqual(result.returncode, 0, result.stdout+result.stderr)

    def test_refresh_keeps_last_answer_and_reapplies_only_on_change(self):
        result = self.run_in(r'''
gtm_prepare() { :; }; gtm_lock() { :; }; gtm_unlock() { :; }
gtm_kernel_apply() { printf 'kernel\n' >> "$GTM_CONFIG_DIR/applied"; }; gtm_relays_apply() { :; }
gtm_dns_refresh --force | grep -q $'^a.example\t4\tchanged\t203.0.113.10,203.0.113.11$' || exit 9
[[ $(wc -l < "$GTM_CONFIG_DIR/applied") == 1 ]] || exit 10
gtm_dns_refresh | grep -q $'\tcached\t' || exit 11
gtm_dns_refresh --force | grep -q $'\tsame\t' || exit 12
[[ $(wc -l < "$GTM_CONFIG_DIR/applied") == 1 ]] || exit 13
touch "$GTM_CONFIG_DIR/dns-down"
gtm_dns_refresh --force | grep -q $'^a.example\t4\tfailed\t203.0.113.10,203.0.113.11$' || exit 14
rm "$GTM_CONFIG_DIR/dns-down"; printf '203.0.113.12 STREAM\n' > "$GTM_CONFIG_DIR/answer"
gtm_dns_refresh --force | grep -q $'\tchanged\t203.0.113.12$' || exit 15
[[ $(wc -l < "$GTM_CONFIG_DIR/applied") == 2 ]] || exit 16
gtm_dns_view | grep -qx $'record\tF000001\t203.0.113.12:443@1' || exit 17
exit 0
''', [record(targets='a.example:443@1')])
        self.assertEqual(result.returncode, 0, result.stdout+result.stderr)

    def test_timer_follows_domain_records(self):
        result = self.run_in(r'''
systemctl() { printf '%s\n' "$*" >> "$GTM_CONFIG_DIR/calls"; }
gtm_load_records && gtm_dns_timer_sync || exit 9
grep -q -- '--dns-refresh' "$GTM_CONFIG_DIR/gre-manager-dns.service" && grep -qx 'enable --now gre-manager-dns.timer' "$GTM_CONFIG_DIR/calls" || exit 10
GTM_RECORDS=(); gtm_dns_timer_sync || exit 11
[[ ! -e $GTM_CONFIG_DIR/gre-manager-dns.timer ]] && grep -qx 'disable --now gre-manager-dns.timer' "$GTM_CONFIG_DIR/calls" || exit 12
gtm_dns_timer_sync || exit 13
exit 0
''', [record(targets='a.example:443@1')])
        self.assertEqual(result.returncode, 0, result.stdout+result.stderr)


class ServerDNSTests(unittest.TestCase):
    def run_in(self, code):
        with tempfile.TemporaryDirectory(dir=ROOT/'.work') as directory:
            folder = Path(directory)
            return bash(paths(folder)+r'''
GTM_RESOLV=$GTM_CONFIG_DIR/resolv.conf GTM_RESOLVED_DIR=$GTM_CONFIG_DIR/resolved.conf.d GTM_RESOLVED_UPSTREAM=$GTM_CONFIG_DIR/upstream
GTM_RUNTIME=$GTM_CONFIG_DIR/lib/apply.sh
gtm_root() { :; }; gtm_prepare() { :; }; gtm_lock() { :; }; gtm_unlock() { :; }
systemctl() { printf '%s\n' "$*" >> "$GTM_CONFIG_DIR/calls"; [[ $* != 'is-active --quiet systemd-resolved' ]] || [[ -f $GTM_CONFIG_DIR/resolved-on ]]; }
'''+code)

    def test_plain_file_is_rewritten_kept_at_boot_and_restored(self):
        result = self.run_in(r'''
printf 'nameserver 10.0.0.2\nsearch corp.example\noptions edns0\n' > "$GTM_RESOLV"
cp "$GTM_RESOLV" "$GTM_CONFIG_DIR/before"
gtm_api dns-status | grep -qx $'mode\tfile' || exit 9
gtm_api dns-apply 127.0.0.1 && exit 10
gtm_api dns-apply 1.1.1.1 1.1.1.1 8.8.8.8 2606:4700:4700::1111 || exit 11
grep -qx 'nameserver 1.1.1.1' "$GTM_RESOLV" && grep -qx 'nameserver 2606:4700:4700::1111' "$GTM_RESOLV" && grep -qx 'search corp.example' "$GTM_RESOLV" || exit 12
[[ $(grep -c nameserver "$GTM_RESOLV") == 3 ]] || exit 13
grep -q 'nameserver 8.8.8.8' "$GTM_CONFIG_DIR/lib/resolv.sh" && grep -qx 'enable gre-manager-resolv.service' "$GTM_CONFIG_DIR/calls" || exit 14
gtm_api dns-status | grep -qx $'original\t10.0.0.2' || exit 15
# A second apply keeps the first original.
gtm_api dns-apply 9.9.9.9 && gtm_api dns-status | grep -qx $'original\t10.0.0.2' || exit 16
gtm_api dns-restore || exit 17
cmp -s "$GTM_RESOLV" "$GTM_CONFIG_DIR/before" && [[ ! -e $GTM_CONFIG_DIR/gre-manager-resolv.service ]] || exit 18
gtm_api dns-status | grep -qx $'managed\t0' || exit 19
exit 0
''')
        self.assertEqual(result.returncode, 0, result.stdout+result.stderr)

    def test_resolved_uses_a_drop_in_and_other_managers_are_left_alone(self):
        result = self.run_in(r'''
mkdir -p "$GTM_CONFIG_DIR/run/systemd/resolve"; touch "$GTM_CONFIG_DIR/run/systemd/resolve/stub-resolv.conf" "$GTM_CONFIG_DIR/resolved-on"
ln -s "$GTM_CONFIG_DIR/run/systemd/resolve/stub-resolv.conf" "$GTM_RESOLV"
printf 'nameserver 10.0.0.53\n' > "$GTM_RESOLVED_UPSTREAM"
gtm_api dns-status | grep -qx $'mode\tresolved' || exit 9
gtm_api dns-apply 1.1.1.1 1.0.0.1 || exit 10
grep -qx 'DNS=1.1.1.1 1.0.0.1' "$GTM_RESOLVED_DIR/90-gre-manager.conf" && grep -qx 'Domains=~.' "$GTM_RESOLVED_DIR/90-gre-manager.conf" || exit 11
grep -qx 'restart systemd-resolved' "$GTM_CONFIG_DIR/calls" || exit 12
gtm_api dns-restore && [[ ! -e $GTM_RESOLVED_DIR/90-gre-manager.conf && -L $GTM_RESOLV ]] || exit 13
rm "$GTM_RESOLV"; mkdir -p "$GTM_CONFIG_DIR/run/resolvconf"; touch "$GTM_CONFIG_DIR/run/resolvconf/resolv.conf"
ln -s "$GTM_CONFIG_DIR/run/resolvconf/resolv.conf" "$GTM_RESOLV"
gtm_api dns-apply 1.1.1.1 2> "$GTM_CONFIG_DIR/err" && exit 14
grep -q 'managed by resolvconf' "$GTM_CONFIG_DIR/err" || exit 15
exit 0
''')
        self.assertEqual(result.returncode, 0, result.stdout+result.stderr)


class TerminalTests(unittest.TestCase):
    def rows(self, engine, stdin):
        result = bash('gtm_form_save() { printf \'\\nROW:%s\\n\' "${GTM_FORM_ROWS[@]}"; }\ngtm_dns_lookup() { printf \'203.0.113.40\\n\'; }\n'
                      f'gtm_new_forward {engine}', stdin)
        self.assertEqual(result.returncode, 0, result.stdout[-1500:]+result.stderr)
        return [line[4:].split('\t') for line in result.stdout.splitlines() if line.startswith('ROW:')]

    def test_kernel_ranges_stay_one_record_with_mapped_ports(self):
        rows = self.rows('nftables', '2000-2999,8443\n203.0.113.5\n3000\n1\n3\n3000-3999,443\n1\n')
        self.assertEqual([(r[5], r[10]) for r in rows], [('2000-2999', '203.0.113.5:3000-3999@1'), ('8443', '203.0.113.5:443@1')])
        rows = self.rows('iptables', '4000-4999\n203.0.113.6\n4000\n1\n2\n1\n')
        self.assertEqual([(r[5], r[10]) for r in rows], [('4000-4999', '203.0.113.6:4000-4999@1')])

    def test_domain_destination_is_checked_and_saved_as_a_name(self):
        rows = self.rows('haproxy', '443\nBackend.Example.com\n8443\n1\n')
        self.assertEqual(rows[0][10], 'backend.example.com:8443@1')

    def test_dns_presets_match_the_panel(self):
        import json
        presets = json.loads((ROOT/'panel/internal/model/dns_presets.json').read_text(encoding='utf-8'))
        result = bash('printf "%s\\n" "${GTM_SYSDNS_PRESETS[@]}"')
        self.assertEqual(result.stdout.split('\n')[:-1], [p['name']+'|'+' '.join(p['servers']) for p in presets])
        self.assertEqual(bash(' && '.join(f'gtm_sysdns_server {s}' for p in presets for s in p['servers']+p['ipv6'])).returncode, 0)


class PortfwTests(unittest.TestCase):
    def test_rules_are_read_and_active_ports_are_reserved(self):
        with tempfile.TemporaryDirectory(dir=ROOT/'.work') as directory:
            folder = Path(directory)
            (folder/'portfw').mkdir()
            (folder/'portfw'/'rules.db').write_text('1|2001-2003,2010|203.0.113.50|3001-3003,8080|both\n2|443|backend.example|443|tcp\n3|bad;rm|x|1|tcp\n', newline='\n')
            result = bash(paths(folder)+r'''
GTM_PORTFW_DIR=$GTM_CONFIG_DIR/portfw FW_SCRIPT=$GTM_CONFIG_DIR/none
gtm_api portfw-rules > "$GTM_CONFIG_DIR/out" || exit 9
[[ $(wc -l < "$GTM_CONFIG_DIR/out") == 2 ]] && grep -qx $'2\t443\tbackend.example\t443\ttcp' "$GTM_CONFIG_DIR/out" || exit 10
gtm_portfw_active() { return 1; }
gtm_legacy_listener_check udp 0.0.0.0 2002 || exit 11
gtm_portfw_active() { return 0; }
gtm_legacy_listener_check udp 0.0.0.0 2002 2> "$GTM_CONFIG_DIR/err" && exit 12
grep -q 'portfw) rule 1 already forwards 2001-2003' "$GTM_CONFIG_DIR/err" || exit 13
gtm_legacy_listener_check tcp 0.0.0.0 2005-2009 || exit 14
gtm_legacy_listener_check tcp 0.0.0.0 400-500 && exit 15
gtm_legacy_listener_check tcp :: 443 || exit 16
exit 0
''')
            self.assertEqual(result.returncode, 0, result.stdout+result.stderr)


if __name__ == '__main__':
    unittest.main()
