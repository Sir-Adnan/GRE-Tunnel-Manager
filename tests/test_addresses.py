"""Address tools: uses, IP-change replace, paired readdress and additional addresses.

Everything runs against a temporary directory with fake systemctl/ip calls.
"""
import shlex
import tempfile
import unittest
from pathlib import Path

from test_manager import ROOT, bash, record


class AddressTests(unittest.TestCase):
    def setUp(self):
        (ROOT / '.work').mkdir(exist_ok=True)
        self.tmp = tempfile.TemporaryDirectory(dir=ROOT / '.work')
        self.addCleanup(self.tmp.cleanup)
        self.path = Path(self.tmp.name)

    def run_engine(self, code, records=(), locals_='192.0.2.7 203.0.113.25'):
        recs = ' '.join(shlex.quote(r) for r in records)
        prefix = (
            'GTM_SERVICE_DIR=' + shlex.quote(self.path.as_posix()) + '; GTM_CONFIG_DIR=$GTM_SERVICE_DIR; GTM_RUN_DIR=$GTM_SERVICE_DIR\n'
            'gtm_prepare() { :; }; gtm_lock() { :; }; gtm_unlock() { :; }; gtm_need() { :; }\n'
            'RECS=(' + recs + ')\n'
            'gtm_load_records() { GTM_RECORDS=("${RECS[@]}"); }\n'
            'gtm_commit() { printf "%s\\n" "${GTM_RECORDS[@]}" > "$GTM_CONFIG_DIR/committed"; }\n'
            'gtm_listener_check() { :; }; gtm_legacy_listener_check() { :; }; gtm_kernel_apply() { :; }\n'
            'LOCALS=' + shlex.quote(locals_) + '\n'
            'gtm_local_address() { [[ " $LOCALS " == *" $1 "* ]]; }\n'
            'systemctl() { printf "%s\\n" "$*" >> "$GTM_SERVICE_DIR/systemctl.log"; [[ $1 != is-active ]]; }\n'
            'sleep() { :; }\n'
        )
        return bash(prefix + code)

    def gre(self, tid=3, role='iran', remote='198.51.100.2', bind='192.0.2.7'):
        result = bash(f'gtm_link_render {tid} {role} {remote} {bind} 1430')
        self.assertEqual(result.returncode, 0, result.stderr)
        (self.path / f'gre-tun-{tid}.service').write_text(result.stdout, newline='\n')

    def test_uses_cover_gre_connections_and_reverse(self):
        self.gre()
        (self.path / 'gtm-frp-destination-web.toml').write_text('serverAddr = "198.51.100.2"\nserverPort = 7000\n', newline='\n')
        rows = [
            record(bind='192.0.2.7', targets='198.51.100.2:443@1,198.51.100.2:8443@2,203.0.113.9:443@1', strategy='random'),
            record(id='F000002', bind='0.0.0.0', port='80', targets='203.0.113.9:80@1'),
        ]
        result = self.run_engine('gtm_address_uses', rows, locals_='203.0.113.25')
        self.assertEqual(result.returncode, 0, result.stderr)
        lines = result.stdout.splitlines()
        self.assertIn('local\t192.0.2.7\tgre\tgre-tun-3\t0\t1', lines)
        self.assertIn('remote\t198.51.100.2\tgre\tgre-tun-3\t-\t1', lines)
        self.assertIn('local\t192.0.2.7\tconnection\tF000001\t0\t1', lines)
        # One row per address per connection, IP literals only.
        self.assertEqual(lines.count('remote\t198.51.100.2\tconnection\tF000001\t-\t1'), 1)
        self.assertIn('remote\t203.0.113.9\tconnection\tF000001\t-\t1', lines)
        self.assertIn('remote\t198.51.100.2\treverse\tgtm-frp-destination-web\t-\t1', lines)

    def test_local_replace_rewrites_unit_and_bind(self):
        self.gre()
        before = (self.path / 'gre-tun-3.service').read_text()
        result = self.run_engine('gtm_address_api address-replace 192.0.2.7 203.0.113.25 local all',
                                 [record(bind='192.0.2.7', targets='198.51.100.2:443@1')])
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('result\tF000001\tdone', result.stdout)
        self.assertIn('result\tgre-tun-3\tdone', result.stdout)
        after = (self.path / 'gre-tun-3.service').read_text()
        self.assertIn('remote 198.51.100.2 local 203.0.113.25 ttl 255 key 3', after)
        # Only the tunnel line changes; everything else is preserved byte for byte.
        self.assertEqual([l for l in before.splitlines() if 'tunnel add' not in l],
                         [l for l in after.splitlines() if 'tunnel add' not in l])
        committed = (self.path / 'committed').read_text().split('\t')
        self.assertEqual(committed[4], '203.0.113.25')

    def test_remote_replace_keeps_ports_weights_and_others(self):
        result = self.run_engine('gtm_address_api address-replace 198.51.100.2 198.51.100.77 remote F000001',
                                 [record(targets='198.51.100.2:443@1,198.51.100.2:8443@2,203.0.113.9:443@1', strategy='random')])
        self.assertEqual(result.returncode, 0, result.stderr)
        committed = (self.path / 'committed').read_text().rstrip('\n').split('\t')
        self.assertEqual(committed[10], '198.51.100.77:443@1,198.51.100.77:8443@2,203.0.113.9:443@1')

    def test_refusals_change_nothing(self):
        self.gre()
        unit = (self.path / 'gre-tun-3.service').read_text()
        cases = [
            'gtm_address_api address-replace 192.0.2.7 198.51.100.200 local all',  # new not on server
            'gtm_address_api address-replace 192.0.2.7 2001:db8::1 local all',      # family mismatch
            'gtm_address_api address-replace 192.0.2.7 192.0.2.7 local all',        # same address
            'gtm_address_api address-replace 192.0.2.7 203.0.113.25 local gre-tun-9',  # item does not use it
            'gtm_address_api address-replace 192.0.2.7 203.0.113.25 local ../x',    # malformed item
        ]
        for code in cases:
            result = self.run_engine(code)
            self.assertNotEqual(result.returncode, 0, code)
            self.assertEqual((self.path / 'gre-tun-3.service').read_text(), unit, code)

    def test_failed_restart_restores_the_unit(self):
        self.gre()
        unit = (self.path / 'gre-tun-3.service').read_text()
        result = self.run_engine('systemctl() { case $1 in is-active) return 0;; restart) [[ -f "$GTM_SERVICE_DIR/restarted" ]] && return 0; : > "$GTM_SERVICE_DIR/restarted"; return 1;; esac; }\n'
                                 'gtm_address_api address-replace 198.51.100.2 198.51.100.9 remote gre-tun-3')
        self.assertEqual(result.returncode, 1)
        self.assertIn('result\tgre-tun-3\tfailed', result.stdout)
        self.assertEqual((self.path / 'gre-tun-3.service').read_text().rstrip('\n'), unit.rstrip('\n'))

    def test_reverse_rathole_ipv6_and_frp(self):
        (self.path / 'gtm-rathole-destination-db.toml').write_text('[client]\nremote_addr = "[2001:db8::1]:2333"\n', newline='\n')
        result = self.run_engine('gtm_address_api address-replace 2001:db8::1 2001:db8::9 remote gtm-rathole-destination-db')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('remote_addr = "[2001:db8::9]:2333"', (self.path / 'gtm-rathole-destination-db.toml').read_text())
        (self.path / 'gtm-frp-entrance-web.toml').write_text('bindAddr = "192.0.2.7"\nbindPort = 7000\nproxyBindAddr = "192.0.2.7"\n', newline='\n')
        (self.path / 'frps').write_text('#!/bin/sh\nexit 0\n', newline='\n')
        (self.path / 'frps').chmod(0o755)
        result = self.run_engine('PATH=$GTM_SERVICE_DIR:$PATH\ngtm_address_api address-replace 192.0.2.7 203.0.113.25 local gtm-frp-entrance-web')
        self.assertEqual(result.returncode, 0, result.stderr)
        text = (self.path / 'gtm-frp-entrance-web.toml').read_text()
        self.assertIn('bindAddr = "203.0.113.25"', text)
        self.assertIn('proxyBindAddr = "203.0.113.25"', text)
        # A WSS entrance keeps a gateway bound to the address: listed, not editable.
        (self.path / 'gtm-gateway-web.conf').write_text('bind 192.0.2.7:443\n')
        (self.path / 'gtm-frp-entrance-web.toml').write_text('proxyBindAddr = "192.0.2.7"\n', newline='\n')
        result = self.run_engine('gtm_address_uses')
        self.assertIn('local\t192.0.2.7\treverse\tgtm-frp-entrance-web\t1\t0', result.stdout)
        result = self.run_engine('gtm_address_api address-replace 192.0.2.7 203.0.113.25 local gtm-frp-entrance-web')
        self.assertNotEqual(result.returncode, 0)

    def test_paired_readdress_revision_and_rollback(self):
        self.gre(remote='198.51.100.2')
        result = self.run_engine('rev=$(gtm_address_api readdress-check 198.51.100.2 198.51.100.9 remote) || exit 20\n'
                                 'gtm_address_api readdress-apply 0000000000000000000000000000000000000000000000000000000000000000 198.51.100.2 198.51.100.9 remote; [[ $? == 75 ]] || exit 21\n'
                                 'fp=$(gtm_address_api readdress-apply "$rev" 198.51.100.2 198.51.100.9 remote) || exit 22\n'
                                 'grep -q "remote 198.51.100.9 local" "$GTM_SERVICE_DIR/gre-tun-3.service" || exit 23\n'
                                 'now=$(gtm_address_api readdress-check 198.51.100.9 198.51.100.2 remote) || exit 24\n'
                                 '[[ $now == "$fp" ]] || exit 25\n'
                                 'gtm_address_api readdress-apply "$fp" 198.51.100.9 198.51.100.2 remote >/dev/null || exit 26\n'
                                 'grep -q "remote 198.51.100.2 local" "$GTM_SERVICE_DIR/gre-tun-3.service" || exit 27\n'
                                 'gtm_address_api readdress-check 203.0.113.1 203.0.113.2 remote && exit 28; true')
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_extra_address_unit_list_and_delete_guard(self):
        result = self.run_engine('ip() { case "$1 $2" in "link show") return 0;; "route get") echo ok;; esac; }\n'
                                 'gtm_address_api extra-add 203.0.113.40/32 eth0 203.0.113.1',
                                 locals_='192.0.2.7')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('extra\t1', result.stdout)
        unit = (self.path / 'gtm-addr-1.service').read_text()
        self.assertTrue(unit.startswith('# GTM managed address v1\n'))
        self.assertIn('ExecStart=/sbin/ip address replace 203.0.113.40/32 dev eth0', unit)
        self.assertIn('ExecStart=/sbin/ip rule add from 203.0.113.40 table 25201 priority 25201', unit)
        self.assertIn('ExecStart=/sbin/ip route replace default via 203.0.113.1 dev eth0 table 25201', unit)
        result = self.run_engine('gtm_extra_list', locals_='203.0.113.40')
        self.assertEqual(result.stdout, '1\t203.0.113.40/32\teth0\t203.0.113.1\t0\t1\n')
        # Still used by a connection: deletion is refused and the unit stays.
        result = self.run_engine('gtm_address_api extra-delete 1', [record(bind='203.0.113.40')], locals_='203.0.113.40')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('F000001 still uses 203.0.113.40', result.stderr)
        self.assertTrue((self.path / 'gtm-addr-1.service').exists())
        result = self.run_engine('gtm_address_api extra-delete 1', locals_='203.0.113.40')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse((self.path / 'gtm-addr-1.service').exists())

    def test_extra_add_refuses_bad_input_and_foreign_units(self):
        for args in ['203.0.113.40 eth0 -', '203.0.113.40/4 eth0 -', '203.0.113.40/32 eth0 2001:db8::1', '192.0.2.7/32 eth0 -', '203.0.113.40/32 "a;b" -']:
            result = self.run_engine('ip() { return 0; }\ngtm_address_api extra-add ' + args)
            self.assertNotEqual(result.returncode, 0, args)
        self.assertFalse((self.path / 'gtm-addr-1.service').exists())
        (self.path / 'gtm-addr-1.service').write_text('[Service]\nExecStart=/bin/sh -c "id"\n')
        result = self.run_engine('gtm_address_api extra-delete 1')
        self.assertNotEqual(result.returncode, 0)
        self.assertTrue((self.path / 'gtm-addr-1.service').exists())


if __name__ == '__main__':
    unittest.main()
