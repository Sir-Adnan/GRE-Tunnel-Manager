"""Numbered forms, batch creation and safe wildcard listener defaults."""
from pathlib import Path
import shlex
import tempfile
import unittest

from test_manager import ROOT, bash, record


class FormTests(unittest.TestCase):
    def test_port_lists_are_bounded_decimal_data(self):
        result = bash('''gtm_parse_ports '443,8443 8000-8002 443' || exit 1
[[ ${GTM_PORTS[*]} == '443 8443 8000 8001 8002' ]] || exit 2
for value in 0 65536 '443;id' '$(exit 99)' '1-99' 9000-8000 ,443 443, '443,,444' 999999999999999999999; do
    gtm_parse_ports "$value" && exit 3
done
true''')
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_numbered_choices_retry_and_cancel(self):
        result = bash("gtm_choose Protocol tcp TCP tcp UDP udp 'TCP + UDP' both; printf 'RESULT:%s' \"$GTM_REPLY\"", 'udp\n99\n3\n')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('RESULT:both', result.stdout)
        result = bash('gtm_choose Protocol tcp TCP tcp UDP udp', '0\n')
        self.assertNotEqual(result.returncode, 0)

    def test_haproxy_name_is_automatic_and_remote_port_is_separate(self):
        result = bash('''gtm_form_save() { printf '\nROW:%s\n' "${GTM_FORM_ROWS[@]}"; }
gtm_new_forward haproxy''', '443\n203.0.113.20\n8443\n1\n')
        self.assertEqual(result.returncode, 0, result.stderr)
        row = next(line[4:] for line in result.stdout.splitlines() if line.startswith('ROW:')).split('\t')
        self.assertEqual(row[1:6], ['haproxy-443', 'haproxy', 'tcp', '0.0.0.0', '443'])
        self.assertEqual(row[10], '203.0.113.20:8443@1')
        self.assertNotIn('Traffic [', result.stdout)
        self.assertNotIn('Name (optional)', result.stdout)

    def test_combined_ipv6_target_and_same_port_batch(self):
        result = bash('''gtm_form_save() { printf '\nROW:%s\n' "${GTM_FORM_ROWS[@]}"; }
gtm_new_forward haproxy''', '443,8443\n[2001:db8::20]:9443\n2\n1\n')
        self.assertEqual(result.returncode, 0, result.stderr)
        rows = [line[4:].split('\t') for line in result.stdout.splitlines() if line.startswith('ROW:')]
        self.assertEqual([row[1] for row in rows], ['haproxy-443', 'haproxy-8443'])
        self.assertEqual([row[10] for row in rows], ['[2001:db8::20]:443@1', '[2001:db8::20]:8443@1'])

    def test_cancel_is_read_only(self):
        result = bash('''gtm_prepare() { exit 80; }; gtm_install_component() { exit 81; }
ip() { exit 82; }; systemctl() { exit 83; }
gtm_new_forward haproxy''', '443\n203.0.113.20:8443\n0\n')
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_load_balancing_retries_duplicate_targets_and_uses_numeric_strategy(self):
        result = bash('''gtm_form_save() { printf '\nROW:%s\n' "${GTM_FORM_ROWS[@]}"; }
gtm_new_forward haproxy '' balance''', '443\n[2001:db8::20]:8443\n[2001:0db8:0:0:0:0:0:20]:8443\n203.0.113.21:8443\n1\n3\n1\n')
        self.assertEqual(result.returncode, 0, result.stderr)
        row = next(line[4:] for line in result.stdout.splitlines() if line.startswith('ROW:')).split('\t')
        self.assertEqual(row[6], 'source')
        self.assertEqual(row[10], '[2001:db8::20]:8443@1,203.0.113.21:8443@1')
        self.assertIn('already in the list', result.stderr)

    def test_realm_protocol_uses_a_number(self):
        result = bash('''gtm_form_save() { printf '\nROW:%s\n' "${GTM_FORM_ROWS[@]}"; }
gtm_new_forward realm''', '51820\n203.0.113.20\n51820\n2\n1\n')
        self.assertEqual(result.returncode, 0, result.stderr)
        row = next(line[4:] for line in result.stdout.splitlines() if line.startswith('ROW:')).split('\t')
        self.assertEqual(row[3], 'udp')

    def test_kernel_suggests_primary_local_ip_without_public_ip_probes(self):
        result = bash('''ip() { printf '1.1.1.1 via 192.0.2.1 dev eth0 src 192.0.2.10\n'; }
curl() { exit 90; }; ping() { exit 91; }
gtm_form_save() { printf '\nROW:%s\n' "${GTM_FORM_ROWS[@]}"; }
gtm_new_forward iptables''', '443\n203.0.113.20:8443\n1\n1\n')
        self.assertEqual(result.returncode, 0, result.stderr)
        row = next(line[4:] for line in result.stdout.splitlines() if line.startswith('ROW:')).split('\t')
        self.assertEqual(row[4], '192.0.2.10')
        self.assertEqual(row[8:10], ['masquerade', 'any'])

    def test_batch_save_preserves_other_engines_and_allocates_unique_ids(self):
        with tempfile.TemporaryDirectory(dir=ROOT/'.work') as directory:
            folder = Path(directory)
            (folder/'connections.tsv').write_text(record()+'\n', newline='\n')
            (folder/'id-counter').write_text('9\n', newline='\n')
            prefix = 'GTM_CONFIG_DIR='+shlex.quote(folder.as_posix())+'; gtm_paths\n'
            result = bash(prefix+'''gtm_prepare() { :; }; gtm_install_component() { :; }
gtm_lock() { :; }; gtm_unlock() { :; }; gtm_listener_check() { :; }; gtm_legacy_listener_check() { :; }
gtm_commit() { gtm_write_records "$GTM_STATE"; }
gtm_new_forward haproxy''', '443,8443\n203.0.113.40:9443\n1\n1\n')
            self.assertEqual(result.returncode, 0, result.stderr)
            rows = [row.split('\t') for row in (folder/'connections.tsv').read_text().splitlines() if not row.startswith('#')]
            self.assertEqual([row[0] for row in rows], ['F000001', 'F000010', 'F000011'])
            self.assertEqual(rows[0][2], 'nftables')
            self.assertEqual((folder/'id-counter').read_text().strip(), '11')

    def test_wildcard_relay_cannot_loop_to_its_own_local_port(self):
        for target, expected in [('192.0.2.10:443@1', False), ('203.0.113.20:443@1', True), ('192.0.2.10:8443@1', True), ('[::ffff:c000:20a]:443@1', False), ('[::ffff:cb00:7114]:443@1', True)]:
            result = bash('ip() { printf "2: eth0 inet 192.0.2.10/24 scope global eth0\\n"; }\nIFS= read -r row; gtm_record_validate "$row" || exit 8\ngtm_relay_loop_check', record(engine='haproxy', bind='0.0.0.0', targets=target)+'\n')
            self.assertEqual(result.returncode == 0, expected, result.stderr)
