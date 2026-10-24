"""Portable paused recovery: real files in private fixtures, no host services."""
import shlex
import tempfile
from pathlib import Path
import unittest
from test_manager import ROOT, bash, record


class RecoveryTests(unittest.TestCase):
    def setup_script(self, directory):
        base = Path(directory).as_posix()
        return ('GTM_CONFIG_DIR=' + shlex.quote(base + '/config') + '\n'
                'GTM_SERVICE_DIR=' + shlex.quote(base + '/units') + '\n'
                'GTM_RUN_DIR=' + shlex.quote(base + '/run') + '\n'
                'gtm_paths\nmkdir -p "$GTM_CONFIG_DIR" "$GTM_SERVICE_DIR" "$GTM_RUN_DIR"\n'
                'gtm_root() { :; }\n'
                'gtm_prepare() { umask 077; mkdir -p "$GTM_CONFIG_DIR/backups"; }; gtm_lock() { :; }; gtm_unlock() { :; }\n'
                'systemctl() { [[ $1 != is-active ]]; }\n')

    def restore(self, directory, rows, extra=''):
        return bash(self.setup_script(directory) + extra + '\n'
                    'revision=$(gtm_recovery_revision) || exit 1\n'
                    '{ printf "%s\\n" "$revision"; cat; } | gtm_recovery_import\n', rows)

    def test_paused_restore_preserves_ids_names_and_keys(self):
        with tempfile.TemporaryDirectory(dir=ROOT/'.work') as directory:
            line = record(enabled='0')
            reverse = '\t'.join(['rathole', 'vpn', 'entrance', '192.0.2.1', '2333', '443', '127.0.0.1', '443', 'both', 'tcp', 'false', 'a'*24, 'vpn', 'A'*43+'=', '-', '0'])
            rows = ('I\t90\nC\t' + line + '\nG\t3\tiran\t198.51.100.1\t192.0.2.1\t1430\n'
                    'N\tgre-tun-3\tMy GRE\nR\t' + reverse + '\nN\tgtm-rathole-entrance-vpn\tPrivate VPN\n')
            result = self.restore(directory, rows)
            self.assertEqual(result.returncode, 0, result.stderr)
            root = Path(directory)
            self.assertIn(line, (root/'config/connections.tsv').read_text())
            self.assertEqual((root/'config/id-counter').read_text().strip(), '90')
            self.assertIn('My GRE', (root/'config/resource-names.tsv').read_text())
            self.assertIn('fd00:3::2/64', (root/'units/gre-tun-3.service').read_text())
            self.assertIn('local_private_key = "'+'A'*43+'="', (root/'config/gtm-rathole-entrance-vpn.toml').read_text())

    def test_enabled_rows_and_injection_never_write(self):
        for rows in ['C\t'+record(enabled='1')+'\n', 'G\t3\tiran\t$(touch /tmp/gtm-recovery-bad)\t192.0.2.1\t1430\n', 'X\t/etc/shadow\n']:
            with self.subTest(rows=rows), tempfile.TemporaryDirectory(dir=ROOT/'.work') as directory:
                result=self.restore(directory, rows)
                self.assertNotEqual(result.returncode, 0)
                self.assertFalse((Path(directory)/'config/connections.tsv').exists())

    def test_stale_revision_and_existing_state_are_preserved(self):
        with tempfile.TemporaryDirectory(dir=ROOT/'.work') as directory:
            result=bash(self.setup_script(directory)+'printf "%s\\n" '+shlex.quote(record())+' > "$GTM_STATE"\n'
                        '{ printf "%064d\\n" 0; cat; } | gtm_recovery_import', 'I\t0\n')
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual((Path(directory)/'config/connections.tsv').read_text().strip(),record())
            result=self.restore(directory,'I\t0\n')
            self.assertNotEqual(result.returncode,0)

    def test_duplicate_ids_and_orphan_files_block_every_write(self):
        for extra,rows in [('', 'C\t'+record(enabled='0')+'\nC\t'+record(enabled='0')+'\n'),
                           ('printf custom > "$GTM_CONFIG_DIR/gtm-rathole-entrance-vpn.toml"', 'I\t1\n')]:
            with tempfile.TemporaryDirectory(dir=ROOT/'.work') as directory:
                result=self.restore(directory,rows,extra)
                self.assertNotEqual(result.returncode,0)
                self.assertFalse((Path(directory)/'config/connections.tsv').exists())

    def test_write_failure_rolls_back_all_new_resources(self):
        with tempfile.TemporaryDirectory(dir=ROOT/'.work') as directory:
            extra='systemctl() { [[ $1 != is-active && $1 != daemon-reload ]]; }\n'
            result=self.restore(directory,'C\t'+record(enabled='0')+'\nG\t3\tiran\t198.51.100.1\t192.0.2.1\t1430\n',extra)
            self.assertNotEqual(result.returncode,0)
            self.assertFalse((Path(directory)/'units/gre-tun-3.service').exists())
            self.assertFalse((Path(directory)/'config/connections.tsv').exists())

    def test_recovery_never_starts_services_or_applies_firewall(self):
        with tempfile.TemporaryDirectory(dir=ROOT/'.work') as directory:
            extra=('systemctl() { [[ $1 != is-active ]] || return 1; [[ $1 == daemon-reload ]] || { echo BAD_START; return 1; }; }\n'
                   'gtm_kernel_apply() { echo BAD_FIREWALL; return 1; }; gtm_relays_apply() { echo BAD_RELAY; return 1; }\n')
            result=self.restore(directory,'C\t'+record(enabled='0')+'\n',extra)
            self.assertEqual(result.returncode,0,result.stderr)
            self.assertNotIn('BAD_',result.stdout)
