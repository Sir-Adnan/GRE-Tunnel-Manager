"""Reviewed imports preserve complete state and fail before writes on a stale review."""
from pathlib import Path
import shlex
import tempfile
import unittest

from test_manager import ROOT, bash, record


class ConfigImportTests(unittest.TestCase):
    def setup_script(self, directory):
        root = Path(directory).as_posix()
        return ('GTM_CONFIG_DIR=' + shlex.quote(root + '/config') + '\n'
                'GTM_RUN_DIR=' + shlex.quote(root + '/run') + '\n'
                'GTM_SERVICE_DIR=' + shlex.quote(root + '/units') + '\n'
                'gtm_paths\nmkdir -p "$GTM_CONFIG_DIR" "$GTM_RUN_DIR" "$GTM_SERVICE_DIR"\n'
                'gtm_prepare() { :; }; gtm_lock() { printf "locked\\n" >&2; }; gtm_unlock() { :; }\n'
                'gtm_need() { :; }; gtm_commit() { printf "%s\\n" "${GTM_RECORDS[@]}" > "$GTM_STATE"; }\n')

    def test_reviewed_batch_retains_unrelated_rows_and_checks_revision_under_lock(self):
        with tempfile.TemporaryDirectory(dir=ROOT / '.work') as directory:
            existing = record(id='F000010', enabled='0')
            incoming = record(id='F000000', engine='haproxy', port='5000', enabled='0', version='2') + '\tmaxconn=0;log=off;check_mode=off'
            result = bash(self.setup_script(directory) +
                          'printf "%s\\n" ' + shlex.quote(existing) + ' > "$GTM_STATE"\n'
                          'printf "10\\n" > "$GTM_CONFIG_DIR/id-counter"\n'
                          'revision=$(gtm_recovery_revision) || exit 1\n'
                          '{ printf "%s\\n" "$revision"; cat; } | gtm_api create-reviewed\n', incoming + '\n')
            self.assertEqual(result.returncode, 0, result.stderr)
            saved = (Path(directory) / 'config/connections.tsv').read_text()
            self.assertIn(existing, saved)
            self.assertIn('F000011\t', saved)
            self.assertIn('maxconn=0;log=off;check_mode=off', saved)
            self.assertIn('locked', result.stderr)

    def test_stale_import_never_advances_counter_or_publishes_state(self):
        with tempfile.TemporaryDirectory(dir=ROOT / '.work') as directory:
            incoming = record(id='F000000', enabled='0')
            result = bash(self.setup_script(directory) +
                          'printf 10 > "$GTM_CONFIG_DIR/id-counter"\n'
                          '{ printf "%064d\\n" 0; cat; } | gtm_api create-reviewed\n', incoming + '\n')
            self.assertNotEqual(result.returncode, 0)
            self.assertFalse((Path(directory) / 'config/connections.tsv').exists())
            self.assertEqual((Path(directory) / 'config/id-counter').read_text(), '10')

    def test_automatic_haproxy_capacity_omits_both_limits_and_checks(self):
        line = record(engine='haproxy', version='2') + '\tmaxconn=0;log=off;check_mode=off'
        result = bash('IFS= read -r row\ngtm_record_validate "$row" || exit 1\ngtm_haproxy_render\ngtm_haproxy_unit /usr/sbin/haproxy /etc/example.conf F000001', line + '\n')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertNotIn('maxconn ', result.stdout)
        self.assertNotIn(' check inter ', result.stdout)
        self.assertIn('LimitNOFILE=1048576', result.stdout)
        self.assertIn('timeout client 3600s', result.stdout)
