"""Installer orchestration with isolated paths, fake accounts and services.
No host service/account/network changes. Actual Go setup is tested separately.
"""
import hashlib
import io
import os
from pathlib import Path
import platform
import shlex
import subprocess
import tarfile
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


@unittest.skipUnless(platform.system() == 'Linux', 'isolated Linux installer harness')
class PanelInstallTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.bin = self.root / 'commands'
        self.bin.mkdir()
        self.packages = self.root / 'packages'
        self.packages.mkdir()
        self.config = self.root / 'etc/gre-manager-panel/config.json'
        self.log = self.root / 'calls'
        self.env = dict(os.environ, PATH=str(self.bin)+':'+str(self.root / 'usr/local/bin')+':'+os.environ['PATH'],
                        TEST_ROOT=str(self.root), TEST_CONFIG=str(self.config),
                        TEST_LOG=str(self.log), TEST_SETUP_VERSION='2')
        source = (ROOT / 'panel-install.sh').read_text(encoding='utf-8')
        # Redirect only the test copy; production has no configurable system root.
        for prefix in ['/usr/local/', '/var/lib/', '/etc/', '/run/']:
            source = source.replace(prefix, str(self.root)+prefix)
        source = source.replace('&& $EUID == 0', '&& 1 == 1')
        (self.root / 'run').mkdir()
        (self.root / 'usr/local/bin').mkdir(parents=True)
        (self.root / 'etc/systemd/system').mkdir(parents=True)
        self.installer = self.root / 'installer.sh'
        self.installer.write_text(source)
        self.command('getent', """case "$1" in
group) printf 'grepanel:x:123:\\n';;
passwd) printf 'grepanel:x:123:123::/nonexistent:/bin/false\\n';;
esac""")
        self.command('id', "printf '123\\n'")
        self.command('chown', ':')
        self.command('install', """args=()
while (($#)); do case $1 in -o|-g) shift 2;; *) args+=("$1"); shift;; esac; done
/usr/bin/install "${args[@]}" """)
        self.command('systemctl', """printf 'systemctl %s\\n' "$*" >> "$TEST_LOG"
case "$1" in cat) [[ -f "$TEST_ROOT/existing-service" ]];; *) exit 0;; esac""")
        self.command('useradd', 'exit 99')
        self.command('curl', 'echo "unexpected download" >&2; exit 99')
        self.command('sleep', ':')
        self.make_package()

    def command(self, name, body):
        path = self.bin / name
        path.write_text('#!/bin/bash\nset -euo pipefail\n'+body+'\n')
        path.chmod(0o755)

    def make_package(self):
        executable = """#!/bin/bash
set -euo pipefail
case "$1" in
version) printf '%s\\n' "${TEST_BINARY_VERSION:-v1.3.0}";;
setup-version) printf '%s\\n' "$TEST_SETUP_VERSION";;
setup)
    printf 'setup %s\\n' "$*" >> "$TEST_LOG"
    [[ ! -e "$TEST_CONFIG" ]] || exit 81
    [[ ! -f "$TEST_ROOT/fail-setup" ]] || exit 82
    printf '{"listen":"0.0.0.0:8443","protocol":"http","password_hash":"test-hash"}\\n' > "$TEST_CONFIG"
    ;;
address)
    printf 'address\\n' >> "$TEST_LOG"
    python3 -c 'import json,os; json.load(open(os.environ["TEST_CONFIG"]))'
    ;;
*) exit 83;;
esac
"""
        arch = {'x86_64':'amd64', 'aarch64':'arm64'}[platform.machine()]
        archive = self.packages / f'gtm-panel-v1.3.0-linux-{arch}.tar.gz'
        with tarfile.open(archive, 'w:gz') as tar:
            for name, body in [('gtm-panel', executable), ('gre.sh', '#!/bin/bash\nexit 0\n')]:
                data = body.encode()
                info = tarfile.TarInfo(name)
                info.mode = 0o755
                info.size = len(data)
                tar.addfile(info, io.BytesIO(data))
        (self.packages / 'SHA256SUMS').write_text(hashlib.sha256(archive.read_bytes()).hexdigest()+'  '+archive.name+'\n')

    def run_installer(self, *args):
        return subprocess.run(['bash', str(self.installer), '--package-dir', str(self.packages), *args],
                              env=self.env, text=True, capture_output=True, timeout=15)

    def calls(self):
        return self.log.read_text() if self.log.exists() else ''

    def test_fresh_install_and_upgrade_preserve_credentials_and_certificates(self):
        result = self.run_installer('--quick', '--protocol', 'http', '--address', '203.0.113.10')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('setup setup --quick --protocol http --address 203.0.113.10', self.calls())
        data = self.config.read_bytes()
        key = self.config.parent / 'server.key'
        cert = self.config.parent / 'server.crt'
        key.write_text('private-key')
        cert.write_text('operator-certificate')
        (self.root / 'existing-service').touch()
        self.log.write_text('')
        result = self.run_installer('--quick', '--protocol', 'https', '--address', 'other.example.com')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.config.read_bytes(), data)
        self.assertEqual(key.read_text(), 'private-key')
        self.assertEqual(cert.read_text(), 'operator-certificate')
        self.assertNotIn('setup ', self.calls())
        self.assertLess(self.calls().index('address\n'), self.calls().index('systemctl stop'))
        self.assertIn('preserved', result.stdout)

    def test_failed_setup_never_stops_existing_service(self):
        (self.root / 'existing-service').touch()
        (self.root / 'fail-setup').touch()
        result = self.run_installer('--quick')
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn('systemctl stop', self.calls())
        self.assertFalse(self.config.exists())

    def test_corrupt_config_rejects_update_before_service_stop(self):
        self.config.parent.mkdir(parents=True)
        self.config.write_text('broken')
        (self.root / 'existing-service').touch()
        result = self.run_installer('--quick')
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.config.read_text(), 'broken')
        self.assertNotIn('systemctl stop', self.calls())

    def test_old_package_rejects_new_options_before_setup(self):
        self.env['TEST_SETUP_VERSION'] = '1'
        result = self.run_installer('--quick', '--protocol', 'http')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('predates quick', result.stderr)
        self.assertEqual(self.calls(), '')

    def test_checksum_failure_changes_no_configuration_or_service(self):
        (self.packages / 'SHA256SUMS').write_text('0'*64+'  '+next(self.packages.glob('*.tar.gz')).name+'\n')
        result = self.run_installer('--quick')
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(self.config.exists())
        self.assertEqual(self.calls(), '')

    def test_mismatched_binary_version_stops_before_setup(self):
        self.env['TEST_BINARY_VERSION'] = 'v0.0.1'
        result = self.run_installer('--quick')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('Package version does not match', result.stderr)
        self.assertFalse(self.config.exists())
        self.assertEqual(self.calls(), '')

    def test_invalid_arguments_fail_without_mutation_or_secret_echo(self):
        for args in [('--password', 'do-not-log-this'), ('--port',), ('--unknown',)]:
            result = self.run_installer(*args)
            self.assertNotEqual(result.returncode, 0)
            self.assertNotIn('do-not-log-this', result.stdout+result.stderr)
            self.assertFalse(self.config.exists())
        self.assertEqual(self.calls(), '')

    def test_install_lock_refuses_concurrent_installer(self):
        lock = self.root / 'run/gre-manager-panel-install.lock'
        command = 'flock '+shlex.quote(str(lock))+' bash -c '+shlex.quote('bash "$1" --package-dir "$2" --quick')+' _ '+shlex.quote(str(self.installer))+' '+shlex.quote(str(self.packages))
        result = subprocess.run(['bash', '-c', command], env=self.env, text=True, capture_output=True, timeout=15)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('Another panel installation', result.stderr)
        self.assertFalse(self.config.exists())


if __name__ == '__main__':
    unittest.main()
