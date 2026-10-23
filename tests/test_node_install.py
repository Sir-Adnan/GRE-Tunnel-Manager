"""Node installer orchestration in a temporary fake Linux host; no real services."""
import hashlib
import io
import os
from pathlib import Path
import platform
import subprocess
import tarfile
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


@unittest.skipUnless(platform.system() == 'Linux', 'isolated Linux installer harness')
class NodeInstallTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.bin = self.root / 'commands'
        self.bin.mkdir()
        self.packages = self.root / 'packages'
        self.packages.mkdir()
        self.log = self.root / 'calls'
        for path in ['run', 'usr/local/bin', 'etc/systemd/system']:
            (self.root / path).mkdir(parents=True, exist_ok=True)
        self.env = dict(os.environ, PATH=str(self.bin)+':'+os.environ['PATH'], TEST_ROOT=str(self.root), TEST_LOG=str(self.log), TEST_NODE_PROTOCOL='1')
        source = (ROOT / 'node-install.sh').read_text(encoding='utf-8')
        for prefix in ['/usr/local/', '/var/lib/', '/etc/', '/run/']:
            source = source.replace(prefix, str(self.root)+prefix)
        source = source.replace('&& $EUID == 0', '&& 1 == 1')
        self.installer = self.root / 'node-install.sh'
        self.installer.write_text(source)
        self.command('getent', """case "$1" in
group) printf '%s:x:123:\\n' "$2";;
passwd) printf '%s:x:123:123::/nonexistent:/bin/false\\n' "$2";; esac""")
        self.command('id', "printf '123\\n'")
        self.command('chown', ':')
        self.command('runuser', 'shift 3; exec "$@"')
        self.command('install', """args=(); while (($#)); do case $1 in -o|-g) shift 2;; *) args+=("$1"); shift;; esac; done
/usr/bin/install "${args[@]}" """)
        self.command('systemctl', """printf 'systemctl %s\\n' "$*" >> "$TEST_LOG"
case "$1 ${2:-}" in 'cat gre-manager-panel.service') [[ -f "$TEST_ROOT/panel-service" ]];; 'cat gre-manager-agent.service') [[ -f "$TEST_ROOT/agent-service" ]];; *) exit 0;; esac""")
        for name in ['useradd', 'groupadd', 'curl']:
            self.command(name, 'exit 99')
        self.make_package()

    def command(self, name, body):
        path = self.bin / name
        path.write_text('#!/bin/bash\nset -euo pipefail\n'+body+'\n')
        path.chmod(0o755)

    def make_package(self):
        binary = """#!/bin/bash
set -euo pipefail
case "$1" in
version) printf 'v1.3.1\\n';;
nodes) case "$2" in
protocol) printf '%s\\n' "$TEST_NODE_PROTOCOL";;
operations-version) printf '1\\n';;
traffic-version) printf '%s\\n' "${TEST_TRAFFIC_PROTOCOL:-1}";;
enroll) printf 'enroll\\n' >> "$TEST_LOG"; [[ ! -f "$TEST_ROOT/fail-enroll" ]] || exit 2; umask 077; printf '{"private":"identity"}' > "$TEST_ROOT/var/lib/gre-manager-agent/identity.json";;
check) [[ ! -f "$TEST_ROOT/fail-check" ]];;
check-controller) [[ ! -f "$TEST_ROOT/fail-check" ]];;
init) printf 'init\\n' >> "$TEST_LOG"; mkdir -p "$TEST_ROOT/var/lib/gre-manager-nodes"; printf '{"private":"controller"}' > "$TEST_ROOT/var/lib/gre-manager-nodes/controller.json";;
*) exit 98;; esac;;
*) exit 99;; esac
"""
        (self.root / 'usr/local/bin/gtm-panel').write_text(binary)
        (self.root / 'usr/local/bin/gtm-panel').chmod(0o755)
        arch = {'x86_64': 'amd64', 'aarch64': 'arm64'}[platform.machine()]
        archive = self.packages / f'gtm-panel-v1.3.1-linux-{arch}.tar.gz'
        with tarfile.open(archive, 'w:gz') as output:
            for name, body in [('gtm-panel', binary), ('gre.sh', '#!/bin/bash\nexit 0\n')]:
                info = tarfile.TarInfo(name)
                info.mode = 0o755
                data = body.encode()
                info.size = len(data)
                output.addfile(info, io.BytesIO(data))
        (self.packages / 'SHA256SUMS').write_text(hashlib.sha256(archive.read_bytes()).hexdigest()+'  '+archive.name+'\n')

    def run_installer(self, *args):
        return subprocess.run(['bash', str(self.installer), *args], env=self.env, text=True, capture_output=True, timeout=15)

    def calls(self):
        return self.log.read_text() if self.log.exists() else ''

    def test_agent_install_and_upgrade_preserve_identity(self):
        result = self.run_installer('--agent', '--package-dir', str(self.packages))
        self.assertEqual(result.returncode, 0, result.stderr)
        identity = self.root / 'var/lib/gre-manager-agent/identity.json'
        self.assertEqual(identity.stat().st_mode & 0o777, 0o600)
        original = identity.read_bytes()
        (self.root / 'agent-service').touch()
        self.log.write_text('')
        result = self.run_installer('--agent', '--package-dir', str(self.packages))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(identity.read_bytes(), original)
        self.assertNotIn('enroll', self.calls())
        service = (self.root / 'etc/systemd/system/gre-manager-agent-broker.service').read_text()
        self.assertIn('broker --read-only --socket', service)
        self.assertNotIn(' install ', self.calls())

    def test_old_package_and_checksum_fail_before_enrollment(self):
        self.env['TEST_NODE_PROTOCOL'] = '0'
        result = self.run_installer('--agent', '--package-dir', str(self.packages))
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn('enroll', self.calls())
        self.env['TEST_NODE_PROTOCOL'] = '1'
        (self.packages / 'SHA256SUMS').write_text('0'*64+'  '+next(self.packages.glob('*.tar.gz')).name+'\n')
        self.assertNotEqual(self.run_installer('--agent', '--package-dir', str(self.packages)).returncode, 0)
        self.assertNotIn('systemctl stop', self.calls())

    def test_operations_opt_in_and_upgrade_keep_recovery_worker(self):
        result = self.run_installer('--agent', '--operations', '--package-dir', str(self.packages))
        self.assertEqual(result.returncode, 0, result.stderr)
        service = (self.root / 'etc/systemd/system/gre-manager-agent.service').read_text()
        broker = (self.root / 'etc/systemd/system/gre-manager-agent-broker.service').read_text()
        self.assertIn('nodes agent --operations', service)
        self.assertIn('--read-only --node-operations --socket', broker)
        self.assertIn('StopWhenUnneeded=no', broker)
        self.assertIn('WantedBy=multi-user.target', broker)
        (self.root / 'agent-service').touch()
        result = self.run_installer('--agent', '--package-dir', str(self.packages))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('nodes agent --operations', (self.root / 'etc/systemd/system/gre-manager-agent.service').read_text())

    def test_traffic_opt_in_preserves_flags_and_stays_off_by_default(self):
        result = self.run_installer('--agent', '--operations', '--traffic', '--package-dir', str(self.packages))
        self.assertEqual(result.returncode, 0, result.stderr)
        service = self.root / 'etc/systemd/system/gre-manager-agent.service'
        broker = self.root / 'etc/systemd/system/gre-manager-agent-broker.service'
        self.assertIn('nodes agent --operations --traffic', service.read_text())
        self.assertIn('--read-only --node-operations --agent-traffic --socket', broker.read_text())
        self.assertNotIn('traffic --enable', self.calls())
        self.assertEqual((self.root / 'var/lib/gre-manager-agent-traffic').stat().st_mode & 0o777, 0o700)
        result = self.run_installer('--agent', '--package-dir', str(self.packages))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('nodes agent --operations --traffic', service.read_text())

    def test_traffic_old_binary_fails_before_service_stop(self):
        self.env['TEST_TRAFFIC_PROTOCOL'] = '0'
        result = self.run_installer('--agent', '--traffic', '--package-dir', str(self.packages))
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn('enroll', self.calls())
        self.assertNotIn('systemctl stop', self.calls())

    def test_failed_enrollment_and_corrupt_identity_do_not_stop_services(self):
        (self.root / 'fail-enroll').touch()
        result = self.run_installer('--agent', '--package-dir', str(self.packages))
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn('systemctl stop', self.calls())
        (self.root / 'fail-enroll').unlink()
        identity = self.root / 'var/lib/gre-manager-agent/identity.json'
        identity.write_text('broken')
        (self.root / 'fail-check').touch()
        result = self.run_installer('--agent', '--package-dir', str(self.packages))
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(identity.read_text(), 'broken')
        self.assertNotIn('systemctl stop', self.calls())

    def test_controller_preserves_existing_identity_and_needs_updated_panel(self):
        config = self.root / 'etc/gre-manager-panel/config.json'
        config.parent.mkdir(parents=True)
        config.write_text('{}')
        args = ['--controller', '--url', 'https://203.0.113.1:9443']
        self.assertEqual(self.run_installer(*args).returncode, 0)
        state = self.root / 'var/lib/gre-manager-nodes/controller.json'
        before = state.read_bytes()
        self.log.write_text('')
        self.assertEqual(self.run_installer(*args).returncode, 0)
        self.assertEqual(state.read_bytes(), before)
        self.assertNotIn('init', self.calls())
        self.env['TEST_NODE_PROTOCOL'] = '0'
        self.assertNotEqual(self.run_installer(*args).returncode, 0)

    def test_existing_panel_and_secret_arguments_are_rejected(self):
        (self.root / 'panel-service').touch()
        self.assertNotEqual(self.run_installer('--agent', '--package-dir', str(self.packages)).returncode, 0)
        for args in [('--token', 'do-not-print'), ('--agent', '--url', 'https://host:9443'), ('--agent', '--controller')]:
            result = self.run_installer(*args)
            self.assertNotEqual(result.returncode, 0)
            self.assertNotIn('do-not-print', result.stdout+result.stderr)


if __name__ == '__main__':
    unittest.main()
