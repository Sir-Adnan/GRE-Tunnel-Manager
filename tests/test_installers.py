"""install.sh bootstrap and the panel-install.sh / node-install.sh shims.

The bootstrap only downloads, verifies and hands over to "gtm"; the install
logic itself is covered by the Go tests in panel/internal/install and
panel/internal/gtm. Nothing here touches host services or accounts.
"""
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
VERSION = next(line.split('=', 1)[1] for line in (ROOT / 'install.sh').read_text(encoding='utf-8').splitlines()
               if line.startswith('GTM_VERSION='))
FAKE_GTM = """#!/bin/bash
case "$1" in
version) printf '%s\\n' "${TEST_BINARY_VERSION:-v__VERSION__}";;
*) printf 'gtm-panel %s\\n' "$*" >> "$TEST_LOG";;
esac
"""


@unittest.skipUnless(platform.system() == 'Linux', 'Linux shell harness')
class BootstrapTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)
        self.bin = self.root / 'bin'
        self.bin.mkdir()
        self.packages = self.root / 'packages'
        self.packages.mkdir()
        self.log = self.root / 'calls'
        for name in ('systemctl', 'apt-get'):
            self.command(name, 'exit 0')
        self.command('curl', 'echo "unexpected download" >&2; exit 99')
        self.env = dict(os.environ, PATH=f'{self.bin}:{os.environ["PATH"]}', TEST_LOG=str(self.log))
        source = (ROOT / 'install.sh').read_text(encoding='utf-8').replace('[[ $EUID == 0 ]]', '[[ 1 == 1 ]]')
        self.installer = self.root / 'install.sh'
        self.installer.write_text(source, encoding='utf-8')
        self.make_package()

    def command(self, name, body):
        path = self.bin / name
        path.write_text('#!/bin/bash\n' + body + '\n', encoding='utf-8')
        path.chmod(0o755)

    def make_package(self, sums_override=None):
        arch = {'x86_64': 'amd64', 'aarch64': 'arm64'}[platform.machine()]
        archive = self.packages / f'gtm-panel-v{VERSION}-linux-{arch}.tar.gz'
        with tarfile.open(archive, 'w:gz') as tar:
            for name, body in (('gtm-panel', FAKE_GTM.replace('__VERSION__', VERSION)), ('gre.sh', '#!/bin/bash\n')):
                data = body.encode()
                info = tarfile.TarInfo(name)
                info.mode = 0o755
                info.size = len(data)
                tar.addfile(info, io.BytesIO(data))
        digest = sums_override or hashlib.sha256(archive.read_bytes()).hexdigest()
        (self.packages / 'SHA256SUMS').write_text(f'{digest}  {archive.name}\n', encoding='ascii')

    def run_installer(self, *args, env=None):
        return subprocess.run(['bash', str(self.installer), '--package-dir', str(self.packages), *args],
                              env=env or self.env, text=True, capture_output=True, timeout=30, stdin=subprocess.DEVNULL)

    def calls(self):
        return self.log.read_text() if self.log.exists() else ''

    def test_hands_options_and_verified_source_to_gtm(self):
        result = self.run_installer('--domain', 'panel.example.com', '--yes')
        self.assertEqual(result.returncode, 0, result.stderr)
        call = self.calls().strip()
        self.assertRegex(call, r'^gtm-panel gtm install --source (\S+) --domain panel\.example\.com --yes$')
        source = call.split('--source ')[1].split()[0]
        self.assertFalse(Path(source).exists(), 'the temporary package directory is removed')
        self.assertIn('Package verified', result.stdout)

    def test_remove_and_agent_tasks(self):
        self.assertEqual(self.run_installer('--remove', '--yes').returncode, 0)
        self.assertEqual(self.calls(), 'gtm-panel gtm remove --yes\n')
        self.log.unlink()
        self.assertEqual(self.run_installer('--agent', '--operations').returncode, 0)
        self.assertRegex(self.calls(), r'^gtm-panel gtm install --source \S+ --agent --operations\n$')

    def test_checksum_failure_installs_nothing(self):
        self.make_package(sums_override='0' * 64)
        result = self.run_installer('--yes')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('Checksum verification failed', result.stderr)
        self.assertEqual(self.calls(), '')

    def test_version_mismatch_installs_nothing(self):
        result = self.run_installer('--yes', env=dict(self.env, TEST_BINARY_VERSION='v0.0.1'))
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('does not match', result.stderr)
        self.assertEqual(self.calls(), '')

    def test_invalid_version_and_help(self):
        result = self.run_installer('--version', 'latest')
        self.assertNotEqual(result.returncode, 0)
        result = subprocess.run(['bash', str(self.installer), '--help'], env=self.env, text=True, capture_output=True, timeout=15)
        self.assertEqual(result.returncode, 0)
        self.assertIn('--password-env', result.stdout)
        self.assertEqual(self.calls(), '')

    def test_missing_systemd_stops_early(self):
        (self.bin / 'systemctl').unlink()
        env = dict(self.env, PATH=f'{self.bin}:/usr/bin:/bin')
        if subprocess.run(['bash', '-c', 'command -v systemctl'], env=env, capture_output=True).returncode == 0:
            self.skipTest('host provides systemctl')
        result = self.run_installer('--yes', env=env)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('systemd is required', result.stderr)


@unittest.skipUnless(platform.system() == 'Linux', 'Linux shell harness')
class ShimTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.dir = Path(tmp.name)
        self.log = self.dir / 'calls'
        for name in ('panel-install.sh', 'node-install.sh'):
            (self.dir / name).write_text((ROOT / name).read_text(encoding='utf-8'), encoding='utf-8')
        # A sibling install.sh is used instead of a download.
        (self.dir / 'install.sh').write_text('#!/bin/bash\nprintf "install.sh %s\\n" "$*" >> "$TEST_LOG"\n', encoding='utf-8')
        self.bin = self.dir / 'bin'
        self.bin.mkdir()
        gtm = self.bin / 'gtm'
        gtm.write_text('#!/bin/bash\nprintf "gtm %s\\n" "$*" >> "$TEST_LOG"\n', encoding='utf-8')
        gtm.chmod(0o755)
        self.env = dict(os.environ, TEST_LOG=str(self.log), PATH=f'{self.bin}:{os.environ["PATH"]}')

    def run_shim(self, name, *args):
        result = subprocess.run(['bash', str(self.dir / name), *args], env=self.env, text=True, capture_output=True, timeout=15)
        calls = self.log.read_text() if self.log.exists() else ''
        if self.log.exists():
            self.log.unlink()
        return result, calls

    def test_panel_options_map_to_install_sh(self):
        cases = {
            ('--quick',): '--yes --self-signed',
            ('--quick', '--address', '203.0.113.7', '--username', 'ops', '--port', '2053', '--install-engines'):
                '--yes --domain 203.0.113.7 --user ops --port 2053 --engines --self-signed',
            ('--quick', '--domain', 'panel.example.com', '--letsencrypt', '--email', 'ops@example.com'):
                '--yes --domain panel.example.com --email ops@example.com --https',
            ('--protocol', 'http', '--quick'): '--yes --http',
            ('--staging',): '--staging --https',
            ('--uninstall',): '--remove',
            ('--uninstall', '--yes'): '--remove --yes',
            (): '',
        }
        for args, mapped in cases.items():
            result, calls = self.run_shim('panel-install.sh', *args)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(calls.strip(), f'install.sh --version {VERSION} {mapped}'.strip(), args)

    def test_panel_shim_rejects_conflicts_without_running(self):
        for args in (('--protocol', 'http', '--letsencrypt'), ('--port',), ('--bogus',), ('--protocol', 'ftp')):
            result, calls = self.run_shim('panel-install.sh', *args)
            self.assertNotEqual(result.returncode, 0, args)
            self.assertEqual(calls, '')

    def test_node_shim_maps_agent_and_controller(self):
        result, calls = self.run_shim('node-install.sh', '--agent', '--operations', '--traffic')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(calls, f'install.sh --version {VERSION} --agent --operations --traffic\n')
        result, calls = self.run_shim('node-install.sh', '--controller', '--url', 'https://203.0.113.7:9443', '--listen', '0.0.0.0:9443')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(calls, 'gtm controller enable --url https://203.0.113.7:9443 --listen 0.0.0.0:9443\n')
        for args in (('--controller',), ('--agent', '--url', 'x'), ('--controller', '--url', 'u', '--operations'), ()):
            result, calls = self.run_shim('node-install.sh', *args)
            self.assertNotEqual(result.returncode, 0, args)
            self.assertEqual(calls, '')


if __name__ == '__main__':
    unittest.main()
