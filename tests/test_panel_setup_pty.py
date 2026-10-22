"""Real Go setup/recovery on a Unix terminal, without installing services."""
import json
import os
from pathlib import Path
import select
import subprocess
import tempfile
import time
import unittest

BINARY = os.environ.get('GTM_PANEL_TEST_BINARY', '')


@unittest.skipUnless(os.name == 'posix' and BINARY, 'requires a built Linux panel and Unix PTY')
class PanelSetupPTYTests(unittest.TestCase):
    def terminal(self, args, steps):
        import pty
        import termios
        master, slave = pty.openpty()
        process = subprocess.Popen([BINARY, *args], stdin=slave, stdout=slave, stderr=slave)
        os.close(slave)
        output = bytearray()
        start = 0
        try:
            for prompt, value in steps:
                deadline = time.monotonic()+10
                while prompt not in output[start:]:
                    if time.monotonic() >= deadline:
                        self.fail('missing terminal prompt: '+prompt.decode())
                    if select.select([master], [], [], 0.1)[0]:
                        try:
                            data = os.read(master, 8192)
                        except OSError:
                            data = b''
                        if not data:
                            self.fail('setup exited before: '+prompt.decode())
                        output.extend(data)
                start = len(output)
                if prompt in (b'Admin password', b'Confirm password:'):
                    # The prompt write precedes ReadPassword changing termios.
                    # Synchronize with actual hidden mode instead of racing it.
                    while termios.tcgetattr(master)[3] & termios.ECHO:
                        if time.monotonic() >= deadline:
                            self.fail('terminal password input was not hidden')
                        time.sleep(0.001)
                os.write(master, value+b'\n')
            process.wait(timeout=10)
            while select.select([master], [], [], 0)[0]:
                try:
                    data = os.read(master, 8192)
                except OSError:
                    break
                if not data:
                    break
                output.extend(data)
            return process.returncode, bytes(output)
        finally:
            if process.poll() is None:
                process.kill()
                process.wait()
            os.close(master)

    def test_hidden_setup_and_recovery_preserve_access(self):
        with tempfile.TemporaryDirectory() as folder:
            config = Path(folder)/'config.json'
            code, output = self.terminal(['setup', '--config', str(config), '--address', '127.0.0.1', '--listen', '127.0.0.1'], [
                (b'Setup [1]:', b'2'), (b'Access [1]:', b'2'),
                (b'Server IP or domain', b''), (b'Panel port', b''), (b'Admin username', b''),
                (b'Admin password', b'Short7!'),
                (b'Admin password', b'Eight!42'), (b'Confirm password:', b'Eight!42')])
            self.assertEqual(code, 0)
            self.assertNotIn(b'Eight!42', output)
            self.assertNotIn(b'Short7!', output)
            initial = json.loads(config.read_text())
            code, output = self.terminal(['reset-password', '--config', str(config)], [
                (b'Admin password', b'New!1234'), (b'Confirm password:', b'Mismatch!'),
                (b'Admin password', b'New!1234'), (b'Confirm password:', b'Mismatch!'),
                (b'Admin password', b'New!1234'), (b'Confirm password:', b'Mismatch!')])
            self.assertNotEqual(code, 0)
            self.assertNotIn(b'New!1234', output)
            self.assertEqual(json.loads(config.read_text()), initial)
            code, output = self.terminal(['reset-password', '--config', str(config)], [
                (b'Admin password', b'New!1234'), (b'Confirm password:', b'New!1234')])
            self.assertEqual(code, 0)
            self.assertNotIn(b'New!1234', output)
            changed = json.loads(config.read_text())
            self.assertNotEqual(initial.pop('password_hash'), changed.pop('password_hash'))
            self.assertEqual(initial, changed)

    def test_manual_password_cannot_be_read_from_a_pipe(self):
        with tempfile.TemporaryDirectory() as folder:
            result = subprocess.run([BINARY, 'setup', '--config', folder+'/config.json', '--address', '127.0.0.1'],
                                    input=b'2\n2\n\n\n\n', capture_output=True, timeout=10)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn(b'password entry requires a terminal', result.stderr)
            self.assertFalse((Path(folder)/'config.json').exists())


if __name__ == '__main__':
    unittest.main()
