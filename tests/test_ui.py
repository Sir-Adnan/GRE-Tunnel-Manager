"""Fixed terminal style, dedicated managers and SSH fallbacks."""
import os
import re
import subprocess
import unittest

from test_manager import BASH, ROOT, bash

ANSI = re.compile(r'\x1b\[[0-9;]*[A-Za-z]')


class TerminalTests(unittest.TestCase):
    def test_choices_fit_narrow_and_wide_windows(self):
        for width in [20, 40, 72, 80, 100, 160]:
            result = bash(f'COLUMNS={width}; GTM_DEMO=1; gtm_home')
            self.assertEqual(result.returncode, 0, result.stderr)
            options = [line for line in result.stdout.splitlines() if line.startswith('  [')]
            self.assertTrue(all(len(line) <= width for line in options), (width, options))
            for number in range(8):
                self.assertIn(f'[{number}]', result.stdout)

    def test_technical_addresses_survive_wrapping(self):
        result = bash('COLUMNS=40; GTM_DEMO=1; gtm_show_records')
        self.assertEqual(result.returncode, 0, result.stderr)
        contents = ''.join(line.strip() for line in result.stdout.splitlines())
        for value in ['F000001', 'F000002', 'F000003', '203.0.113.20:443', '203.0.113.21:443']:
            self.assertIn(value, contents)

    def test_no_color_and_dumb_remain_plain(self):
        for settings in ['NO_COLOR=1; TERM=xterm-256color', 'TERM=dumb']:
            result = bash('GTM_FORCE_COLOR=1; '+settings+'; gtm_palette; gtm_home')
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertNotIn('\x1b', result.stdout)
            self.assertTrue(result.stdout.isascii())

    def test_fixed_color_has_no_background_fills_or_preferences(self):
        result = bash('''unset NO_COLOR; TERM=xterm-256color; GTM_FORCE_COLOR=1
GTM_THEME=light; GTM_LANGUAGE=fa; GTM_LAYOUT=compact
GTM_PREFS=<(printf 'invalid\t$(exit 99)\n')
gtm_palette; gtm_home
if declare -F gtm_preferences || declare -F gtm_settings; then exit 8; fi''')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('\x1b[0;96m', result.stdout)
        self.assertNotRegex(result.stdout, r'\x1b\[(?:[^m]*;)?4[0-9](?:;[^m]*)?m')
        self.assertTrue(result.stdout.isascii())

    def test_dedicated_engine_previews_are_read_only(self):
        for engine, title in [('haproxy', 'H A P R O X Y'), ('realm', 'R E A L M')]:
            result = bash(f'gtm_prepare() {{ exit 81; }}; systemctl() {{ exit 82; }}; gtm_main --preview {engine}')
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn(title, result.stdout)
            self.assertIn('Add Tunnel', result.stdout)
            self.assertIn('Status & Logs', result.stdout)

    def test_engine_filter_scopes_selection_without_dropping_other_records(self):
        result = bash('''GTM_DEMO=1; GTM_ENGINE_FILTER=haproxy
gtm_records; [[ ${#GTM_RECORDS[@]} == 1 && ${GTM_RECORDS[0]} == F000003* ]] || exit 9
gtm_prepare() { :; }; gtm_lock() { :; }; gtm_unlock() { :; }; gtm_confirm() { :; }
gtm_read() { printf -v "$2" '%s' 1; }
gtm_load_records() { gtm_demo_records; }
gtm_commit() { printf 'REMAINING:%s\n' "${GTM_RECORDS[@]}"; }
gtm_mutate_selected delete''')
        self.assertEqual(result.returncode, 0, result.stderr)
        remaining = [line for line in result.stdout.splitlines() if line.startswith('REMAINING:')]
        self.assertEqual(len(remaining), 2)
        self.assertTrue(any('F000001' in line for line in remaining))
        self.assertTrue(any('F000002' in line for line in remaining))
        self.assertFalse(any('F000003' in line for line in remaining))

    @unittest.skipIf(os.name == 'nt', 'PTY validation requires a Unix terminal')
    def test_actual_tty_emits_fixed_colors_within_window(self):
        import fcntl
        import pty
        import struct
        import termios

        master, slave = pty.openpty()
        try:
            fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack('HHHH', 40, 96, 0, 0))
            env = dict(os.environ, TERM='xterm-256color', LC_ALL='C.UTF-8')
            for key in ['NO_COLOR', 'COLUMNS', 'LINES']:
                env.pop(key, None)
            process = subprocess.Popen([BASH, 'gre.sh', '--preview', 'haproxy'], cwd=ROOT,
                                       stdin=slave, stdout=slave, stderr=slave, env=env)
            os.close(slave)
            slave = None
            output = bytearray()
            while True:
                try:
                    chunk = os.read(master, 65536)
                except OSError:
                    break
                if not chunk:
                    break
                output.extend(chunk)
            self.assertEqual(process.wait(timeout=10), 0)
            rendered = output.decode('utf-8').replace('\r', '')
            self.assertIn('\x1b[0;96m', rendered)
            self.assertIn('H A P R O X Y', rendered)
            self.assertTrue(all(len(line) <= 96 for line in ANSI.sub('', rendered).splitlines()))
        finally:
            os.close(master)
            if slave is not None:
                os.close(slave)
