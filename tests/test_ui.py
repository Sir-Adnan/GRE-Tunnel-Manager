"""Regression coverage for SSH sizing, readable palettes and terminal fallbacks."""
import os
import re
import subprocess
import unittest

from test_manager import BASH, ROOT, bash

ANSI = re.compile(r'\x1b\[[0-9;]*m')


class TerminalTests(unittest.TestCase):
    def test_panels_fit_narrow_and_wide_windows_without_losing_choices(self):
        for width in [20, 40, 72, 80, 100, 160]:
            result = bash(f'COLUMNS={width}; LINES=40; GTM_DEMO=1; GTM_LAYOUT=guided; gtm_home')
            self.assertEqual(result.returncode, 0, result.stderr)
            panels = [line for line in result.stdout.splitlines() if line.startswith(('  |', '  +'))]
            self.assertTrue(panels)
            self.assertTrue(all(len(line) <= width for line in panels), (width, panels))
            for number in range(8):
                self.assertIn(f'[{number}]', result.stdout)

    def test_technical_values_survive_wrapping(self):
        result = bash('''COLUMNS=40; LINES=40; GTM_DEMO=1; gtm_show_records''')
        self.assertEqual(result.returncode, 0, result.stderr)
        contents = ''.join(line.strip()[1:-1].strip() for line in result.stdout.splitlines() if line.startswith('  |'))
        for value in ['F000001', 'F000002', 'F000003', '203.0.113.20:443@2', '203.0.113.21:443@1']:
            self.assertIn(value, contents)

    def test_no_color_dumb_and_c_locale_remain_plain(self):
        for settings in ['NO_COLOR=1; TERM=xterm-256color', 'TERM=dumb']:
            result = bash('GTM_THEME=dark; GTM_FORCE_COLOR=1; '+settings+'; LC_ALL=C; gtm_palette; gtm_home')
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertNotIn('\x1b', result.stdout)
            self.assertTrue(result.stdout.isascii())

    def test_dark_and_light_color_rows_have_matching_widths(self):
        for theme in ['dark', 'light']:
            result = bash(f'''unset NO_COLOR; TERM=xterm-256color; LC_ALL=C; GTM_FORCE_COLOR=1
GTM_THEME={theme}; COLUMNS=80; gtm_palette; gtm_home''')
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn('48;5;', result.stdout)
            lines = ANSI.sub('', result.stdout).splitlines()
            panels = [line for line in lines if line.startswith(('  |', '  +'))]
            self.assertTrue(all(len(line) == 78 for line in panels), panels)

    def test_layout_preferences_and_cli_override_are_validated(self):
        result = bash('''GTM_PREFS=<(printf 'layout\tcompact\nlayout\t$(exit 99)\n') gtm_preferences
[[ $GTM_LAYOUT == compact ]] || exit 8
gtm_main --preview home --layout guided
[[ $GTM_LAYOUT == guided ]]''')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('GRE Tunnel', result.stdout)
        result = bash('gtm_main --preview home --layout invalid')
        self.assertEqual(result.returncode, 2)

    def test_engine_filter_scopes_selection_without_dropping_other_records(self):
        result = bash('''GTM_DEMO=1; GTM_ENGINE_FILTER=haproxy
gtm_records; [[ ${#GTM_RECORDS[@]} == 1 && ${GTM_RECORDS[0]} == F000003* ]] || exit 9
gtm_prepare() { :; }; gtm_lock() { :; }; gtm_unlock() { :; }; gtm_confirm() { :; }
gtm_read() { printf -v "$2" '%s' 1; }
gtm_load_records() { gtm_demo_records; }
gtm_commit() { printf 'REMAINING:%s\\n' "${GTM_RECORDS[@]}"; }
gtm_mutate_selected delete''')
        self.assertEqual(result.returncode, 0, result.stderr)
        remaining = [line for line in result.stdout.splitlines() if line.startswith('REMAINING:')]
        self.assertEqual(len(remaining), 2)
        self.assertTrue(any('F000001' in line for line in remaining))
        self.assertTrue(any('F000002' in line for line in remaining))
        self.assertFalse(any('F000003' in line for line in remaining))

    @unittest.skipIf(os.name == 'nt', 'PTY validation requires a Unix terminal')
    def test_actual_tty_detects_size_and_emits_color(self):
        import fcntl
        import pty
        import struct
        import termios

        master, slave = pty.openpty()
        try:
            fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack('HHHH', 40, 96, 0, 0))
            env = dict(os.environ, TERM='xterm-256color', LC_ALL='C.UTF-8')
            env.pop('NO_COLOR', None)
            env.pop('COLUMNS', None)
            env.pop('LINES', None)
            process = subprocess.Popen([BASH, 'gre.sh', '--preview', 'home', '--theme', 'dark'],
                                       cwd=ROOT, stdin=slave, stdout=slave, stderr=slave, env=env)
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
            self.assertIn('\x1b[', rendered)
            self.assertIn('╭', rendered)
            panels = [line for line in ANSI.sub('', rendered).splitlines() if line.startswith(('  │', '  ╭', '  ╰'))]
            self.assertTrue(panels)
            self.assertTrue(all(len(line) == 94 for line in panels), panels)
        finally:
            os.close(master)
            if slave is not None:
                os.close(slave)
