"""Fixed terminal style, dedicated managers and SSH fallbacks."""
import os
import re
import subprocess
import unittest

from test_manager import BASH, ROOT, bash

ANSI = re.compile(r'\x1b\[[0-9;]*[A-Za-z]')


class TerminalTests(unittest.TestCase):
    def test_header_keeps_public_and_local_addresses_separate(self):
        result = bash('''GTM_SERVER_INFO_READY=1
GTM_HOST=test-node; GTM_OS='Ubuntu 24.04'; GTM_LOCAL4=10.20.30.40
GTM_PUBLIC_IP=203.0.113.5; GTM_LOCAL6=2001:db8:abcd:1234:5678:9abc:def0:1234
GTM_PROVIDER='Example Hosting'; GTM_ASN=AS64500; GTM_COUNTRY=Germany
COLUMNS=80; LINES=24; gtm_header 'HAProxy / Add tunnel' ''')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('Public v4 203.0.113.5', result.stdout)
        self.assertIn('Local v4  10.20.30.40', result.stdout)
        self.assertIn('2001:db8:abcd:1234:5678:9abc:def0:1234', result.stdout)
        self.assertIn('Example Hosting / AS64500 / Germany', result.stdout)
        self.assertNotIn('T U N N E L   M A N A G E R', result.stdout)
        result = bash('''COLUMNS=40; gtm_terminal_size
gtm_header_address 'Local v6  ' ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff''')
        self.assertIn('ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff', result.stdout)
        self.assertTrue(all(len(line) <= 40 for line in result.stdout.splitlines()))

    def test_banner_adapts_to_height_and_width(self):
        for width, height, large in [(80, 40, True), (40, 40, False), (80, 24, False)]:
            result = bash(f'GTM_DEMO=1; COLUMNS={width}; LINES={height}; gtm_header "HAProxy Manager"')
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual('T U N N E L   M A N A G E R' in result.stdout, large)
            self.assertIn('H A P R O X Y', result.stdout)
            self.assertTrue(all(len(line) <= width for line in result.stdout.splitlines()))

    def test_server_info_is_cached_and_previews_do_not_probe(self):
        result = bash('''count=0
gtm_server_local_info() { ((count+=1)); GTM_HOST=local; }
gtm_server_lookup() { exit 71; }
gtm_server_info; gtm_server_info
[[ $count == 1 ]] || exit 72
GTM_SERVER_INFO_READY=0; gtm_server_info
[[ $count == 2 ]] || exit 73
GTM_SERVER_INFO_READY=0; GTM_DEMO=1; gtm_header 'Main Menu'
[[ $count == 2 ]] || exit 74
[[ $GTM_HOST == demo-server ]]''')
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_local_info_prefers_default_interfaces_and_skips_tunnels(self):
        result = bash('''ip() {
case "$*" in
    '-4 route show default') printf 'default via 10.0.0.1 dev eth0\n';;
    '-6 route show default') printf 'default dev eth1 metric 100\n';;
    '-o address show scope global') printf '%s\n' \\
        '9: gre1 inet 10.0.10.1/30 scope global gre1' \\
        '3: eth2 inet 192.0.2.30/24 scope global eth2' \\
        '2: eth0 inet 192.0.2.10/24 scope global eth0' \\
        '2: eth0 inet6 2001:db8::1/64 scope global tentative' \\
        '4: eth1 inet6 2001:db8::2/64 scope global dynamic';;
    *) exit 78;;
esac
}
gtm_server_local_info
[[ $GTM_LOCAL4 == 192.0.2.10 && $GTM_LOCAL6 == 2001:db8::2 ]]''')
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_metadata_lookup_is_bounded_and_untrusted_text_is_not_executed(self):
        result = bash('''curl() {
[[ "$*" == *'--connect-timeout 1 --max-time 2 --max-filesize 8192'* ]] || return 19
[[ "$*" == *'https://ipwho.is/?fields='* ]] || return 20
printf '%s' '{"success":true,"ip":"203.0.113.5","country":"Germany","connection":{"org":"$(exit 99) Example","asn":64500}}'
}
gtm_server_lookup
[[ $GTM_PUBLIC_IP == 203.0.113.5 && $GTM_ASN == AS64500 ]] || exit 21
[[ $GTM_PROVIDER == '(exit 99) Example' && $GTM_COUNTRY == Germany ]] || exit 22
value=$(gtm_info_text $'bad\\033[31m\\r\\nname')
[[ $value != *$'\\033'* && $value != *$'\\r'* && $value != *$'\\n'* ]]''')
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_failed_or_invalid_lookup_keeps_local_information(self):
        for response in ['{"success":false,"ip":"203.0.113.5"}',
                         '{"success":true,"ip":"$(exit 99)"}', 'rate limited']:
            result = bash('''GTM_LOCAL4=10.0.0.2; GTM_PUBLIC_IP=''; GTM_PROVIDER=''
curl() { printf '%s' "$PAYLOAD"; }
IFS= read -r PAYLOAD
gtm_server_lookup
[[ $GTM_LOCAL4 == 10.0.0.2 && -z $GTM_PUBLIC_IP && -z $GTM_PROVIDER ]]''', response+'\n')
            self.assertEqual(result.returncode, 0, result.stderr)
        result = bash("curl() { return 28; }; gtm_server_lookup")
        self.assertEqual(result.returncode, 0, result.stderr)

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
        rendered = self.pty_output(['gre.sh', '--preview', 'haproxy'])
        self.assertIn('\x1b[0;96m', rendered)
        self.assertIn('H A P R O X Y', rendered)
        self.assertTrue(all(len(line) <= 96 for line in ANSI.sub('', rendered).splitlines()))

    @unittest.skipIf(os.name == 'nt', 'PTY validation requires a Unix terminal')
    def test_interactive_header_lookup_gate_refresh_and_step_redraw(self):
        rendered = self.pty_output(['-c', '''source ./gre.sh; gtm_palette
gtm_server_local_info() { GTM_HOST=test-node; GTM_OS=Linux; GTM_LOCAL4=10.0.0.2; }
gtm_server_lookup() { printf 'LOOKUP_CALLED\\n' >&2; GTM_PUBLIC_IP=203.0.113.5; }
GTM_SERVER_LOOKUP=0; gtm_header 'HAProxy / Add tunnel'
GTM_SERVER_INFO_READY=0; unset GTM_SERVER_LOOKUP; gtm_header 'HAProxy / Add tunnel'
gtm_header 'HAProxy / Add tunnel'; gtm_step 2 3 'Remote server'
GTM_SERVER_INFO_READY=0; gtm_header Tools'''])
        self.assertEqual(rendered.count('LOOKUP_CALLED'), 2)
        self.assertEqual(rendered.count('Public v4 203.0.113.5'), 4)
        self.assertIn('STEP 2/3  Remote server', rendered)
        self.assertIn('Local v4  10.0.0.2', rendered)

    def pty_output(self, args):
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
            process = subprocess.Popen([BASH, *args], cwd=ROOT,
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
            return rendered
        finally:
            os.close(master)
            if slave is not None:
                os.close(slave)
