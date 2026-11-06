"""Generated artifacts and same-second ordering, tested in fresh Bash processes."""
import os
from pathlib import Path
import shlex
import tempfile
import unittest

from test_manager import ROOT, bash, record
from test_advanced import paths


class ReliabilityTests(unittest.TestCase):
    def test_generated_runner_initializes_range_and_dns_limits_in_a_fresh_process(self):
        with tempfile.TemporaryDirectory(dir=ROOT / '.work') as directory:
            folder = Path(directory)
            (folder / 'connections.tsv').write_text(record(port='2000-2999', targets='203.0.113.20:443@1') + '\n')
            result = bash(paths(folder) + r'''
GTM_RUNTIME=$GTM_CONFIG_DIR/apply.sh
systemctl() { :; }; gtm_root() { :; }
gtm_kernel_apply() { gtm_load_records && [[ $GTM_SPAN_MAX == 4096 && $GTM_DNS_MAX == 16 && $GTM_DNS_UNIT == gre-manager-dns ]]; }
gtm_install_runner || exit 10
env -i PATH="$PATH" bash "$GTM_RUNTIME" || exit 11
''')
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_same_second_history_and_pruning_use_actual_write_order(self):
        # Legacy names need a filesystem with subsecond mtimes; DrvFS may round
        # explicit utime calls to seconds. New points do not depend on mtimes.
        with tempfile.TemporaryDirectory() as directory:
            folder = Path(directory)
            backups = folder / 'backups'
            backups.mkdir()
            older = backups / '20261106T120000-900-32000.tsv'
            newer = backups / '20261106T120000-900-1.tsv'
            for file in (older, newer):
                file.write_text('# point\n')
            os.utime(older, ns=(1793966400000000000, 1793966400000000000))
            os.utime(newer, ns=(1793966400100000000, 1793966400100000000))
            result = bash(paths(folder) + 'gtm_history_points\nGTM_RESTORE_POINTS=1; gtm_prune_restore_points\n')
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertEqual(result.stdout.splitlines()[0], newer.as_posix())
            self.assertTrue(newer.exists())
            self.assertFalse(older.exists())

    def test_new_restore_point_order_survives_coarse_mtimes_and_a_clock_step(self):
        with tempfile.TemporaryDirectory(dir=ROOT / '.work') as directory:
            folder = Path(directory)
            result = bash(paths(folder) + r'''
printf '1793966400900000000\n' > "$GTM_CONFIG_DIR/restore-counter"
date() { if [[ $1 == +%s%N ]]; then printf '1793966400100000000\n'; else command date "$@"; fi; }
first=$(gtm_restore_point_path) || exit 10
second=$(gtm_restore_point_path) || exit 11
printf '# one\n' > "$first"; printf '# two\n' > "$second"
touch -t 202611061200.00 "$first" "$second"
[[ $first != "$second" && $(gtm_history_points | head -n 1) == "$second" ]] || exit 12
GTM_RESTORE_POINTS=1; gtm_prune_restore_points
[[ ! -e $first && -f $second ]] || exit 13
''')
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_nft_chain_uses_a_non_keyword_identifier_everywhere(self):
        result = bash('GTM_RECORDS=(' + shlex.quote(record()) + ')\ngtm_nft_render')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('add chain inet gre_manager gtm_mss {', result.stdout)
        self.assertIn('add rule inet gre_manager gtm_mss ', result.stdout)
        self.assertNotIn('inet gre_manager mss ', result.stdout)
        self.assertNotIn('inet gre_manager "mss" ', result.stdout)
