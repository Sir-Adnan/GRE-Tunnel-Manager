"""Release version copies stay aligned with src/core.sh."""
import importlib.util
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('gtm_build', ROOT / 'tools' / 'build.py')
build = importlib.util.module_from_spec(spec)
spec.loader.exec_module(build)


class ReleaseVersionTests(unittest.TestCase):
    def test_every_version_copy_matches_core(self):
        version = build.release_version()
        self.assertEqual(build.version_mismatches(version), [])
        self.assertTrue(build.build().startswith(f'#!/usr/bin/env bash\n# GRE / Traffic Manager v{version}\n'))

    def test_mismatch_is_reported_per_file(self):
        problems = build.version_mismatches('0.0.1')
        self.assertEqual(len(problems), len(build.VERSION_COPIES))
        self.assertTrue(all('expected 0.0.1' in problem for problem in problems))


if __name__ == '__main__':
    unittest.main()
