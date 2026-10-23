"""Paired resource guards use a temporary filesystem and fake service calls."""
import shlex
import tempfile
from pathlib import Path
import unittest
from test_manager import ROOT, bash, record


class PairAPITests(unittest.TestCase):
    def setUp(self):
        (ROOT / '.work').mkdir(exist_ok=True)
        self.tmp = tempfile.TemporaryDirectory(dir=ROOT / '.work')
        self.addCleanup(self.tmp.cleanup)
        self.path = Path(self.tmp.name)
        self.prefix = ('GTM_SERVICE_DIR='+shlex.quote(self.path.as_posix())+'; GTM_CONFIG_DIR=$GTM_SERVICE_DIR; GTM_RUN_DIR=$GTM_SERVICE_DIR\n'
                       'gtm_prepare() { :; }; gtm_lock() { :; }; gtm_unlock() { :; }; gtm_load_records() { GTM_RECORDS=(); }\n'
                       'gtm_local_address() { :; }; systemctl() { :; }; ip() { [[ $1 != link ]]; }; gtm_need() { :; }\n')

    def test_gre_revision_apply_and_fingerprint_guard(self):
        result = bash(self.prefix + 'rev=$(gtm_pair_api pair-check-gre 1 iran 198.51.100.2 192.0.2.1 1430) || exit 20\n'
                      'fp=$(gtm_pair_api pair-apply-gre "$rev" 1 iran 198.51.100.2 192.0.2.1 1430) || exit 21\n'
                      'gtm_pair_api pair-verify gre-tun-1 "$fp" || exit 22\n'
                      'printf "# operator edit\\n" >> "$GTM_SERVICE_DIR/gre-tun-1.service"\n'
                      'gtm_pair_api pair-delete gre-tun-1 "$fp" && exit 23\ntrue')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('# operator edit', (self.path/'gre-tun-1.service').read_text())

    def test_stale_preflight_and_existing_units_are_preserved(self):
        result = bash(self.prefix + 'rev=$(gtm_pair_api pair-check-gre 1 iran 198.51.100.2 192.0.2.1 1430) || exit 20\n'
                      'gtm_load_records() { GTM_RECORDS=('+shlex.quote(record())+'); }\n'
                      'gtm_pair_api pair-apply-gre "$rev" 1 iran 198.51.100.2 192.0.2.1 1430')
        self.assertEqual(result.returncode, 75)
        self.assertFalse((self.path/'gre-tun-1.service').exists())
        (self.path/'gre-tun-1.service').write_text('custom operator unit')
        result = bash(self.prefix + 'gtm_pair_api pair-check-gre 1 iran 198.51.100.2 192.0.2.1 1430')
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual((self.path/'gre-tun-1.service').read_text(), 'custom operator unit')

    def test_safe_removal_keeps_unrelated_files(self):
        (self.path/'unrelated.service').write_text('keep')
        result = bash(self.prefix + 'gtm_link_remove_guard() { :; }; gtm_link_delete() { rm -f "$GTM_SERVICE_DIR/gre-tun-$1.service"; }\n'
                      'rev=$(gtm_pair_api pair-check-gre 1 iran 198.51.100.2 192.0.2.1 1430) || exit 20\n'
                      'fp=$(gtm_pair_api pair-apply-gre "$rev" 1 iran 198.51.100.2 192.0.2.1 1430) || exit 21\n'
                      'gtm_pair_api pair-delete gre-tun-1 "$fp"')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse((self.path/'gre-tun-1.service').exists())
        self.assertEqual((self.path/'unrelated.service').read_text(), 'keep')

    def test_closed_frp_layout_and_service_ids(self):
        fields = ['frp','pair-example','destination','192.0.2.1','7000','443','127.0.0.1','8443','tcp','tcp','true','a'*32,'pair-example','-','-','0']
        result = bash('gtm_pair_frp_parse', '\t'.join(fields)+'\n')
        self.assertEqual(result.returncode, 0, result.stderr)
        for field, value in [(0,'rathole'),(9,'wss'),(14,'/etc/private.pem'),(1,'../escape')]:
            bad = fields.copy(); bad[field] = value
            self.assertNotEqual(bash('gtm_pair_frp_parse', '\t'.join(bad)+'\n').returncode, 0)
        self.assertNotEqual(bash('gtm_pair_service "../../sshd"').returncode, 0)

    def test_unowned_auxiliary_services_block_creation_and_compensation(self):
        keepalive = self.path/'gre-keepalive-1.service'
        keepalive.write_text('operator service')
        result = bash(self.prefix + 'gtm_pair_api pair-check-gre 1 iran 198.51.100.2 192.0.2.1 1430')
        self.assertNotEqual(result.returncode, 0)
        keepalive.unlink()
        result = bash(self.prefix + 'rev=$(gtm_pair_api pair-check-gre 1 iran 198.51.100.2 192.0.2.1 1430) || exit 20\n'
                      'fp=$(gtm_pair_api pair-apply-gre "$rev" 1 iran 198.51.100.2 192.0.2.1 1430) || exit 21\n'
                      'printf "operator service" > "$GTM_SERVICE_DIR/gre-keepalive-1.service"\n'
                      'gtm_pair_api pair-delete gre-tun-1 "$fp" && exit 22\ntrue')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(keepalive.read_text(), 'operator service')
        self.assertTrue((self.path/'gre-tun-1.service').exists())
        (self.path/'gtm-gateway-example.service').write_text('unrelated gateway')
        result = bash(self.prefix + 'gtm_pair_revision gtm-frp-entrance-example')
        self.assertNotEqual(result.returncode, 0)
