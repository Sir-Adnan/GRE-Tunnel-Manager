"""Closed routing, native Realm profiles and locked display metadata."""
from pathlib import Path
import shlex
import tempfile
import tomllib
import unittest

from test_manager import ROOT, bash, record

(ROOT / ".work").mkdir(exist_ok=True)


class Phase5ManagementTests(unittest.TestCase):
    def test_haproxy_affinity_is_bounded_optional_and_roundtrips(self):
        row = record(engine='haproxy', strategy='roundrobin', targets='203.0.113.20:443@1,203.0.113.21:443@1', version='2')
        result = bash('IFS= read -r row\ngtm_record_validate "$row" || exit 1\n'
                      'gtm_haproxy_render\ngtm_haproxy_options', row+'\tstick=source;stick_size=2048;stick_expire=120\n')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('stick-table type ipv6 size 2048 expire 120s', result.stdout)
        self.assertIn('stick on src', result.stdout)
        for options in ['stick=source;stick_size=999999', 'stick=source;stick_expire=0', 'stick=source;stick_size=1', 'stick=shell']:
            result = bash('IFS= read -r row\ngtm_record_validate "$row"', row+'\t'+options+'\n')
            self.assertNotEqual(result.returncode, 0, options)
    def test_routing_v4_roundtrip_and_injection_rejection(self):
        base = record(engine='haproxy', strategy='roundrobin',
                      targets='203.0.113.20:443@1,203.0.113.21:443@1', version='4')
        row = base + '\tconnect=5\t1|sni|-|vpn.example.com~-~2'
        result = bash('IFS= read -r row\ngtm_record_validate "$row" || exit 1\n'
                      'emitted=$(gtm_record_emit); [[ $emitted == "$row" ]] || exit 2\n'
                      'gtm_haproxy_render', row + '\n')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('req.ssl_sni -i vpn.example.com', result.stdout)
        self.assertIn('backend route1\n    server target2 203.0.113.21:443', result.stdout)
        for routing in ['1|http|-|bad;host~-~1', '1|https|../../etc/passwd|-',
                        '1|sni|-|example.com~/path~1', '1|http|-|example.com~-~3',
                        '1|http|-|example.com~-~1,example.com~-~2']:
            result = bash('IFS= read -r row\ngtm_record_validate "$row"', base+'\tconnect=5\t'+routing+'\n')
            self.assertNotEqual(result.returncode, 0, routing)

    def test_realm_native_ws_mptcp_grammar_and_feature_guards(self):
        row = record(engine='realm', version='3') + '\tremote_transport=ws;ws_host=relay.test;ws_path=/relay;send_mptcp=true'
        result = bash('IFS= read -r row\ngtm_record_validate "$row" || exit 1\ngtm_realm_render', row+'\n')
        self.assertEqual(result.returncode, 0, result.stderr)
        config = tomllib.loads(result.stdout)
        self.assertTrue(config['network']['send_mptcp'])
        self.assertEqual(config['endpoints'][0]['remote_transport'], 'ws;host=relay.test;path=/relay')
        for version in ['Realm 2.9.6 [transport]', 'realm 2.9.6 [transport]']:
            result = bash('gtm_realm_defaults; M_REMOTE_TRANSPORT=ws\n'
                          'realm() { printf "%s" '+shlex.quote(version)+'; }\ngtm_realm_profile_preflight')
            self.assertEqual(result.returncode, 0, result.stderr)
        for version in ['Realm 2.9.6 [proxy]', 'Realm 2.9.60 [transport]', 'Realm 2.8.0 [transport]']:
            result = bash('gtm_realm_defaults; M_REMOTE_TRANSPORT=ws\n'
                          'realm() { printf "%s" '+shlex.quote(version)+'; }\ngtm_realm_profile_preflight')
            self.assertNotEqual(result.returncode, 0, version)
        result = bash('gtm_realm_defaults; M_SEND_MPTCP=true\nrealm() { echo "Realm 2.9.6 [transport]"; }; sysctl() { echo 0; }; gtm_realm_profile_preflight')
        self.assertNotEqual(result.returncode, 0)

    def test_metadata_cas_preserves_other_records_and_technical_units(self):
        with tempfile.TemporaryDirectory(dir=ROOT/'.work') as directory:
            folder = Path(directory)
            for n in [1, 2]:
                (folder/f'gre-tun-{n}.service').write_text(f'[Unit]\nDescription=GRE {n}\n')
            result = bash('GTM_CONFIG_DIR='+shlex.quote(folder.as_posix())+'\nGTM_SERVICE_DIR=$GTM_CONFIG_DIR\n'+r'''
hash1=$(sha256sum "$GTM_SERVICE_DIR/gre-tun-1.service"); hash1=${hash1%% *}
hash2=$(sha256sum "$GTM_SERVICE_DIR/gre-tun-2.service"); hash2=${hash2%% *}
gtm_metadata_rename gre-tun-1 "$hash1:-" "Customer A" || exit 1
gtm_metadata_rename gre-tun-2 "$hash2:-" "Customer B" || exit 2
if gtm_metadata_rename gre-tun-1 "$hash1:-" Stale; then exit 3; fi
gtm_metadata_load || exit 4
[[ ${#GTM_METADATA[@]} == 2 ]] || exit 5
gtm_metadata_forget gre-tun-1 || exit 6
gtm_metadata_load || exit 7
[[ ${#GTM_METADATA[@]} == 1 && ${GTM_METADATA[0]} == *"Customer B" ]] || exit 8
''')
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual((folder/'gre-tun-1.service').read_text(), '[Unit]\nDescription=GRE 1\n')
            self.assertTrue((folder/'resource-names.tsv.bak').is_file())

    def test_nft_selectors_are_scoped_and_iptables_rejects_hash(self):
        for strategy, selector in [('roundrobin', 'numgen inc'), ('source', 'jhash ip saddr')]:
            row = record(strategy=strategy, targets='203.0.113.20:443@2,203.0.113.21:8443@1')
            result = bash('IFS= read -r row\nGTM_RECORDS=("$row")\ngtm_nft_render', row+'\n')
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn(selector, result.stdout)
            self.assertNotIn('flush ruleset', result.stdout)
        result = bash('IFS= read -r row\ngtm_record_validate "$row"', record(engine='iptables', strategy='source')+'\n')
        self.assertNotEqual(result.returncode, 0)
