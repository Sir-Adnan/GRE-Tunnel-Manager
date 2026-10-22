"""Noninteractive web/CLI boundary regressions without host mutation."""
import shlex
import tempfile
from pathlib import Path
import unittest
from test_manager import ROOT, bash, record


class APITests(unittest.TestCase):
    def test_readonly_state_never_installs_or_calls_network(self):
        with tempfile.TemporaryDirectory(dir=ROOT/'.work') as directory:
            path=Path(directory)/'connections.tsv'
            path.write_text(record()+'\n',encoding='utf-8',newline='\n')
            result=bash('GTM_STATE='+shlex.quote(path.as_posix())+'\n'
                        'gtm_prepare() { exit 90; }; ip() { exit 91; }; systemctl() { exit 92; }\n'
                        'gtm_api state')
            self.assertEqual(result.returncode,0,result.stderr)
            self.assertEqual(result.stdout.strip(),record())

    def test_stale_bulk_selection_does_not_commit(self):
        old=record(engine='realm')
        result=bash('gtm_prepare() { :; }; gtm_lock() { :; }; gtm_unlock() { :; }\n'
                    'gtm_load_records() { GTM_RECORDS=('+shlex.quote(old)+'); }\n'
                    'gtm_commit() { echo BAD_COMMIT; }\n'
                    'gtm_api_change delete', old.replace('Example service','Changed service')+'\n')
        self.assertNotEqual(result.returncode,0)
        self.assertNotIn('BAD_COMMIT',result.stdout)

    def test_delete_preserves_other_engines_and_realm_options(self):
        first=record(engine='haproxy')
        second=record(engine='realm',id='F000002',port='444',version='3')+'\tudp_timeout=60;send_proxy=false'
        result=bash('gtm_prepare() { :; }; gtm_lock() { :; }; gtm_unlock() { :; }\n'
                    'gtm_load_records() { GTM_RECORDS=('+shlex.quote(first)+' '+shlex.quote(second)+'); }\n'
                    'gtm_commit() { printf "%s\\n" "${GTM_RECORDS[@]}"; }\n'
                    'gtm_api_change delete', first+'\n')
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertEqual(result.stdout.strip(),second)

    def test_realm_v3_rendering_and_injection_rejection(self):
        line=record(engine='realm',protocol='both',version='3')+'\tudp_timeout=60;tcp_keepalive=30;accept_proxy=true;log=error'
        result=bash('IFS= read -r line\ngtm_record_validate "$line" && gtm_realm_render',line+'\n')
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertIn('udp_timeout = 60',result.stdout)
        self.assertIn('accept_proxy = true',result.stdout)
        self.assertIn('level = "error"',result.stdout)
        for option in ['udp_timeout=0','log=$(id)','accept_proxy=yes','send_proxy_version=3','raw=exec','udp_timeout=60;udp_timeout=70']:
            result=bash('IFS= read -r line\ngtm_record_validate "$line"',record(engine='realm',version='3')+'\t'+option+'\n')
            self.assertNotEqual(result.returncode,0,option)

    def test_gre_creation_validates_and_keeps_wire_contract(self):
        with tempfile.TemporaryDirectory(dir=ROOT/'.work') as directory:
            path=Path(directory)
            result=bash('GTM_SERVICE_DIR='+shlex.quote(path.as_posix())+'; GTM_RUN_DIR=$GTM_SERVICE_DIR\n'
                        'gtm_local_address() { :; }; systemctl() { :; }; ip() { return 1; }\n'
                        'gtm_link_create 10 iran 203.0.113.20 192.0.2.10 1430\n')
            self.assertEqual(result.returncode,0,result.stderr)
            text=(path/'gre-tun-10.service').read_text()
            self.assertIn('key 10',text)
            self.assertIn('10.0.10.2/30',text)
            self.assertIn('fd00:10::2/64',text)
            self.assertIn('gre-out-10',text)
            before=text
            result=bash('GTM_SERVICE_DIR='+shlex.quote(path.as_posix())+'; GTM_RUN_DIR=$GTM_SERVICE_DIR\n'
                        'gtm_local_address() { :; }; systemctl() { :; }; ip() { return 1; }\n'
                        'gtm_link_create 10 iran 203.0.113.30 192.0.2.10 1430\n')
            self.assertNotEqual(result.returncode,0)
            self.assertEqual((path/'gre-tun-10.service').read_text(),before)
