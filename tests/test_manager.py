"""Read-only Bash logic and generated configuration regression tests."""
import json
import ipaddress
import os
from pathlib import Path
import re
import shlex
import shutil
import subprocess
import tempfile
import tomllib
import unittest

ROOT = Path(__file__).resolve().parents[1]
BASH = os.environ.get('BASH_BIN') or (r'C:\Program Files\Git\bin\bash.exe' if os.name == 'nt' else shutil.which('bash'))


def bash(code, stdin=None):
    prefix = 'source ./gre.sh\ngtm_paths\nGTM_THEME=plain\nGTM_LANGUAGE=en\ngtm_palette\n'
    result = subprocess.run([BASH, '-c', prefix + code], cwd=ROOT,
                            input=None if stdin is None else stdin.encode('utf-8'), capture_output=True, timeout=20)
    result.stdout = result.stdout.decode('utf-8')
    result.stderr = result.stderr.decode('utf-8')
    return result


def record(engine='nftables', protocol='tcp', strategy='single', targets='203.0.113.20:443@1', **kw):
    values = dict(id='F000001', name='Example service', engine=engine, protocol=protocol,
                  bind='192.0.2.10', port='443', strategy=strategy, enabled='1',
                  snat='masquerade', interface='any', targets=targets, version='1')
    values.update(kw)
    return '\t'.join(values.values())


def render(engine, code, **kw):
    return bash('IFS= read -r line\ngtm_record_validate "$line" || exit 41\n' + code, record(engine, **kw) + '\n')


class ManagerTests(unittest.TestCase):
    def test_missing_default_state_is_new_but_explicit_or_bad_state_fails(self):
        (ROOT / '.work').mkdir(exist_ok=True)
        with tempfile.TemporaryDirectory(dir=ROOT / '.work') as directory:
            folder = Path(directory)
            result = bash('GTM_STATE='+shlex.quote((folder/'missing').as_posix())+'\n'
                          'gtm_load_records || exit 10\n'
                          'gtm_load_records "$GTM_STATE" && exit 11\n'
                          'GTM_STATE='+shlex.quote(folder.as_posix())+'\n'
                          'gtm_load_records && exit 12\ntrue')
            self.assertEqual(result.returncode, 0, result.stderr)

    def test_catalog_is_offline_and_distinguishes_planned_capabilities(self):
        result = bash('gtm_prepare() { exit 81; }; ip() { exit 82; }; systemctl() { exit 83; }\ngtm_main --catalog')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('rathole', result.stdout)
        self.assertIn('Planned / not implemented', result.stdout)
        self.assertIn('not HTTP CONNECT', result.stdout)

    def test_rathole_configs_are_authenticated_and_dual_protocol(self):
        for role, host, local_ip in [('entrance','2001:db8::1','::1'), ('destination','192.0.2.10','203.0.113.20')]:
            result = bash('RATH_ROLE='+role+'; RATH_HOST='+host+'; RATH_LOCAL_IP='+local_ip+'\n'
                          'RATH_NAME=example; RATH_CONTROL=2333; RATH_PUBLIC=443; RATH_LOCAL_PORT=8443\n'
                          'RATH_PROTO=both; RATH_TOKEN=abcdefghijklmnopqrstuvwx; RATH_KEY=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\n'
                          'gtm_rathole_render')
            self.assertEqual(result.returncode, 0, result.stderr)
            config = tomllib.loads(result.stdout)['server' if role == 'entrance' else 'client']
            self.assertEqual(config['transport']['type'], 'noise')
            self.assertEqual(config['transport']['noise']['pattern'], 'Noise_NK_25519_ChaChaPoly_BLAKE2s')
            self.assertIn('local_private_key' if role == 'entrance' else 'remote_public_key',config['transport']['noise'])
            self.assertEqual(set(config['services']), {'example_tcp','example_udp'})
            for proto in ['tcp','udp']:
                self.assertEqual(config['services']['example_'+proto]['type'],proto)
                self.assertEqual(config['services']['example_'+proto]['token'],'abcdefghijklmnopqrstuvwx')
            if role == 'entrance': self.assertEqual(config['bind_addr'],'[2001:db8::1]:2333')

    def test_rathole_validation_and_real_archive_version_format(self):
        result = bash('''
RATH_ROLE=destination; RATH_HOST=192.0.2.10; RATH_LOCAL_IP=203.0.113.20
RATH_NAME=example; RATH_CONTROL=2333; RATH_PUBLIC=443; RATH_LOCAL_PORT=8443
RATH_PROTO=tcp; RATH_TOKEN=abcdefghijklmnopqrstuvwx; RATH_KEY=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
gtm_rathole_validate || exit 10
RATH_NAME='../bad'; gtm_rathole_validate && exit 11; RATH_NAME=example
RATH_KEY='bad'; gtm_rathole_validate && exit 12; RATH_KEY=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
RATH_TOKEN='$(id)'; gtm_rathole_validate && exit 13; RATH_TOKEN=abcdefghijklmnopqrstuvwx
RATH_LOCAL_IP=$RATH_HOST; RATH_LOCAL_PORT=$RATH_PUBLIC; gtm_rathole_validate && exit 14
rathole() { printf 'rathole \\nBuild Version: 0.5.0\\nCommit SHA: test\\n'; }
gtm_rathole_binary || exit 15
rathole() { printf 'rathole 9.0.0\\n'; }; gtm_rathole_binary && exit 16
true
''')
        self.assertEqual(result.returncode,0,result.stderr)

    def test_reverse_listeners_reject_enabled_kernel_reservations(self):
        with tempfile.TemporaryDirectory(dir=ROOT / '.work') as directory:
            source = Path(directory)/'state.tsv'
            source.write_text(record()+'\n',newline='\n')
            result = bash('GTM_STATE='+shlex.quote(source.as_posix())+'\n'+'''
gtm_listener_check() { :; }; gtm_legacy_listener_check() { :; }
gtm_port_available tcp 192.0.2.10 443 && exit 10
gtm_port_available tcp 192.0.2.11 443 || exit 11
gtm_port_available udp 192.0.2.10 443 || exit 12
''')
            self.assertEqual(result.returncode,0,result.stderr)

    def test_rathole_new_instance_failure_cleans_up_only_owned_files(self):
        with tempfile.TemporaryDirectory(dir=ROOT / '.work') as directory:
            folder = Path(directory)
            (folder/'keep.service').write_text('unrelated')
            result = bash('GTM_CONFIG_DIR='+shlex.quote(folder.as_posix())+'; GTM_SERVICE_DIR=$GTM_CONFIG_DIR; GTM_RUN_DIR=$GTM_CONFIG_DIR\n'+'''
RATH_ROLE=destination; RATH_HOST=192.0.2.10; RATH_LOCAL_IP=203.0.113.20
RATH_NAME=example; RATH_CONTROL=2333; RATH_PUBLIC=443; RATH_LOCAL_PORT=8443
RATH_PROTO=tcp; RATH_TOKEN=abcdefghijklmnopqrstuvwx; RATH_KEY=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
rathole() { :; }; gtm_rathole_binary() { :; }
systemctl() { [[ $1 != enable ]]; }
gtm_rathole_create && exit 10
[[ ! -e $GTM_CONFIG_DIR/gtm-rathole-destination-example.toml ]] || exit 11
[[ ! -e $GTM_SERVICE_DIR/gtm-rathole-destination-example.service ]] || exit 12
[[ -e $GTM_SERVICE_DIR/keep.service ]] || exit 13
gtm_rathole_cleanup '../keep' && exit 14
true
''')
            self.assertEqual(result.returncode,0,result.stderr)

    def test_rathole_existing_name_is_never_overwritten(self):
        with tempfile.TemporaryDirectory(dir=ROOT / '.work') as directory:
            folder = Path(directory)
            config = folder/'gtm-rathole-entrance-example.toml'
            config.write_text('keep this key')
            result = bash('GTM_CONFIG_DIR='+shlex.quote(folder.as_posix())+'; GTM_SERVICE_DIR=$GTM_CONFIG_DIR\n'
                          'RATH_ROLE=entrance; RATH_NAME=example\n'
                          'systemctl() { exit 90; }; gtm_rathole_create')
            self.assertNotEqual(result.returncode,0)
            self.assertEqual(config.read_text(),'keep this key')

    def test_build_is_current(self):
        result = subprocess.run([shutil.which('python3') or shutil.which('python'), 'tools/build.py', '--check'], cwd=ROOT, capture_output=True)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_semantic_manager_version(self):
        result=bash('gtm_main --version')
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertEqual(result.stdout.strip(),'v1.2.0')

    def test_deleted_connection_ids_are_not_reused(self):
        (ROOT / '.work').mkdir(exist_ok=True)
        with tempfile.TemporaryDirectory(dir=ROOT / '.work') as directory:
            folder=Path(directory)
            (folder/'id-counter').write_text('11\n',newline='\n')
            result=bash('GTM_CONFIG_DIR='+shlex.quote(folder.as_posix())+'; GTM_RECORDS=(); gtm_new_id')
            self.assertEqual(result.returncode,0,result.stderr)
            self.assertEqual(result.stdout,'F000012')

    def test_shell_syntax(self):
        for path in [ROOT / 'gre.sh', *sorted((ROOT / 'src').glob('*.sh'))]:
            result = subprocess.run([BASH, '-n'], input=path.read_bytes(), capture_output=True)
            self.assertEqual(result.returncode, 0, (path, result.stderr))

    def test_embedded_shell_syntax(self):
        source = (ROOT / 'gre.sh').read_text(encoding='utf-8')
        for body in re.findall(r"cat <<'?EOF'?[^\n]*\n(.*?)^EOF$", source, re.M | re.S):
            if body.startswith('#!/bin/bash') or body.startswith('# Tunnel Setup'):
                result = subprocess.run([BASH, '-n'], input=body.encode(), capture_output=True)
                self.assertEqual(result.returncode, 0, result.stderr)

    def test_ports_overflow_and_shell_input_rejected(self):
        result = bash('for value in 0 65536 18446744073709551617 "1;id" "$(printf nope)" -1; do gtm_port "$value" && exit 9; done\ngtm_port 00080 && gtm_port 65535')
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_ip_validation_is_not_a_route_probe(self):
        result = bash('ip() { return 99; }; for ip in 0.0.0.0 192.0.2.1 ::1 fd00::10 2001:db8:0:0:0:0:0:1; do gtm_ip "$ip" || exit 8; done\nfor ip in 010.0.0.1 256.0.0.1 :1 1: 1::2::3 ::: ::ffff:192.0.2.1; do gtm_ip "$ip" && exit 9; done\ntrue')
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_selection_checks_boundaries_and_deduplicates(self):
        result = bash('gtm_selection "1 3 1" 3 || exit 1\nprintf "%s\\n" "${GTM_SELECTED[*]}"\nfor bad in 0 4 18446744073709551616 a "1;id"; do gtm_selection "$bad" 3 && exit 2; done\ntrue')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.strip(), '0 2')

    def test_invalid_record_cannot_reach_renderer(self):
        for value in [record(name='$(id)'), record(protocol='icmp'), record(engine='eval'),
                      record(engine='haproxy', protocol='udp'), record(strategy='leastconn'),
                      record(targets='203.0.113.20:443@0'), record(bind='0.0.0.0'), record(version='2'),
                      record(engine='haproxy', strategy='random'),
                      record(bind='0:0:0:0:0:0:0:0',targets='[2001:db8::2]:443'),
                      record(bind='192.0.2.10', targets='192.0.2.10:443'),
                      record(strategy='random', targets='203.0.113.20:443@1,203.0.113.20:0443@2')]:
            result = bash('IFS= read -r row\ngtm_record_validate "$row"', value+'\n')
            self.assertNotEqual(result.returncode, 0, value)

    def test_ipv6_keys_match_standard_library(self):
        addresses=['::', '::1', 'fd00:10::2', '2001:DB8:0:0:0:1:0:0', 'ffff::abcd',
                   '1:2:3:4:5:6:7:8', '1::', '::0001:00AB']
        addresses += [str(ipaddress.IPv6Address(n)) for n in [1, 65536, 2**64, 2**127, 2**128-1]]
        for address in addresses:
            result=bash('gtm_ip_key '+shlex.quote(address))
            self.assertEqual(result.returncode,0,result.stderr)
            self.assertEqual(result.stdout,ipaddress.IPv6Address(address).packed.hex())

    def test_equivalent_ipv6_listeners_and_targets_are_rejected(self):
        first=record(bind='2001:db8::1',targets='[2001:db8::2]:443')
        second=record(id='F000002',bind='2001:0DB8:0:0:0:0:0:1',targets='[2001:db8::3]:443')
        result=bash('gtm_load_records <(cat)',first+'\n'+second+'\n')
        self.assertNotEqual(result.returncode,0)
        for targets in ['[2001:0db8:0:0:0:0:0:1]:443',
                        '[2001:db8::2]:443,[2001:0DB8:0:0:0:0:0:2]:443@2']:
            result=bash('IFS= read -r row; gtm_record_validate "$row"',record(bind='2001:db8::1',strategy='random',targets=targets)+'\n')
            self.assertNotEqual(result.returncode,0)

    def test_relays_cannot_hide_conflicts_behind_interfaces(self):
        rows=[record(engine='realm',interface='eth0'),record(engine='haproxy',id='F000002',interface='eth1')]
        result=bash('gtm_load_records <(cat)','\n'.join(rows)+'\n')
        self.assertNotEqual(result.returncode,0)

    def test_offline_cli_validates_and_previews_without_mutations(self):
        code=r'''
gtm_prepare() { exit 81; }; gtm_lock() { exit 82; }; gtm_preflight() { exit 83; }
systemctl() { exit 84; }; nft() { exit 85; }; iptables() { exit 86; }
'''
        (ROOT / '.work').mkdir(exist_ok=True)
        with tempfile.TemporaryDirectory(dir=ROOT / '.work') as directory:
            state=Path(directory)/'state.tsv'; state.write_text(record()+'\n',newline='\n')
            previous=state.read_bytes()
            for action in ['--validate','--plan']:
                result=bash(code+'gtm_main '+action+' --state-file '+shlex.quote(state.as_posix()))
                self.assertEqual(result.returncode,0,result.stderr)
                self.assertEqual(state.read_bytes(),previous)
                if action == '--plan':
                    self.assertIn('nothing applied',result.stdout)
                    self.assertIn('add table inet gre_manager',result.stdout)
        result=bash('gtm_main --validate --state-file missing-state-file')
        self.assertNotEqual(result.returncode,0)
        result=bash('gtm_main --plan --doctor')
        self.assertEqual(result.returncode,2)

    def test_link_dependencies_include_disabled_and_ipv6_records(self):
        rows=[record(targets='10.0.10.2:443',enabled='0'),
              record(id='F000002',bind='2001:db8::1',targets='[FD00:0010:0:0::2]:443'),
              record(id='F000003',port='8443',interface='gre-out-10'),
              record(id='F000004',port='10443',targets='10.0.100.2:443')]
        code='IFS= read -r -d "" rows || :\ngtm_load_records() { mapfile -t GTM_RECORDS <<< "$rows"; }; gtm_link_dependents 10 || exit; printf "%s\\n" "${GTM_DEPENDENTS[@]}"'
        result=bash(code,'\n'.join(rows))
        self.assertEqual(result.returncode,0,result.stderr)
        for connection_id in ['F000001','F000002','F000003']: self.assertIn(connection_id,result.stdout)
        self.assertNotIn('F000004',result.stdout)

    def test_stale_edit_is_rejected_without_losing_other_changes(self):
        code=r'''
IFS= read -r expected; IFS= read -r changed; IFS= read -r replacement
GTM_RECORDS=("$changed")
gtm_replace_record "$expected" "$replacement" && exit 9
[[ ${GTM_RECORDS[0]} == "$changed" ]] || exit 10
gtm_replace_record "$changed" "$replacement" || exit 11
[[ ${GTM_RECORDS[0]} == "$replacement" ]]
'''
        result=bash(code,'\n'.join([record(),record(name='Other session'),record(name='My edit',enabled='0')])+'\n')
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertIn('another session',result.stderr)

    def test_wizard_edit_preserves_disabled_and_source_settings(self):
        code=r'''
IFS= read -r saved
gtm_records() { GTM_RECORDS=("$saved"); }; gtm_load_records() { gtm_records; }
gtm_prepare() { :; }; gtm_lock() { :; }; gtm_unlock() { :; }
gtm_install_component() { :; }; gtm_legacy_listener_check() { :; }; gtm_confirm() { :; }
gtm_commit() { printf 'FINAL:%s\n' "${GTM_RECORDS[0]}"; }
gtm_new_forward nftables F000001
'''
        original=record(enabled='0',snat='preserve')
        result=bash(code,original+'\n'+'\n'*7)
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertIn('FINAL:'+original,result.stdout)

    def test_local_listener_check_respects_bind_address_and_wildcards(self):
        code=r'''
IFS= read -r listener
ss() { printf '%s\n' "$listener"; }
gtm_listener_check tcp 192.0.2.10 443
'''
        for address, expected in [('127.0.0.1',0),('192.0.2.10',1),('0.0.0.0',1),('*',1),('[::]',1)]:
            result=bash(code,f'LISTEN 0 4096 {address}:443 0.0.0.0:*\n')
            self.assertEqual(result.returncode,expected,(address,result.stderr))

    def test_nft_owns_only_its_table_and_scopes_snat(self):
        result = render('nftables', 'GTM_RECORDS=("$line"); gtm_nft_render', protocol='both', strategy='random', targets='203.0.113.20:443@2,203.0.113.21:8443@1')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertNotIn('flush ruleset', result.stdout)
        self.assertIn('flush table inet gre_manager', result.stdout)
        self.assertIn('numgen random mod 3 vmap', result.stdout)
        self.assertIn('ct original ip daddr 192.0.2.10', result.stdout)
        self.assertIn('meta l4proto udp dnat ip to 203.0.113.21:8443', result.stdout)

    def test_disabled_forward_has_no_rules(self):
        result = render('nftables', 'GTM_RECORDS=("$line"); gtm_nft_render', enabled='0')
        self.assertEqual(result.returncode, 0)
        self.assertNotIn('203.0.113.20', result.stdout)

    def test_iptables_probability_preserves_weight_and_groups(self):
        result = render('iptables', 'GTM_RECORDS=("$line"); gtm_iptables_render 4 nat', strategy='random', targets='203.0.113.20:443@3,203.0.113.21:443@1')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('--probability 0.7500000000', result.stdout)
        self.assertEqual(result.stdout.count(' -j DNAT '), 2)
        self.assertIn('--ctorigdst 192.0.2.10 --ctorigdstport 443', result.stdout)

    def test_realm_config_has_real_endpoints_and_logging(self):
        result = render('realm', 'gtm_realm_render', protocol='both', strategy='roundrobin', targets='203.0.113.20:443@2,[2001:db8::1]:8443@1')
        self.assertEqual(result.returncode, 0, result.stderr)
        parsed = tomllib.loads(result.stdout)
        self.assertEqual(parsed['log']['level'], 'warn')
        self.assertTrue(parsed['network']['use_udp'])
        self.assertFalse(parsed['network']['no_tcp'])
        self.assertEqual(parsed['endpoints'][0]['balance'], 'roundrobin: 2, 1')
        self.assertEqual(parsed['endpoints'][0]['extra_remotes'], ['[2001:db8::1]:8443'])

    def test_haproxy_failover_and_checks(self):
        result = render('haproxy', 'gtm_haproxy_render', strategy='failover', targets='203.0.113.20:443@1,203.0.113.21:443@1')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('mode tcp', result.stdout)
        self.assertIn('target1 203.0.113.20:443 weight 1 check', result.stdout)
        self.assertIn('target2 203.0.113.21:443 weight 1 check inter 3s fall 3 rise 2 backup', result.stdout)

    def test_frp_transports_have_valid_toml_and_authenticated_sides(self):
        for role in ['entrance', 'destination']:
            for transport in ['tcp', 'websocket', 'wss', 'quic']:
                result = bash(f'P_ROLE={role}; P_NAME=site-a; P_HOST=192.0.2.10; P_CONTROL=7000; P_PUBLIC=443; P_LOCAL_IP=127.0.0.1; P_LOCAL_PORT=8443; P_TRANSPORT={transport}; P_PROTO=tcp; P_MUX=true; P_TOKEN=abcdefghijklmnopqrstuvwx; P_GROUP=sites; P_INTERNAL=7001; P_GATEWAY_CERT=/etc/ssl/site.pem; P_TLS_CA=/etc/ssl/site.crt; gtm_frp_render')
                self.assertEqual(result.returncode, 0, result.stderr)
                parsed = tomllib.loads(result.stdout)
                self.assertEqual(parsed['auth']['method'], 'token')
                self.assertEqual(parsed['log']['to'], 'console')
                if role == 'destination':
                    self.assertEqual(parsed['transport']['protocol'], transport)
                    self.assertTrue(parsed['transport']['tls']['enable'])
                    self.assertEqual(parsed['proxies'][0]['loadBalancer']['group'], 'sites')
                else:
                    self.assertEqual(parsed['allowPorts'], [{'single':443}])

    def test_duplicate_listener_is_rejected_before_mutation(self):
        with tempfile.TemporaryDirectory(dir=ROOT / '.work') as directory:
            source = Path(directory) / 'connections.tsv'
            source.write_text(record()+'\n'+record(id='F000002',engine='realm')+'\n', newline='\n')
            result = bash('gtm_load_records '+shlex.quote(source.as_posix()))
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('Listener conflicts', result.stderr)

    def test_demo_does_not_mutate_server(self):
        result = bash('GTM_DEMO=1; gtm_prepare')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('Demo mode', result.stderr)

    def test_languages_and_terminal_ascii(self):
        for lang in ['en','finglish','fa']:
            result = subprocess.run([BASH,'gre.sh','--preview','home','--language',lang,'--theme','plain'],cwd=ROOT,capture_output=True,text=True,encoding='utf-8')
            self.assertEqual(result.returncode,0,result.stderr)
            self.assertNotIn('\x1b',result.stdout)
            if lang != 'fa': self.assertTrue(result.stdout.isascii())
            else: self.assertIn('مدیریت', result.stdout)

    def test_prefs_are_data_not_shell(self):
        result = bash('GTM_PREFS=<(printf "language\\tfa\\ntheme\\tplain\\ninvalid\\t\\$(exit 8)\\n") gtm_preferences; [[ $GTM_LANGUAGE == fa && $GTM_THEME == plain ]]')
        self.assertEqual(result.returncode,0,result.stderr)

    def test_failed_apply_restores_previous_state(self):
        (ROOT / '.work').mkdir(exist_ok=True)
        with tempfile.TemporaryDirectory(dir=ROOT / '.work') as directory:
            folder=Path(directory)
            (folder/'backups').mkdir()
            state=folder/'connections.tsv'
            previous=record(name='Previous')+'\n'
            state.write_text(previous,encoding='utf-8',newline='\n')
            result=bash('GTM_CONFIG_DIR='+shlex.quote(folder.as_posix())+'; gtm_paths\n'
                        'gtm_preflight() { return 0; }\n'
                        'gtm_install_runner() { return 0; }\n'
                        'gtm_kernel_apply() { gtm_load_records || return; [[ ${GTM_RECORDS[0]} == *Previous* ]]; }\n'
                        'gtm_relays_apply() { return 0; }\n'
                        'IFS= read -r row; GTM_RECORDS=("$row"); gtm_commit',record(name='Replacement')+'\n')
            self.assertNotEqual(result.returncode,0)
            self.assertEqual(state.read_text(encoding='utf-8'),previous)
            self.assertEqual(len(list((folder/'backups').glob('*.tsv'))),1)

    def test_preflight_failure_keeps_state_and_skips_apply(self):
        (ROOT / '.work').mkdir(exist_ok=True)
        with tempfile.TemporaryDirectory(dir=ROOT / '.work') as directory:
            folder=Path(directory); (folder/'backups').mkdir()
            previous=record(name='Previous')+'\n'
            state=folder/'connections.tsv'; state.write_text(previous,newline='\n')
            code='GTM_CONFIG_DIR='+shlex.quote(folder.as_posix())+'; gtm_paths\n'+r'''
gtm_preflight() { return 1; }
gtm_install_runner() { exit 91; }; gtm_kernel_apply() { exit 92; }; gtm_relays_apply() { exit 93; }
IFS= read -r row; GTM_RECORDS=("$row"); gtm_commit
'''
            result=bash(code,record(name='Replacement')+'\n')
            self.assertEqual(result.returncode,1,result.stderr)
            self.assertEqual(state.read_text(),previous)
            self.assertEqual(sorted(p.name for p in folder.iterdir()),['backups','connections.tsv'])

    def test_relay_recovery_is_attempted_even_when_kernel_recovery_fails(self):
        (ROOT / '.work').mkdir(exist_ok=True)
        with tempfile.TemporaryDirectory(dir=ROOT / '.work') as directory:
            folder=Path(directory); (folder/'backups').mkdir()
            previous=record(name='Previous')+'\n'
            state=folder/'connections.tsv'; state.write_text(previous,newline='\n')
            code='GTM_CONFIG_DIR='+shlex.quote(folder.as_posix())+'; gtm_paths\n'+r'''
gtm_preflight() { :; }; gtm_install_runner() { :; }
gtm_kernel_apply() { return 1; }
gtm_relays_apply() { [[ ${GTM_RECORDS[0]} == *Previous* ]] || return 1; printf 'restored\n' > "$GTM_CONFIG_DIR/relay-recovery"; }
IFS= read -r row; GTM_RECORDS=("$row"); gtm_commit
'''
            result=bash(code,record(name='Replacement')+'\n')
            self.assertEqual(result.returncode,1,result.stderr)
            self.assertEqual(state.read_text(),previous)
            self.assertEqual((folder/'relay-recovery').read_text(),'restored\n')
            self.assertIn('Recovery needs attention',result.stderr)

    def test_repeated_legacy_realm_delete_keeps_remaining_endpoint(self):
        (ROOT / '.work').mkdir(exist_ok=True)
        with tempfile.TemporaryDirectory(dir=ROOT / '.work') as directory:
            config=Path(directory)/'realm.toml'
            config.write_text('[network]\nno_tcp = false\nuse_udp = true\n\n'+''.join(
                f'\n[[endpoints]]\nlisten = "0.0.0.0:{port}"\nremote = "192.0.2.1:443"\n'
                for port in [1001,1002,1003]),encoding='utf-8',newline='\n')
            result=bash('REALM_CONFIG_FILE='+shlex.quote(config.as_posix())+'\n'
                        'realm_apply_config() { return 0; }; realm_backup_config() { return 0; }\n'
                        'realm_delete_relay; realm_delete_relay','0\n0\n')
            self.assertEqual(result.returncode,0,result.stderr)
            remaining=tomllib.loads(config.read_text())['endpoints']
            self.assertEqual([r['listen'] for r in remaining],['0.0.0.0:1003'])

    def test_legacy_group_removal_preserves_other_groups_and_shared_rules(self):
        (ROOT / '.work').mkdir(exist_ok=True)
        with tempfile.TemporaryDirectory(dir=ROOT / '.work') as directory:
            folder=Path(directory); (folder/'backups').mkdir()
            file=folder/'rules.sh'
            dnat='iptables -t nat -A PREROUTING -p tcp --dport 443 -j DNAT --to-destination 10.0.10.1:443'
            other=dnat.replace('--dport 443','--dport 8443')
            snat='iptables -t nat -A POSTROUTING -d 10.0.10.1 -p tcp --dport 443 -j MASQUERADE'
            manual='echo untouched-manual-line'
            file.write_text('#!/bin/bash\n'+ '\n'.join([dnat,dnat,other,snat,manual])+'\n',newline='\n')
            code='GTM_CONFIG_DIR='+shlex.quote(folder.as_posix())+'; FW_SCRIPT='+shlex.quote(file.as_posix())+'\n'+r'''
declare -A counts=()
while IFS= read -r item; do [[ $item == iptables* ]] || continue; counts["$item"]=$(( ${counts["$item"]:-0}+1 )); done < "$FW_SCRIPT"
iptables() {
    [[ $* != '-t nat -S PREROUTING' ]] || return 0
    local key="iptables $*"
    key=${key/-C /-A }; key=${key/-D /-A }
    if [[ " $* " == *' -C '* ]]; then (( ${counts["$key"]:-0}>0 )); return; fi
    if [[ " $* " == *' -D '* ]]; then (( ${counts["$key"]:-0}>0 )) || return 1; counts["$key"]=$((counts["$key"]-1)); return 0; fi
    return 1
}
gtm_confirm() { return 0; }
gtm_legacy_delete_group
for k in "${!counts[@]}"; do [[ $k != *'--dport 443 -j DNAT'* ]] || [[ ${counts[$k]} == 0 ]] || exit 8; done
'''
            result=bash(code,'1\n')
            self.assertEqual(result.returncode,0,result.stderr)
            remaining=file.read_text()
            self.assertNotIn(dnat+'\n',remaining)
            self.assertIn(other,remaining)
            self.assertIn(snat,remaining)
            self.assertIn(manual,remaining)


if __name__ == '__main__':
    unittest.main(verbosity=2)
