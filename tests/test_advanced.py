"""HAProxy lifecycle, closed legacy cleanup and journaled tuning regressions."""
from pathlib import Path
import shlex
import tempfile
import unittest

from test_manager import ROOT, bash, record

(ROOT / '.work').mkdir(exist_ok=True)


def paths(folder):
    return ('GTM_CONFIG_DIR='+shlex.quote(folder.as_posix())+'\n'
            'GTM_SERVICE_DIR=$GTM_CONFIG_DIR; GTM_RUN_DIR=$GTM_CONFIG_DIR; GTM_SYSCTL_DIR=$GTM_CONFIG_DIR\n'
            'gtm_paths\nmkdir -p "$GTM_CONFIG_DIR/backups"\n'
            'SYSCTL_FILE=$GTM_CONFIG_DIR/old-tcp.conf; PERF_SYSCTL_FILE=$GTM_CONFIG_DIR/old-capacity.conf\n'
            'PERF_MODULES_FILE=$GTM_CONFIG_DIR/old-modules.conf; PERF_SCRIPT=$GTM_CONFIG_DIR/old-perf.sh; PERF_SERVICE=$GTM_CONFIG_DIR/gre-perf.service\n'
            'gtm_confirm() { return 0; }\n')


SYSCTL_MOCK = r'''
DB=$GTM_CONFIG_DIR/sysctls.tsv; WRITES=$GTM_CONFIG_DIR/writes
sysctl() {
    local key=${2%%=*} value=${2#*=}
    if [[ $1 == -n ]]; then
        awk -F '\t' -v key="$2" '$1 == key {print $2; found=1} END {if(!found) exit 1}' "$DB"
    elif [[ $1 == -w ]]; then
        [[ -f $GTM_TUNING_STATE ]] || return 90
        [[ $key != "${FAIL_KEY:-}" || $value != "${FAIL_VALUE:-}" ]] || return 1
        printf '%s\n' "$2" >> "$WRITES"
        awk -F '\t' -v OFS='\t' -v key="$key" -v value="$value" '{if($1==key) $2=value; print}' "$DB" > "$DB.tmp" && mv "$DB.tmp" "$DB"
    else return 91; fi
}
'''


RULE_MOCK = r'''
DB=$GTM_CONFIG_DIR/rules; CALLS=$GTM_CONFIG_DIR/calls
systemctl() { printf '%s\n' "$*" >> "$CALLS"; }
iptables() {
    local action index key
    local -a args=("$@")
    [[ " $* " != *' -S '* ]] || return 0
    for index in "${!args[@]}"; do
        if [[ ${args[$index]} == -C || ${args[$index]} == -D ]]; then action=${args[$index]}; break; fi
    done
    [[ -n $action ]] || return 2
    if [[ $index == 0 ]]; then args[$index]=-I; else args[$index]=-A; fi
    key="iptables ${args[*]}"
    if [[ $action == -C ]]; then [[ ${FAIL_CHECK:-0} == 0 ]] || return 2; grep -Fxq -- "$key" "$DB"; return $?; fi
    [[ ${FAIL_DELETE:-0} == 0 ]] || return 2
    awk -v key="$key" '$0==key && !removed {removed=1; next} {print}' "$DB" > "$DB.tmp" && mv "$DB.tmp" "$DB"
}
'''


class AdvancedTests(unittest.TestCase):
    def test_haproxy_http_health_has_closed_fields_and_preserves_passthrough(self):
        opts='check_mode=http;check_port=8080;check_path=/ready/live;check_host=health.example.com;check_status=204'
        row=record(engine='haproxy',version='2')+'\t'+opts
        result=bash('IFS= read -r row; gtm_record_validate "$row" && gtm_haproxy_render',row+'\n')
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertIn('mode tcp',result.stdout)
        self.assertIn('http-check send meth GET uri /ready/live ver HTTP/1.1 hdr Host health.example.com',result.stdout)
        self.assertIn('http-check expect status 204',result.stdout)
        self.assertNotIn(' ssl',result.stdout)
        for bad in ['check_mode=http', 'check_mode=https', 'check_mode=http;check_port=443',
                    'check_path=/x?token=y', 'check_path=/x;log=off;log=errors', 'check_host=${HOST}',
                    'check_host=x y', 'check_host=$(id)', 'check_status=2xx', 'check_path=/x#comment']:
            result=bash('gtm_record_validate '+shlex.quote(record(engine='haproxy',version='2')+'\t'+bad))
            self.assertNotEqual(result.returncode,0,bad)

    def test_gre_setup_no_longer_applies_implicit_global_tuning(self):
        result=bash('sysctl() { exit 92; }; SYSCTL_FILE=/missing-legacy-file; apply_sysctl')
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertIn('does not rewrite',result.stdout)

    def test_haproxy_v2_limits_checks_proxy_and_injection(self):
        options = 'connect=3;idle=86400;queue=20;maxconn=20000;server_maxconn=500;check_interval=2;check_timeout=3;check_fall=2;check_rise=3;check_port=8080;slowstart=10;proxy=v2;log=errors'
        row = record(engine='haproxy', version='2')+'\t'+options
        result = bash('IFS= read -r row\ngtm_record_validate "$row" && gtm_haproxy_render',row+'\n')
        self.assertEqual(result.returncode,0,result.stderr)
        for expected in ['maxconn 20000','timeout client 86400s','timeout queue 20s','timeout check 3s',
                         'check inter 2s fall 2 rise 3 port 8080 maxconn 500 slowstart 10s send-proxy-v2',
                         'option dontlog-normal','mode 600 level user']:
            self.assertIn(expected,result.stdout)
        for bad in ['idle=0','idle=999999999999999999','idle=3600;idle=7200','proxy=accept-proxy',
                    'log=off\nfrontend injected','maxconn=$(id)','unknown=1','connect=1;', 'maxconn=0000000']:
            result=bash('gtm_record_validate '+shlex.quote(record(engine='haproxy',version='2')+'\t'+bad))
            self.assertNotEqual(result.returncode,0,bad)
        result=bash('IFS= read -r row\ngtm_record_validate "$row"',record(version='2')+'\tidle=3600\n')
        self.assertNotEqual(result.returncode,0)

    def test_haproxy_options_survive_disable_and_regular_edit(self):
        row=record(engine='haproxy',version='2',enabled='0')+'\tidle=86400;proxy=v2'
        result=bash('IFS= read -r row\ngtm_record_validate "$row" || exit 1\nR_ENABLED=1; changed=$(gtm_record_emit)\ngtm_record_validate "$changed" || exit 2\n[[ $R_OPTIONS == "idle=86400;proxy=v2" && $R_VERSION == 2 ]]',row+'\n')
        self.assertEqual(result.returncode,0,result.stderr)
        result=bash('''
IFS= read -r saved
gtm_records() { GTM_RECORDS=("$saved"); }
gtm_prepare() { :; }; gtm_install_component() { :; }; gtm_confirm() { :; }
gtm_legacy_listener_check() { :; }; gtm_lock() { :; }; gtm_unlock() { :; }
gtm_load_records() { GTM_RECORDS=("$saved"); }; gtm_commit() { printf '%s\n' "${GTM_RECORDS[@]}"; }
gtm_new_forward haproxy F000001
''',row+'\n\n\n1\n')
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertIn('\t2\tidle=86400;proxy=v2',result.stdout)

    def test_haproxy_reload_for_config_change_restart_for_unit_limit(self):
        with tempfile.TemporaryDirectory(dir=ROOT/'.work') as directory:
            folder=Path(directory)
            code=paths(folder)+r'''
haproxy() { :; }
systemctl() {
    [[ $1 != is-active ]] || [[ -f $GTM_CONFIG_DIR/active ]] || return 1
    case $1 in restart|reload) printf '%s\n' "$1" >> "$GTM_CONFIG_DIR/actions"; touch "$GTM_CONFIG_DIR/active";; esac
    return 0
}
gtm_haproxy_pid() { printf 123; }; gtm_haproxy_wait() { :; }
'''
            for row in [record(engine='haproxy'),record(engine='haproxy',version='2')+'\tidle=7200',
                        record(engine='haproxy',version='2')+'\tidle=7200;maxconn=20000']:
                code+='GTM_RECORDS=('+shlex.quote(row)+'); gtm_relays_apply || exit 10\n'
            result=bash(code)
            self.assertEqual(result.returncode,0,result.stderr)
            self.assertEqual((folder/'actions').read_text().splitlines(),['restart','reload','restart'])
            unit=(folder/'gtm-F000001.service').read_text()
            self.assertIn('ExecReload=/bin/kill -USR2 $MAINPID',unit)
            self.assertIn('KillMode=mixed',unit)

    def test_tuning_restores_baseline_and_preserves_external_change(self):
        with tempfile.TemporaryDirectory(dir=ROOT/'.work') as directory:
            folder=Path(directory)
            (folder/'sysctls.tsv').write_text('net.netfilter.nf_conntrack_count\t10\nnet.netfilter.nf_conntrack_max\t262144\nnet.core.somaxconn\t4096\nnet.core.netdev_max_backlog\t1000\nnet.ipv4.tcp_max_syn_backlog\t4096\n',newline='\n')
            result=bash(paths(folder)+SYSCTL_MOCK+r'''
gtm_tuning_apply capacity 524288 || exit 10
gtm_tuning_apply capacity 1048576 || exit 11
sysctl -w net.core.somaxconn=7777 || exit 12
gtm_tuning_restore || exit 13
[[ $(gtm_tuning_read net.netfilter.nf_conntrack_max) == 262144 ]] || exit 14
[[ $(gtm_tuning_read net.core.somaxconn) == 7777 ]] || exit 15
[[ ! -e $GTM_TUNING_FILE ]] || exit 16
gtm_tuning_load; [[ ${#GTM_TUNING_ROWS[@]} == 0 ]]
''')
            self.assertEqual(result.returncode,0,result.stderr)
            self.assertIn('Preserved external change',result.stdout)

    def test_failed_tuning_apply_recovers_all_prior_values(self):
        with tempfile.TemporaryDirectory(dir=ROOT/'.work') as directory:
            folder=Path(directory)
            original='net.netfilter.nf_conntrack_count\t10\nnet.netfilter.nf_conntrack_max\t262144\nnet.core.somaxconn\t4096\nnet.core.netdev_max_backlog\t1000\nnet.ipv4.tcp_max_syn_backlog\t4096\n'
            (folder/'sysctls.tsv').write_text(original,newline='\n')
            result=bash(paths(folder)+SYSCTL_MOCK+r'''
FAIL_KEY=net.core.netdev_max_backlog; FAIL_VALUE=16384
gtm_tuning_apply capacity 524288 && exit 10
gtm_tuning_load || exit 11
[[ ${#GTM_TUNING_ROWS[@]} == 0 && ! -e $GTM_TUNING_FILE ]]
''')
            self.assertEqual(result.returncode,0,result.stderr)
            self.assertEqual((folder/'sysctls.tsv').read_text(),original)
            self.assertIn('apply failed',result.stderr)
            self.assertGreaterEqual(len((folder/'writes').read_text().splitlines()),4)

    def test_conntrack_restore_defers_when_baseline_is_below_live_usage(self):
        with tempfile.TemporaryDirectory(dir=ROOT/'.work') as directory:
            folder=Path(directory)
            (folder/'sysctls.tsv').write_text('net.netfilter.nf_conntrack_count\t300000\nnet.netfilter.nf_conntrack_max\t524288\n',newline='\n')
            (folder/'tuning.tsv').write_text('net.netfilter.nf_conntrack_max\t262144\t524288\n',newline='\n')
            result=bash(paths(folder)+SYSCTL_MOCK+r'''
gtm_tuning_restore && exit 10
[[ $(gtm_tuning_read net.netfilter.nf_conntrack_max) == 524288 ]] || exit 11
gtm_tuning_load; [[ ${#GTM_TUNING_ROWS[@]} == 1 ]]
''')
            self.assertEqual(result.returncode,0,result.stderr)
            self.assertIn('below the active flow count',result.stderr)

    def test_tuning_refuses_custom_dropin_and_corrupt_journal(self):
        with tempfile.TemporaryDirectory(dir=ROOT/'.work') as directory:
            folder=Path(directory)
            (folder/'tuning.tsv').write_text('net.ipv4.ip_forward\t0\t1\n',newline='\n')
            result=bash(paths(folder)+'sysctl() { exit 92; }; gtm_tuning_restore')
            self.assertNotEqual(result.returncode,0)
            self.assertIn('Invalid tuning journal',result.stderr)
            (folder/'tuning.tsv').write_text('net.netfilter.nf_conntrack_max\t262144\t524288\n',newline='\n')
            (folder/'99-z-gre-manager-owned.conf').write_text('# custom edit\n',newline='\n')
            result=bash(paths(folder)+'sysctl() { exit 92; }; gtm_tuning_restore')
            self.assertNotEqual(result.returncode,0)
            self.assertIn('edited outside',result.stderr)

    def test_partial_tuning_restore_retains_only_failed_keys_for_retry(self):
        with tempfile.TemporaryDirectory(dir=ROOT/'.work') as directory:
            folder=Path(directory)
            (folder/'sysctls.tsv').write_text('net.netfilter.nf_conntrack_count\t10\nnet.netfilter.nf_conntrack_max\t262144\nnet.core.somaxconn\t4096\nnet.core.netdev_max_backlog\t1000\nnet.ipv4.tcp_max_syn_backlog\t4096\n',newline='\n')
            result=bash(paths(folder)+SYSCTL_MOCK+r'''
gtm_tuning_apply capacity 524288 || exit 10
FAIL_KEY=net.netfilter.nf_conntrack_max; FAIL_VALUE=262144
gtm_tuning_restore && exit 11
gtm_tuning_load || exit 12
[[ ${#GTM_TUNING_ROWS[@]} == 1 ]] || exit 13
[[ $(gtm_tuning_read net.core.somaxconn) == 4096 ]] || exit 14
unset FAIL_KEY FAIL_VALUE
gtm_tuning_restore || exit 15
[[ $(gtm_tuning_read net.netfilter.nf_conntrack_max) == 262144 && ! -e $GTM_TUNING_FILE ]]
''')
            self.assertEqual(result.returncode,0,result.stderr)

    def test_legacy_cleanup_refuses_unknown_lines_and_custom_unit(self):
        with tempfile.TemporaryDirectory(dir=ROOT/'.work') as directory:
            folder=Path(directory)
            original='#!/bin/bash\n# Custom GRE Forwarding Rules\niptables -t nat -A PREROUTING -p tcp --dport 443 -j DNAT --to-destination 203.0.113.20:443\niptables -F\n'
            (folder/'legacy.sh').write_text(original,newline='\n')
            result=bash(paths(folder)+'FW_SCRIPT=$GTM_CONFIG_DIR/legacy.sh; FW_SERVICE=$GTM_CONFIG_DIR/legacy.service\niptables() { exit 90; }; systemctl() { exit 91; }\ngtm_legacy_cleanup_all')
            self.assertNotEqual(result.returncode,0)
            self.assertEqual((folder/'legacy.sh').read_text(),original)
            self.assertFalse(list((folder/'backups').glob('*')))
            (folder/'legacy.sh').write_text('\n'.join(original.splitlines()[:-1])+'\n',newline='\n')
            (folder/'legacy.service').write_text('[Service]\nExecStop=custom\n',newline='\n')
            result=bash(paths(folder)+'FW_SCRIPT=$GTM_CONFIG_DIR/legacy.sh; FW_SERVICE=$GTM_CONFIG_DIR/legacy.service\ngtm_legacy_cleanup_all')
            self.assertNotEqual(result.returncode,0)
            self.assertIn('customized',result.stderr)

    def test_legacy_cleanup_drains_duplicates_and_retains_unrelated_live_rules(self):
        for fail in [False,'delete','check']:
            with self.subTest(fail=fail), tempfile.TemporaryDirectory(dir=ROOT/'.work') as directory:
                folder=Path(directory)
                dnat='iptables -t nat -A PREROUTING -p tcp --dport 443 -j DNAT --to-destination 203.0.113.20:443'
                snat='iptables -t nat -A POSTROUTING -d 203.0.113.20 -p tcp --dport 443 -j MASQUERADE'
                fw='iptables -I FORWARD -d 203.0.113.20 -p tcp --dport 443 -j ACCEPT'
                manual='iptables -I FORWARD -d 203.0.113.99 -p tcp --dport 22 -j ACCEPT'
                original='#!/bin/bash\n# Custom GRE Forwarding Rules\n'+dnat+'\n'+snat+'\n'+fw+'\n'
                (folder/'legacy.sh').write_text(original,newline='\n')
                (folder/'rules').write_text('\n'.join([dnat,dnat,snat,fw,manual])+'\n',newline='\n')
                result=bash(paths(folder)+RULE_MOCK+'\nFW_SCRIPT=$GTM_CONFIG_DIR/legacy.sh; FW_SERVICE=$GTM_CONFIG_DIR/legacy.service\nFAIL_DELETE='+('1' if fail=='delete' else '0')+'; FAIL_CHECK='+('1' if fail=='check' else '0')+'\ngtm_legacy_cleanup_all')
                if fail:
                    self.assertNotEqual(result.returncode,0)
                    self.assertEqual((folder/'legacy.sh').read_text(),original)
                    self.assertIn('incomplete',result.stderr)
                else:
                    self.assertEqual(result.returncode,0,result.stderr)
                    self.assertFalse((folder/'legacy.sh').exists())
                    self.assertEqual((folder/'rules').read_text().strip(),manual)
                self.assertTrue(list((folder/'backups').glob('cleanup-*/source.sh')))

    def test_simple_cleanup_refuses_unknown_script_or_modern_dependency(self):
        with tempfile.TemporaryDirectory(dir=ROOT/'.work') as directory:
            folder=Path(directory)
            source=folder/'simple.sh'
            source.write_text('#!/bin/bash\n# Generated by GRE Master - Simple Mode v12\nip tunnel add gre_simp mode gre local 192.0.2.10 remote 203.0.113.20 ttl 255\nip addr add 172.16.200.2/30 dev gre_simp\nip link set gre_simp up\n',newline='\n')
            result=bash(paths(folder)+'GTM_SIMPLE_SCRIPT=$GTM_CONFIG_DIR/simple.sh\ngtm_simple_plan')
            self.assertEqual(result.returncode,0,result.stderr)
            (folder/'connections.tsv').write_text(record(targets='172.16.200.2:443')+'\n',newline='\n')
            result=bash(paths(folder)+'GTM_SIMPLE_SCRIPT=$GTM_CONFIG_DIR/simple.sh\nip() { exit 91; }; gtm_simple_cleanup')
            self.assertNotEqual(result.returncode,0)
            self.assertIn('referenced',result.stderr)
            self.assertTrue(source.exists())
            source.write_text(source.read_text()+'rm -rf /\n',newline='\n')
            result=bash(paths(folder)+'GTM_SIMPLE_SCRIPT=$GTM_CONFIG_DIR/simple.sh\ngtm_simple_plan')
            self.assertNotEqual(result.returncode,0)

    def test_retiring_historical_tuning_never_guesses_runtime_defaults(self):
        with tempfile.TemporaryDirectory(dir=ROOT/'.work') as directory:
            folder=Path(directory)
            old='net.ipv4.ip_forward=1\nnet.ipv6.conf.all.forwarding=1\nnet.core.default_qdisc=fq\nnet.ipv4.tcp_congestion_control=bbr\nnet.core.rmem_max=16777216\nnet.core.wmem_max=16777216\nnet.ipv4.tcp_rmem=4096 87380 16777216\nnet.ipv4.tcp_wmem=4096 65536 16777216\n'
            source=folder/'old-tcp.conf'; source.write_text(old,newline='\n')
            result=bash(paths(folder)+'sysctl() { exit 91; }; iptables() { exit 92; }; systemctl() { :; }\ngtm_legacy_retire_tuning')
            self.assertEqual(result.returncode,0,result.stderr)
            self.assertFalse(source.exists())
            self.assertTrue(list((folder/'backups').glob('retired-tuning-*/*')))
            source.write_text(old+'net.ipv4.ip_default_ttl=99\n',newline='\n')
            result=bash(paths(folder)+'systemctl() { exit 92; }; gtm_legacy_retire_tuning')
            self.assertNotEqual(result.returncode,0)
            self.assertTrue(source.exists())


if __name__ == '__main__':
    unittest.main()
