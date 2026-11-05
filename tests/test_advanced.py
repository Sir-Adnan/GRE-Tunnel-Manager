"""HAProxy lifecycle, retirement of old installations and server optimization regressions."""
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


OPT_MOCK = r'''
DB=$GTM_CONFIG_DIR/sysctls.tsv
modprobe() { return 0; }
sysctl() {
    local key=${2%%=*} value=${2#*=}
    if [[ $1 == -n ]]; then
        awk -F '\t' -v key="$2" '$1 == key {print $2; found=1} END {if(!found) exit 1}' "$DB"
    elif [[ $1 == -w ]]; then
        [[ $key != "${FAIL_KEY:-}" ]] || return 1
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
                    'log=off\nfrontend injected','maxconn=$(id)','unknown=1','connect=1;', 'maxconn=00000000']:
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

    HOST_DB = ('net.netfilter.nf_conntrack_count\t10\nnet.netfilter.nf_conntrack_max\t65536\n'
               'net.netfilter.nf_conntrack_buckets\t16384\nnet.netfilter.nf_conntrack_tcp_timeout_established\t432000\n'
               'net.netfilter.nf_conntrack_tcp_timeout_time_wait\t120\nnet.netfilter.nf_conntrack_tcp_timeout_fin_wait\t120\n'
               'net.netfilter.nf_conntrack_tcp_timeout_close_wait\t60\nnet.netfilter.nf_conntrack_udp_timeout\t30\n'
               'net.netfilter.nf_conntrack_udp_timeout_stream\t120\nnet.core.netdev_max_backlog\t1000\n'
               'net.core.netdev_budget\t300\nnet.core.netdev_budget_usecs\t2000\nnet.core.somaxconn\t4096\n'
               'net.ipv4.tcp_max_syn_backlog\t512\nnet.core.default_qdisc\tfq_codel\nnet.ipv4.tcp_congestion_control\tcubic\n'
               'net.ipv4.tcp_available_congestion_control\treno cubic bbr\nnet.core.rmem_max\t212992\nnet.core.wmem_max\t212992\n'
               'net.ipv4.tcp_rmem\t4096 131072 6291456\nnet.ipv4.tcp_wmem\t4096 16384 4194304\nnet.ipv4.tcp_mtu_probing\t0\n'
               'net.ipv4.tcp_slow_start_after_idle\t1\nnet.ipv4.tcp_keepalive_time\t7200\nnet.ipv4.tcp_keepalive_intvl\t75\n'
               'net.ipv4.tcp_keepalive_probes\t9\nnet.ipv4.tcp_fin_timeout\t60\nnet.ipv4.tcp_tw_reuse\t2\n'
               'net.ipv4.tcp_notsent_lowat\t4294967295\nnet.ipv4.conf.all.rp_filter\t1\nnet.ipv4.conf.default.rp_filter\t1\n'
               'net.ipv4.conf.all.send_redirects\t1\nnet.ipv4.conf.default.send_redirects\t1\n'
               'net.ipv4.conf.all.accept_redirects\t0\nnet.ipv4.conf.default.accept_redirects\t1\n'
               'net.ipv4.ip_local_port_range\t32768 60999\nnet.ipv4.tcp_max_tw_buckets\t262144\n')

    def optimize(self, folder, code, memory_kb=4194304):
        (folder/'sysctls.tsv').write_text(self.HOST_DB,newline='\n')
        (folder/'meminfo').write_text(f'MemTotal:        {memory_kb} kB\n',newline='\n')
        return bash(paths(folder)+OPT_MOCK+'GTM_MEMINFO=$GTM_CONFIG_DIR/meminfo\nvalue() { gtm_optimize_read "$1"; }\n'+code)

    def test_optimize_groups_apply_undo_remove_and_reset(self):
        with tempfile.TemporaryDirectory(dir=ROOT/'.work') as directory:
            folder=Path(directory)
            result=self.optimize(folder,r"""
gtm_optimize_plan conntrack > "$GTM_CONFIG_DIR/plan" || exit 9
gtm_optimize_apply conntrack || exit 10
gtm_optimize_paths
# 8 % of 4 GiB at 350 bytes per flow rounds down to 2^19; buckets are half.
[[ $(value net.netfilter.nf_conntrack_max) == 524288 && $(value net.netfilter.nf_conntrack_buckets) == 262144 ]] || exit 11
[[ $(value net.netfilter.nf_conntrack_tcp_timeout_established) == 3600 && $(value net.netfilter.nf_conntrack_tcp_timeout_time_wait) == 30 ]] || exit 12
[[ $(value net.netfilter.nf_conntrack_udp_timeout) == 60 && $(value net.netfilter.nf_conntrack_udp_timeout_stream) == 180 ]] || exit 13
grep -qx nf_conntrack "$GTM_OPT_MODULES" && grep -q 'nf_conntrack_max = 524288' "$GTM_OPT_FILE" || exit 14
gtm_optimize_apply queues relay || exit 15
[[ $(value net.ipv4.tcp_congestion_control) == bbr && $(value net.ipv4.tcp_keepalive_time) == 600 && $(value net.core.netdev_budget) == 600 ]] || exit 16
grep -qx tcp_bbr "$GTM_OPT_MODULES" || exit 17
gtm_optimize_undo || exit 18
[[ $(value net.ipv4.tcp_congestion_control) == cubic && $(value net.core.netdev_budget) == 300 ]] || exit 19
[[ $(value net.netfilter.nf_conntrack_max) == 524288 ]] && ! grep -qx tcp_bbr "$GTM_OPT_MODULES" || exit 20
gtm_optimize_apply relay || exit 21
gtm_optimize_remove conntrack || exit 22
[[ $(value net.netfilter.nf_conntrack_max) == 65536 && $(value net.netfilter.nf_conntrack_tcp_timeout_established) == 432000 ]] || exit 23
[[ $(value net.ipv4.tcp_congestion_control) == bbr ]] && ! grep -q nf_conntrack "$GTM_OPT_MODULES" || exit 24
gtm_optimize_status > "$GTM_CONFIG_DIR/status" || exit 25
gtm_optimize_remove all || exit 26
[[ $(value net.ipv4.tcp_congestion_control) == cubic && $(value net.ipv4.tcp_rmem) == '4096 131072 6291456' ]] || exit 27
[[ ! -e $GTM_OPT_FILE && ! -e $GTM_OPT_MODULES && ! -e $GTM_OPT_JOURNAL && ! -d $GTM_OPT_STEPS ]] || exit 28
gtm_optimize_undo && exit 29
true
""")
            self.assertEqual(result.returncode,0,result.stdout+result.stderr)
            plan=(folder/'plan').read_text()
            self.assertIn('change\tconntrack\tnet.netfilter.nf_conntrack_max\t65536\t524288\tflow-limit\tchange\t-\t-',plan)
            status=(folder/'status').read_text()
            self.assertIn('meta\tsteps\t',status)
            self.assertIn('key\trelay\tnet.ipv4.tcp_congestion_control\tbbr\tcubic\tbbr\trelay\t-\t-\tbbr\tbbr\tsame',status)
            self.assertIn('key\tconntrack\tnet.netfilter.nf_conntrack_max\t65536\t-\t-\t-\t-\t-\t524288\tflow-limit\tchange',status)

    def test_optimize_never_makes_provider_defaults_worse(self):
        with tempfile.TemporaryDirectory(dir=ROOT/'.work') as directory:
            folder=Path(directory)
            # A provider image that already ships better values than ours for some keys.
            result=self.optimize(folder,r"""
for pair in 'net.core.default_qdisc=cake' 'net.ipv4.tcp_congestion_control=bbr' 'net.core.rmem_max=67108864' \
    'net.ipv4.tcp_rmem=8192 262144 16777216' 'net.core.netdev_max_backlog=65536' 'net.ipv4.tcp_keepalive_time=300' \
    'net.ipv4.tcp_mtu_probing=2' 'net.ipv4.tcp_tw_reuse=1' 'net.ipv4.conf.all.rp_filter=0' 'net.ipv4.tcp_notsent_lowat=16384'; do
    sysctl -w "$pair" >/dev/null
done
gtm_optimize_plan queues relay routing > "$GTM_CONFIG_DIR/plan" || exit 9
gtm_optimize_apply queues relay routing || exit 10
[[ $(value net.core.default_qdisc) == cake && $(value net.core.rmem_max) == 67108864 && $(value net.core.netdev_max_backlog) == 65536 ]] || exit 11
# Triples grow field by field: the larger minimum and default stay, the maximum grows.
[[ $(value net.ipv4.tcp_rmem) == '8192 262144 33554432' ]] || exit 12
[[ $(value net.ipv4.tcp_keepalive_time) == 300 && $(value net.ipv4.tcp_mtu_probing) == 2 && $(value net.ipv4.tcp_notsent_lowat) == 16384 ]] || exit 13
# Strict reverse-path filtering becomes loose; a disabled filter stays disabled.
[[ $(value net.ipv4.conf.all.rp_filter) == 0 && $(value net.ipv4.conf.default.rp_filter) == 2 ]] || exit 14
[[ $(value net.ipv4.conf.all.send_redirects) == 0 && $(value net.ipv4.conf.default.accept_redirects) == 0 ]] || exit 15
gtm_optimize_remove all || exit 16
[[ $(value net.ipv4.tcp_rmem) == '8192 262144 16777216' && $(value net.ipv4.conf.default.rp_filter) == 1 ]]
""")
            self.assertEqual(result.returncode,0,result.stdout+result.stderr)
            plan=(folder/'plan').read_text()
            for key,current in [('net.core.default_qdisc','cake'),('net.core.rmem_max','67108864'),('net.ipv4.tcp_keepalive_time','300'),
                                ('net.ipv4.tcp_mtu_probing','2'),('net.ipv4.conf.all.rp_filter','0'),('net.ipv4.tcp_notsent_lowat','16384')]:
                self.assertRegex(plan,'\t'+key.replace('.','\\.')+'\t'+current+'\t'+current+'\t[a-z-]+\tkept\t',key)
            self.assertRegex(plan,'\tnet\\.ipv4\\.tcp_congestion_control\tbbr\tbbr\tbbr\tsame\t')
            self.assertIn('the server value is already better; kept',result.stdout)

    def test_optimize_keeps_stricter_values_and_releases_external_changes(self):
        with tempfile.TemporaryDirectory(dir=ROOT/'.work') as directory:
            folder=Path(directory)
            result=self.optimize(folder,r"""
sysctl -w net.netfilter.nf_conntrack_tcp_timeout_established=600 >/dev/null
sysctl -w net.netfilter.nf_conntrack_max=2097152 >/dev/null
gtm_optimize_plan conntrack > "$GTM_CONFIG_DIR/plan" || exit 9
gtm_optimize_apply conntrack || exit 10
[[ $(value net.netfilter.nf_conntrack_tcp_timeout_established) == 600 && $(value net.netfilter.nf_conntrack_max) == 2097152 ]] || exit 11
sysctl -w net.netfilter.nf_conntrack_udp_timeout=90 >/dev/null
gtm_optimize_remove all || exit 12
# An administrator's later change is left in place, everything else returns.
[[ $(value net.netfilter.nf_conntrack_udp_timeout) == 90 && $(value net.netfilter.nf_conntrack_tcp_timeout_time_wait) == 120 ]]
""", memory_kb=1048576)
            self.assertEqual(result.returncode,0,result.stdout+result.stderr)
            self.assertIn('Left net.netfilter.nf_conntrack_udp_timeout = 90',result.stdout)
            self.assertIn('\tnet.netfilter.nf_conntrack_tcp_timeout_established\t600\t600\tidle-tcp\tkept',(folder/'plan').read_text())

    def test_failed_optimize_apply_reverts_its_own_writes(self):
        with tempfile.TemporaryDirectory(dir=ROOT/'.work') as directory:
            folder=Path(directory)
            result=self.optimize(folder,r"""
FAIL_KEY=net.netfilter.nf_conntrack_tcp_timeout_time_wait
gtm_optimize_apply conntrack && exit 10
unset FAIL_KEY
gtm_optimize_paths; gtm_optimize_load || exit 11
[[ ${#GTM_OPT_ROWS[@]} == 0 && ! -e $GTM_OPT_FILE && -z $(gtm_optimize_last_step) ]] || exit 12
[[ $(value net.netfilter.nf_conntrack_max) == 65536 ]]
""")
            self.assertEqual(result.returncode,0,result.stdout+result.stderr)
            self.assertIn('Applying stopped',result.stderr)

    def test_optimize_wins_over_servertools_reports_it_and_imports_old_tuning(self):
        with tempfile.TemporaryDirectory(dir=ROOT/'.work') as directory:
            folder=Path(directory)
            servertools=folder/'99-zz-server-tools.conf'
            servertools.write_text('net.netfilter.nf_conntrack_tcp_timeout_established = 7200\n',newline='\n')
            (folder/'tuning.tsv').write_text('# Traffic Manager tuning v1\nnet.core.somaxconn\t1024\t4096\n',newline='\n')
            (folder/'99-z-gre-manager-owned.conf').write_text('net.core.somaxconn = 4096\n',newline='\n')
            result=self.optimize(folder,r"""
gtm_optimize_status > "$GTM_CONFIG_DIR/before" || exit 9
gtm_optimize_apply conntrack || exit 10
gtm_optimize_paths
[[ $(value net.netfilter.nf_conntrack_tcp_timeout_established) == 3600 ]] || exit 11
[[ ! -e $GTM_OPT_OLD_JOURNAL && ! -e $GTM_OPT_OLD_FILE ]] || exit 12
gtm_optimize_status > "$GTM_CONFIG_DIR/after" || exit 13
grep -q 'nf_conntrack_tcp_timeout_established = 3600' "$GTM_OPT_FILE" || exit 15
gtm_optimize_remove all || exit 14
# The imported key returns to the value from before the old tuning menu.
[[ $(value net.core.somaxconn) == 1024 ]]
""")
            self.assertEqual(result.returncode,0,result.stdout+result.stderr)
            self.assertIn('Imported the earlier tuning',result.stdout)
            before=(folder/'before').read_text()
            self.assertIn('meta\tservertools\t'+servertools.as_posix(),before)
            self.assertIn('meta\timport\t',before)
            after=(folder/'after').read_text()
            self.assertIn('\tnet.netfilter.nf_conntrack_tcp_timeout_established\t3600\t432000\t3600\tconntrack\t'+servertools.as_posix()+'\t7200\t3600\tidle-tcp\tsame',after)
            self.assertIn('key\tqueues\tnet.core.somaxconn\t4096\t1024\t4096\tprevious\t-\t-\t8192\taccept-queue\tchange',after)

    def test_optimize_profiles_scale_values_and_return_toward_originals(self):
        with tempfile.TemporaryDirectory(dir=ROOT/'.work') as directory:
            folder=Path(directory)
            result=self.optimize(folder,r"""
# A relay listens on 20000, inside the wider port range: the low end stays.
ss() { printf 'tcp LISTEN 0 4096 0.0.0.0:20000 0.0.0.0:*\n'; }
GTM_OPT_LEVEL=aggressive GTM_OPT_GOAL=users
gtm_optimize_apply conntrack relay || exit 10
gtm_optimize_paths
# 16 % of 4 GiB at 350 bytes per flow rounds down to 2^20.
[[ $(value net.netfilter.nf_conntrack_max) == 1048576 && $(value net.netfilter.nf_conntrack_tcp_timeout_established) == 1800 ]] || exit 11
[[ $(value net.core.rmem_max) == 67108864 && $(value net.ipv4.tcp_rmem) == '8192 262144 67108864' && $(value net.ipv4.tcp_keepalive_time) == 300 ]] || exit 12
[[ $(value net.ipv4.ip_local_port_range) == '32768 65535' && $(value net.ipv4.tcp_max_tw_buckets) == 1048576 ]] || exit 13
[[ $(cat "$GTM_OPT_DIR/profile") == 'aggressive users' ]] || exit 14
# A lighter profile moves applied keys back toward, never below, the original.
GTM_OPT_LEVEL=conservative GTM_OPT_GOAL=general
gtm_optimize_plan relay > "$GTM_CONFIG_DIR/plan" || exit 15
gtm_optimize_apply conntrack relay || exit 16
[[ $(value net.netfilter.nf_conntrack_max) == 262144 && $(value net.netfilter.nf_conntrack_tcp_timeout_established) == 7200 ]] || exit 17
[[ $(value net.ipv4.tcp_keepalive_time) == 1800 && $(value net.core.rmem_max) == 16777216 ]] || exit 18
[[ $(value net.ipv4.ip_local_port_range) == '32768 60999' && $(value net.ipv4.tcp_notsent_lowat) == 4294967295 ]] || exit 19
# Keys back at their original value are no longer tracked.
! grep -q 'ip_local_port_range\|tcp_notsent_lowat\|tcp_max_tw_buckets' "$GTM_OPT_JOURNAL" "$GTM_OPT_FILE" || exit 20
gtm_optimize_status > "$GTM_CONFIG_DIR/status" || exit 21
gtm_optimize_remove all || exit 22
[[ ! -e $GTM_OPT_DIR/profile && $(value net.netfilter.nf_conntrack_max) == 65536 ]]
""")
            self.assertEqual(result.returncode,0,result.stdout+result.stderr)
            plan=(folder/'plan').read_text()
            self.assertIn('\tnet.ipv4.ip_local_port_range\t32768 65535\t32768 60999\tports\tchange\t-\t-\tn2 1024 65535',plan)
            self.assertIn('\tnet.ipv4.tcp_notsent_lowat\t131072\t4294967295\tnotsent\tchange\t',plan)
            self.assertIn('\tnet.core.default_qdisc\tfq\tfq\tpacing\tsame\t-\t-\tc fq,cake,fq_pie,fq_codel,pfifo_fast',plan)
            status=(folder/'status').read_text()
            self.assertIn('meta\tprofile\tconservative general',status)
            self.assertIn('meta\tcapped\t0',status)
            self.assertRegex(status,'meta\tlast\t[0-9]+')
            self.assertIn('\tnet.ipv4.tcp_max_tw_buckets\t262144\t-\t-\t-\t-\t-\t262144\ttw-buckets\toff',status)

    def test_optimize_aggressive_is_capped_on_small_servers_and_latency_goal(self):
        with tempfile.TemporaryDirectory(dir=ROOT/'.work') as directory:
            folder=Path(directory)
            result=self.optimize(folder,r"""
GTM_OPT_LEVEL=aggressive GTM_OPT_GOAL=latency
gtm_optimize_status > "$GTM_CONFIG_DIR/status" || exit 9
gtm_optimize_apply conntrack relay || exit 10
# 1 GiB: balanced table and buffers, aggressive timeouts, latency extras.
[[ $(value net.netfilter.nf_conntrack_max) == 131072 && $(value net.core.rmem_max) == 33554432 ]] || exit 11
[[ $(value net.netfilter.nf_conntrack_tcp_timeout_established) == 1800 && $(value net.ipv4.tcp_keepalive_time) == 300 ]] || exit 12
[[ $(value net.ipv4.tcp_notsent_lowat) == 16384 && $(value net.netfilter.nf_conntrack_udp_timeout_stream) == 300 ]]
""", memory_kb=1048576)
            self.assertEqual(result.returncode,0,result.stdout+result.stderr)
            status=(folder/'status').read_text()
            self.assertIn('meta\tcapped\t1',status)
            self.assertIn('meta\tview\taggressive latency',status)

    def test_optimize_custom_values_stay_in_bounds_and_worse_needs_confirmation(self):
        with tempfile.TemporaryDirectory(dir=ROOT/'.work') as directory:
            folder=Path(directory)
            result=self.optimize(folder,r"""
gtm_optimize_custom net.ipv4.tcp_fin_timeout=1 && exit 9
gtm_optimize_custom 'net.ipv4.tcp_rmem=8192 4096 33554432' && exit 10
gtm_optimize_custom net.ipv4.ip_forward=1 && exit 11
gtm_optimize_custom 'net.core.default_qdisc=pfifo' && exit 12
gtm_optimize_custom net.ipv4.tcp_fin_timeout=20 net.ipv4.tcp_keepalive_probes=10 'net.ipv4.tcp_rmem=4096 262144 67108864' || exit 13
gtm_optimize_plan relay > "$GTM_CONFIG_DIR/plan" || exit 14
gtm_optimize_apply relay && exit 15
[[ $(value net.ipv4.tcp_fin_timeout) == 60 ]] || exit 16
GTM_OPT_ALLOW_WORSE=1 gtm_optimize_apply relay || exit 17
[[ $(value net.ipv4.tcp_fin_timeout) == 20 && $(value net.ipv4.tcp_keepalive_probes) == 10 && $(value net.ipv4.tcp_rmem) == '4096 262144 67108864' ]] || exit 18
gtm_optimize_remove all || exit 19
[[ $(value net.ipv4.tcp_keepalive_probes) == 9 ]]
""")
            self.assertEqual(result.returncode,0,result.stdout+result.stderr)
            plan=(folder/'plan').read_text()
            self.assertIn('\tnet.ipv4.tcp_fin_timeout\t60\t20\tfin-timeout\tcustom\t',plan)
            self.assertIn('\tnet.ipv4.tcp_keepalive_probes\t9\t10\tkeepalive\tworse\t',plan)
            self.assertIn('worse than the server',result.stderr)

    def test_api_optimize_profile_arguments(self):
        with tempfile.TemporaryDirectory(dir=ROOT/'.work') as directory:
            folder=Path(directory)
            result=self.optimize(folder,r"""
gtm_prepare() { :; }; gtm_lock() { :; }; gtm_unlock() { :; }
gtm_api optimize-plan balanced users relay,queues net.core.somaxconn=20000 > "$GTM_CONFIG_DIR/plan" || exit 9
gtm_api optimize-status aggressive general > "$GTM_CONFIG_DIR/status" || exit 10
for bad in 'optimize-plan turbo general relay' 'optimize-plan balanced general relay;id' 'optimize-plan balanced general' \
    'optimize-apply balanced general relay maybe' 'optimize-apply balanced general rm allow' 'optimize-status balanced' \
    'optimize-plan balanced general relay net.core.somaxconn=99999999'; do
    read -r -a words <<< "$bad"
    gtm_api "${words[@]}" >/dev/null 2>&1; [[ $? == 2 ]] || { echo "accepted: $bad"; exit 11; }
done
gtm_api optimize-apply - - queues deny || exit 12
[[ $(value net.core.somaxconn) == 8192 ]]
""")
            self.assertEqual(result.returncode,0,result.stdout+result.stderr)
            plan=(folder/'plan').read_text()
            self.assertIn('\tnet.core.somaxconn\t4096\t20000\taccept-queue\tcustom\t',plan)
            self.assertIn('\tnet.ipv4.tcp_max_syn_backlog\t512\t16384\tsyn-queue\tchange\t',plan)
            self.assertIn('meta\tview\taggressive general',(folder/'status').read_text())

    def test_optimize_refuses_edited_files_and_bad_journal(self):
        with tempfile.TemporaryDirectory(dir=ROOT/'.work') as directory:
            folder=Path(directory)
            (folder/'optimize').mkdir()
            (folder/'optimize'/'journal.tsv').write_text('net.ipv4.ip_forward\t0\t1\tconntrack\n',newline='\n')
            result=self.optimize(folder,'gtm_optimize_apply conntrack')
            self.assertNotEqual(result.returncode,0)
            self.assertIn('Invalid optimization journal',result.stderr)
            (folder/'optimize'/'journal.tsv').unlink()
            result=self.optimize(folder,'gtm_optimize_apply queues || exit 10\nprintf "# mine\\n" >> "$GTM_CONFIG_DIR/zz-gre-manager-optimize.conf"\ngtm_optimize_remove all')
            self.assertNotEqual(result.returncode,0)
            self.assertIn('Kept the edited file',result.stderr)
            for bad in ['gtm_optimize_apply rm', 'gtm_optimize_plan "conntrack;id"', 'gtm_optimize_remove x']:
                self.assertEqual(self.optimize(folder,bad).returncode,2,bad)

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
