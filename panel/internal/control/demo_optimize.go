package control

import (
	"encoding/json"
	"errors"
	"maps"
	"strconv"
	"strings"
)

// demoOptimizer mirrors the Bash optimization module on in-memory values:
// the same catalog and modes, an undo stack, group removal and reset.
type demoOptimizer struct {
	values  map[string]string
	journal map[string][3]string // before, applied, group
	steps   []map[string][3]string
}

type catalogEntry struct{ group, key, value, mode, reason string }

// demoCatalog matches gtm_optimize_catalog for the demo host's 1 GiB.
var demoCatalog = []catalogEntry{
	{"conntrack", "net.netfilter.nf_conntrack_max", "131072", "raise", "flow-limit"},
	{"conntrack", "net.netfilter.nf_conntrack_buckets", "65536", "raise", "flow-buckets"},
	{"conntrack", "net.netfilter.nf_conntrack_tcp_timeout_established", "3600", "lower", "idle-tcp"},
	{"conntrack", "net.netfilter.nf_conntrack_tcp_timeout_time_wait", "30", "lower", "closing-tcp"},
	{"conntrack", "net.netfilter.nf_conntrack_tcp_timeout_fin_wait", "30", "lower", "closing-tcp"},
	{"conntrack", "net.netfilter.nf_conntrack_tcp_timeout_close_wait", "30", "lower", "closing-tcp"},
	{"conntrack", "net.netfilter.nf_conntrack_udp_timeout", "60", "raise", "udp"},
	{"conntrack", "net.netfilter.nf_conntrack_udp_timeout_stream", "180", "raise", "udp-stream"},
	{"queues", "net.core.netdev_max_backlog", "16384", "raise", "backlog"},
	{"queues", "net.core.netdev_budget", "600", "raise", "budget"},
	{"queues", "net.core.netdev_budget_usecs", "8000", "raise", "budget"},
	{"queues", "net.core.somaxconn", "8192", "raise", "accept-queue"},
	{"queues", "net.ipv4.tcp_max_syn_backlog", "8192", "raise", "syn-queue"},
	{"relay", "net.core.default_qdisc", "fq", "prefer=fq,cake,fq_pie", "pacing"},
	{"relay", "net.ipv4.tcp_congestion_control", "bbr", "prefer=bbr,bbr2,bbr3", "bbr"},
	{"relay", "net.core.rmem_max", "33554432", "raise", "buffers"},
	{"relay", "net.core.wmem_max", "33554432", "raise", "buffers"},
	{"relay", "net.ipv4.tcp_rmem", "4096 131072 33554432", "raise3", "buffers"},
	{"relay", "net.ipv4.tcp_wmem", "4096 65536 33554432", "raise3", "buffers"},
	{"relay", "net.ipv4.tcp_notsent_lowat", "131072", "lower", "notsent"},
	{"relay", "net.ipv4.tcp_mtu_probing", "1", "raise", "mtu-probing"},
	{"relay", "net.ipv4.tcp_slow_start_after_idle", "0", "lower", "idle-restart"},
	{"relay", "net.ipv4.tcp_keepalive_time", "600", "lower", "keepalive"},
	{"relay", "net.ipv4.tcp_keepalive_intvl", "30", "lower", "keepalive"},
	{"relay", "net.ipv4.tcp_keepalive_probes", "5", "lower", "keepalive"},
	{"relay", "net.ipv4.tcp_fin_timeout", "15", "lower", "fin-timeout"},
	{"relay", "net.ipv4.tcp_tw_reuse", "1", "prefer=1", "tw-reuse"},
	{"routing", "net.ipv4.conf.all.rp_filter", "2", "loose", "rp-filter"},
	{"routing", "net.ipv4.conf.default.rp_filter", "2", "loose", "rp-filter"},
	{"routing", "net.ipv4.conf.all.send_redirects", "0", "lower", "redirects"},
	{"routing", "net.ipv4.conf.default.send_redirects", "0", "lower", "redirects"},
	{"routing", "net.ipv4.conf.all.accept_redirects", "0", "lower", "accept-redirects"},
	{"routing", "net.ipv4.conf.default.accept_redirects", "0", "lower", "accept-redirects"},
}

// betterValue mirrors gtm_optimize_better: never worse than the live value.
func betterValue(current, wanted, mode string) string {
	n := func(v string) int { x, _ := strconv.Atoi(v); return x }
	switch {
	case mode == "raise":
		return map[bool]string{true: current, false: wanted}[n(current) >= n(wanted)]
	case mode == "lower":
		return map[bool]string{true: current, false: wanted}[n(current) <= n(wanted)]
	case mode == "raise3":
		have, want := strings.Fields(current), strings.Fields(wanted)
		if len(have) != 3 || len(want) != 3 {
			return wanted
		}
		out := make([]string, 3)
		for i := range out {
			out[i] = strconv.Itoa(max(n(have[i]), n(want[i])))
		}
		return strings.Join(out, " ")
	case strings.HasPrefix(mode, "prefer="):
		if oneOf(current, strings.Split(strings.TrimPrefix(mode, "prefer="), ",")...) {
			return current
		}
		return wanted
	case mode == "loose":
		if current == "1" {
			return "2"
		}
		return current
	}
	return wanted
}

func adviceNote(current, wanted, value string) string {
	switch {
	case value != current:
		return "change"
	case current == wanted:
		return "same"
	}
	return "kept"
}

const demoServerTools = "/etc/sysctl.d/99-zz-server-tools.conf"

// The demo pretends ServerTools also sets one key, to show the notice.
var demoOthers = map[string]string{"net.netfilter.nf_conntrack_tcp_timeout_established": "7200"}

func newDemoOptimizer() *demoOptimizer {
	return &demoOptimizer{journal: map[string][3]string{}, values: map[string]string{
		"net.netfilter.nf_conntrack_max": "65536", "net.netfilter.nf_conntrack_buckets": "16384",
		"net.netfilter.nf_conntrack_tcp_timeout_established": "7200", "net.netfilter.nf_conntrack_tcp_timeout_time_wait": "120",
		"net.netfilter.nf_conntrack_tcp_timeout_fin_wait": "120", "net.netfilter.nf_conntrack_tcp_timeout_close_wait": "60",
		"net.netfilter.nf_conntrack_udp_timeout": "30", "net.netfilter.nf_conntrack_udp_timeout_stream": "120",
		"net.core.netdev_max_backlog": "1000", "net.core.netdev_budget": "300", "net.core.netdev_budget_usecs": "2000",
		"net.core.somaxconn": "4096", "net.ipv4.tcp_max_syn_backlog": "512", "net.core.default_qdisc": "cake",
		"net.ipv4.tcp_congestion_control": "cubic", "net.core.rmem_max": "212992", "net.core.wmem_max": "212992",
		"net.ipv4.tcp_rmem": "4096 131072 6291456", "net.ipv4.tcp_wmem": "4096 16384 4194304", "net.ipv4.tcp_mtu_probing": "0",
		"net.ipv4.tcp_slow_start_after_idle": "1", "net.ipv4.tcp_keepalive_time": "7200", "net.ipv4.tcp_keepalive_intvl": "75",
		"net.ipv4.tcp_keepalive_probes": "9", "net.ipv4.tcp_fin_timeout": "60", "net.ipv4.tcp_tw_reuse": "2",
		"net.ipv4.tcp_notsent_lowat": "4294967295", "net.ipv4.conf.all.rp_filter": "0", "net.ipv4.conf.default.rp_filter": "1",
		"net.ipv4.conf.all.send_redirects": "1", "net.ipv4.conf.default.send_redirects": "1",
		"net.ipv4.conf.all.accept_redirects": "0", "net.ipv4.conf.default.accept_redirects": "1",
	}}
}

func (d *demoOptimizer) plan(groups []string) OptimizePlan {
	p := OptimizePlan{Groups: groups, Changes: []OptimizeChange{}}
	for _, c := range demoCatalog {
		if !oneOf(c.group, groups...) {
			continue
		}
		current := d.values[c.key]
		value := betterValue(current, c.value, c.mode)
		change := OptimizeChange{Group: c.group, Key: c.key, Current: current, Value: value, Reason: c.reason, Note: adviceNote(current, c.value, value)}
		if other, ok := demoOthers[c.key]; ok {
			change.OtherFile, change.OtherValue = demoServerTools, other
		}
		p.Changes = append(p.Changes, change)
	}
	return p
}

func (d *demoOptimizer) view() OptimizeView {
	flows := uint64(23517)
	v := OptimizeView{Memory: 1073741824, Flows: &flows, Congestion: []string{"reno", "cubic", "bbr"}, Steps: len(d.steps), File: "/etc/sysctl.d/zz-gre-manager-optimize.conf", ServerTools: []string{demoServerTools}, Keys: []OptimizeKey{}}
	for _, c := range demoCatalog {
		current := d.values[c.key]
		value := betterValue(current, c.value, c.mode)
		k := OptimizeKey{Group: c.group, Key: c.key, Current: current, Recommended: value, Reason: c.reason, Note: adviceNote(current, c.value, value)}
		if j, ok := d.journal[c.key]; ok {
			k.Before, k.Applied, k.AppliedGroup = j[0], j[1], j[2]
		}
		if other, ok := demoOthers[c.key]; ok {
			k.OtherFile, k.OtherValue = demoServerTools, other
		}
		v.Keys = append(v.Keys, k)
	}
	return v
}

// moveTo makes target the journal: its keys take their applied values and
// the others return to their original values.
func (d *demoOptimizer) moveTo(target map[string][3]string) {
	for key, row := range d.journal {
		if t, ok := target[key]; ok {
			d.values[key] = t[1]
		} else {
			d.values[key] = row[0]
		}
	}
	d.journal = maps.Clone(target)
}

func (d *Demo) optimizeDemo(r Request) (json.RawMessage, error) {
	if d.optimizer == nil {
		d.optimizer = newDemoOptimizer()
	}
	o := d.optimizer
	switch r.Action {
	case "optimize":
		return json.Marshal(o.view())
	case "optimize-plan", "optimize-apply":
		groups, e := r.Optimize.groups()
		if e != nil {
			return nil, e
		}
		p := o.plan(groups)
		if r.Action == "optimize-plan" {
			return json.Marshal(p)
		}
		next, n := maps.Clone(o.journal), 0
		for _, c := range p.Changes {
			if c.Note != "change" {
				continue
			}
			before := c.Current
			if j, ok := next[c.Key]; ok {
				before = j[0]
			}
			next[c.Key] = [3]string{before, c.Value, c.Group}
			o.values[c.Key] = c.Value
			n++
		}
		if n == 0 {
			return json.Marshal("Nothing to change. " + demoMessage)
		}
		o.steps = append(o.steps, o.journal)
		o.journal = next
		return json.Marshal("Applied " + strconv.Itoa(n) + " setting(s). " + demoMessage)
	case "optimize-undo":
		if len(o.steps) == 0 {
			return nil, errors.New("There is no step to undo.")
		}
		last := o.steps[len(o.steps)-1]
		o.steps = o.steps[:len(o.steps)-1]
		o.moveTo(last)
		return json.Marshal("Undid the last step. " + demoMessage)
	}
	group := r.Optimize.Group
	if !oneOf(group, append([]string{"all", "previous"}, optimizeGroups...)...) {
		return nil, errors.New("unknown optimization group")
	}
	if group == "all" {
		o.moveTo(map[string][3]string{})
		o.steps = nil
		return json.Marshal("Every setting is back to its original value. " + demoMessage)
	}
	remaining := map[string][3]string{}
	for key, row := range o.journal {
		if row[2] != group {
			remaining[key] = row
		}
	}
	o.steps = append(o.steps, o.journal)
	o.moveTo(remaining)
	return json.Marshal("Settings of " + group + " are back to their original values. " + demoMessage)
}
