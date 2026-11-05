package control

import (
	"encoding/json"
	"errors"
	"maps"
	"strconv"
	"strings"
	"time"
)

// demoOptimizer mirrors the Bash optimization module on in-memory values:
// the same profiles, modes and bounds, an undo stack, group removal and reset.
type demoOptimizer struct {
	values  map[string]string
	journal map[string][3]string // before, applied, group
	steps   []map[string][3]string
	profile OptimizeProfile
	last    int64
}

type catalogEntry struct{ group, key, value, mode, reason string }

const (
	demoMemory = uint64(1073741824)
	// demoSmall matches GTM_OPT_SMALL: aggressive is capped below it.
	demoSmall = uint64(1792 * 1048576)
)

// demoCatalog matches gtm_optimize_catalog for a profile and memory size.
func demoCatalog(level, goal string, memory uint64) []catalogEntry {
	percent, limitCap, bucketCap := uint64(8), uint64(4194304), uint64(2097152)
	established, closing, backlog, budget, usecs, somax, syn := "3600", "30", "16384", "600", "8000", 8192, 8192
	buffer, rmem, wmem, notsent := "33554432", "4096 131072 33554432", "4096 65536 33554432", "131072"
	ka, kai, kap, fin := "600", "30", "5", "15"
	udp, stream, tw, ports := "60", "180", "-", "-"
	switch level {
	case "conservative":
		percent, established, closing, backlog, budget, usecs, somax, syn = 4, "7200", "60", "8192", "400", "4000", 4096, 4096
		buffer, rmem, wmem, notsent = "16777216", "4096 131072 16777216", "4096 65536 16777216", "-"
		ka, kai, kap, fin = "1800", "60", "6", "30"
	case "aggressive":
		percent, limitCap, bucketCap, established, closing, backlog, budget, usecs, somax, syn = 16, 8388608, 4194304, "1800", "15", "65536", "1000", "8000", 65535, 65535
		buffer, rmem, wmem, notsent = "67108864", "8192 262144 67108864", "8192 131072 67108864", "131072"
		ka, kai, kap, fin = "300", "15", "5", "10"
		if memory < demoSmall {
			percent, limitCap, bucketCap, backlog = 8, 4194304, 2097152, "32768"
			buffer, rmem, wmem = "33554432", "4096 131072 33554432", "4096 65536 33554432"
		}
	}
	switch goal {
	case "users":
		somax, syn, ports = max(somax, 16384), max(syn, 16384), "16384 65535"
		tw = map[string]string{"conservative": "262144", "aggressive": "1048576"}[level]
		if tw == "" {
			tw = "524288"
		}
	case "latency":
		notsent, udp, stream = "16384", "120", "300"
	}
	limit := uint64(131072)
	for limit*2 <= memory*percent/100/350 && limit < limitCap {
		limit *= 2
	}
	buckets := min(limit/2, bucketCap)
	n := func(v uint64) string { return strconv.FormatUint(v, 10) }
	i := strconv.Itoa
	return []catalogEntry{
		{"conntrack", "net.netfilter.nf_conntrack_max", n(limit), "raise", "flow-limit"},
		{"conntrack", "net.netfilter.nf_conntrack_buckets", n(buckets), "raise", "flow-buckets"},
		{"conntrack", "net.netfilter.nf_conntrack_tcp_timeout_established", established, "lower", "idle-tcp"},
		{"conntrack", "net.netfilter.nf_conntrack_tcp_timeout_time_wait", closing, "lower", "closing-tcp"},
		{"conntrack", "net.netfilter.nf_conntrack_tcp_timeout_fin_wait", closing, "lower", "closing-tcp"},
		{"conntrack", "net.netfilter.nf_conntrack_tcp_timeout_close_wait", closing, "lower", "closing-tcp"},
		{"conntrack", "net.netfilter.nf_conntrack_udp_timeout", udp, "raise", "udp"},
		{"conntrack", "net.netfilter.nf_conntrack_udp_timeout_stream", stream, "raise", "udp-stream"},
		{"queues", "net.core.netdev_max_backlog", backlog, "raise", "backlog"},
		{"queues", "net.core.netdev_budget", budget, "raise", "budget"},
		{"queues", "net.core.netdev_budget_usecs", usecs, "raise", "budget"},
		{"queues", "net.core.somaxconn", i(somax), "raise", "accept-queue"},
		{"queues", "net.ipv4.tcp_max_syn_backlog", i(syn), "raise", "syn-queue"},
		{"relay", "net.core.default_qdisc", "fq", "prefer=fq,cake,fq_pie", "pacing"},
		{"relay", "net.ipv4.tcp_congestion_control", "bbr", "prefer=bbr,bbr2,bbr3", "bbr"},
		{"relay", "net.core.rmem_max", buffer, "raise", "buffers"},
		{"relay", "net.core.wmem_max", buffer, "raise", "buffers"},
		{"relay", "net.ipv4.tcp_rmem", rmem, "raise3", "buffers"},
		{"relay", "net.ipv4.tcp_wmem", wmem, "raise3", "buffers"},
		{"relay", "net.ipv4.tcp_notsent_lowat", notsent, "lower", "notsent"},
		{"relay", "net.ipv4.tcp_mtu_probing", "1", "raise", "mtu-probing"},
		{"relay", "net.ipv4.tcp_slow_start_after_idle", "0", "lower", "idle-restart"},
		{"relay", "net.ipv4.tcp_keepalive_time", ka, "lower", "keepalive"},
		{"relay", "net.ipv4.tcp_keepalive_intvl", kai, "lower", "keepalive"},
		{"relay", "net.ipv4.tcp_keepalive_probes", kap, "lower", "keepalive"},
		{"relay", "net.ipv4.tcp_fin_timeout", fin, "lower", "fin-timeout"},
		{"relay", "net.ipv4.tcp_tw_reuse", "1", "prefer=1", "tw-reuse"},
		{"relay", "net.ipv4.ip_local_port_range", ports, "range", "ports"},
		{"relay", "net.ipv4.tcp_max_tw_buckets", tw, "raise", "tw-buckets"},
		{"routing", "net.ipv4.conf.all.rp_filter", "2", "loose", "rp-filter"},
		{"routing", "net.ipv4.conf.default.rp_filter", "2", "loose", "rp-filter"},
		{"routing", "net.ipv4.conf.all.send_redirects", "0", "lower", "redirects"},
		{"routing", "net.ipv4.conf.default.send_redirects", "0", "lower", "redirects"},
		{"routing", "net.ipv4.conf.all.accept_redirects", "0", "lower", "accept-redirects"},
		{"routing", "net.ipv4.conf.default.accept_redirects", "0", "lower", "accept-redirects"},
	}
}

// demoBounds matches gtm_optimize_bounds.
func demoBounds(key string, memory uint64) string {
	switch {
	case key == "net.netfilter.nf_conntrack_max":
		flows := min(max(memory/4/350, 65536), 16777216)
		return "n 32768 " + strconv.FormatUint(flows, 10)
	case key == "net.netfilter.nf_conntrack_buckets":
		return "n 8192 4194304"
	case key == "net.netfilter.nf_conntrack_tcp_timeout_established":
		return "n 300 432000"
	case strings.HasPrefix(key, "net.netfilter.nf_conntrack_tcp_timeout_"):
		return "n 5 300"
	case key == "net.netfilter.nf_conntrack_udp_timeout":
		return "n 10 600"
	case key == "net.netfilter.nf_conntrack_udp_timeout_stream":
		return "n 30 3600"
	case key == "net.core.default_qdisc":
		return "c fq,cake,fq_pie,fq_codel,pfifo_fast"
	case key == "net.ipv4.tcp_congestion_control":
		return "c reno,cubic,bbr"
	case key == "net.ipv4.tcp_rmem" || key == "net.ipv4.tcp_wmem":
		return "n3 4096 268435456"
	case key == "net.ipv4.ip_local_port_range":
		return "n2 1024 65535"
	case strings.HasSuffix(key, ".rp_filter"):
		return "n 0 2"
	case strings.HasSuffix(key, "_redirects"):
		return "n 0 1"
	}
	return map[string]string{
		"net.core.netdev_max_backlog": "n 1000 262144", "net.core.netdev_budget": "n 300 5000", "net.core.netdev_budget_usecs": "n 2000 32000",
		"net.core.somaxconn": "n 128 65535", "net.ipv4.tcp_max_syn_backlog": "n 128 262144", "net.core.rmem_max": "n 212992 268435456",
		"net.core.wmem_max": "n 212992 268435456", "net.ipv4.tcp_notsent_lowat": "n 16384 4294967295", "net.ipv4.tcp_mtu_probing": "n 0 2",
		"net.ipv4.tcp_tw_reuse": "n 0 2", "net.ipv4.tcp_slow_start_after_idle": "n 0 1", "net.ipv4.tcp_keepalive_time": "n 60 7200",
		"net.ipv4.tcp_keepalive_intvl": "n 5 120", "net.ipv4.tcp_keepalive_probes": "n 3 10", "net.ipv4.tcp_fin_timeout": "n 5 60",
		"net.ipv4.tcp_max_tw_buckets": "n 4096 4194304",
	}[key]
}

// customValid matches gtm_optimize_custom_valid.
func customValid(spec, value string) bool {
	var c OptimizeChange
	c.bounds(spec)
	switch c.Kind {
	case "choice":
		return oneOf(value, c.Choices...)
	case "number", "range", "triple":
		fields := strings.Fields(value)
		want := map[string]int{"number": 1, "range": 2, "triple": 3}[c.Kind]
		if len(fields) != want || strings.Join(fields, " ") != value {
			return false
		}
		previous := int64(-1)
		for _, f := range fields {
			v, e := strconv.ParseInt(f, 10, 64)
			if e != nil || uint64(v) < c.Min || uint64(v) > c.Max || v < previous || (c.Kind == "range" && v == previous) {
				return false
			}
			previous = v
		}
		return true
	}
	return false
}

// betterValue mirrors gtm_optimize_better: never worse than the base value.
func betterValue(current, wanted, mode string) string {
	n := func(v string) int { x, _ := strconv.Atoi(v); return x }
	switch {
	case mode == "raise":
		return map[bool]string{true: current, false: wanted}[n(current) >= n(wanted)]
	case mode == "lower":
		return map[bool]string{true: current, false: wanted}[n(current) <= n(wanted)]
	case mode == "raise3" || mode == "range":
		have, want := strings.Fields(current), strings.Fields(wanted)
		if len(have) != len(want) || len(have) < 2 {
			return wanted
		}
		out := make([]string, len(have))
		for i := range out {
			if mode == "range" && i == 0 {
				out[i] = strconv.Itoa(min(n(have[i]), n(want[i])))
			} else {
				out[i] = strconv.Itoa(max(n(have[i]), n(want[i])))
			}
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

// advise mirrors gtm_optimize_compute for one key: the value and its note.
func (d *demoOptimizer) advise(c catalogEntry, set map[string]string) (string, string) {
	current := d.values[c.key]
	base := current
	if j, ok := d.journal[c.key]; ok && j[1] == current {
		base = j[0]
	}
	if v, ok := set[c.key]; ok {
		note := "custom"
		if betterValue(base, v, c.mode) != v {
			note = "worse"
		}
		if v == current {
			note = "same"
		}
		return v, note
	}
	if c.value == "-" {
		if base == current {
			return base, "off"
		}
		return base, "change"
	}
	value := betterValue(base, c.value, c.mode)
	switch {
	case value != current:
		return value, "change"
	case current == c.value:
		return value, "same"
	}
	return value, "kept"
}

const demoServerTools = "/etc/sysctl.d/99-zz-server-tools.conf"

// The demo pretends ServerTools also sets one key, to show the notice.
var demoOthers = map[string]string{"net.netfilter.nf_conntrack_tcp_timeout_established": "7200"}

func newDemoOptimizer() *demoOptimizer {
	return &demoOptimizer{journal: map[string][3]string{}, profile: OptimizeProfile{Level: "balanced", Goal: "general"}, values: map[string]string{
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
		"net.ipv4.tcp_notsent_lowat": "4294967295", "net.ipv4.ip_local_port_range": "32768 60999", "net.ipv4.tcp_max_tw_buckets": "262144",
		"net.ipv4.conf.all.rp_filter": "0", "net.ipv4.conf.default.rp_filter": "1",
		"net.ipv4.conf.all.send_redirects": "1", "net.ipv4.conf.default.send_redirects": "1",
		"net.ipv4.conf.all.accept_redirects": "0", "net.ipv4.conf.default.accept_redirects": "1",
	}}
}

// chosen returns the requested profile, or the saved one when none is given.
func (d *demoOptimizer) chosen(in OptimizeInput) (OptimizeProfile, error) {
	p, e := in.profile()
	if e != nil {
		return OptimizeProfile{}, e
	}
	if p[0] == "-" {
		return d.profile, nil
	}
	return OptimizeProfile{Level: p[0], Goal: p[1]}, nil
}

func (d *demoOptimizer) plan(groups []string, profile OptimizeProfile, set map[string]string) OptimizePlan {
	p := OptimizePlan{Groups: groups, Profile: profile, Changes: []OptimizeChange{}}
	for _, c := range demoCatalog(profile.Level, profile.Goal, demoMemory) {
		if !oneOf(c.group, groups...) {
			continue
		}
		value, note := d.advise(c, set)
		change := OptimizeChange{Group: c.group, Key: c.key, Current: d.values[c.key], Value: value, Reason: c.reason, Note: note}
		change.bounds(demoBounds(c.key, demoMemory))
		if other, ok := demoOthers[c.key]; ok {
			change.OtherFile, change.OtherValue = demoServerTools, other
		}
		p.Changes = append(p.Changes, change)
	}
	return p
}

func (d *demoOptimizer) view(profile OptimizeProfile) OptimizeView {
	flows := uint64(23517)
	v := OptimizeView{Memory: demoMemory, Flows: &flows, Congestion: []string{"reno", "cubic", "bbr"}, Steps: len(d.steps), Last: d.last, Profile: d.profile, View: profile,
		Capped: profile.Level == "aggressive" && demoMemory < demoSmall, File: "/etc/sysctl.d/zz-gre-manager-optimize.conf", ServerTools: []string{demoServerTools}, Keys: []OptimizeKey{}}
	for _, c := range demoCatalog(profile.Level, profile.Goal, demoMemory) {
		value, note := d.advise(c, nil)
		k := OptimizeKey{Group: c.group, Key: c.key, Current: d.values[c.key], Recommended: value, Reason: c.reason, Note: note}
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

func (d *demoOptimizer) apply(groups []string, profile OptimizeProfile, in OptimizeInput) (string, error) {
	for key, value := range in.Set {
		if spec := demoBounds(key, demoMemory); spec == "" || !customValid(spec, value) {
			return "", errors.New("Custom value for " + key + " is outside its allowed range.")
		}
	}
	p := d.plan(groups, profile, in.Set)
	next, n := maps.Clone(d.journal), 0
	for _, c := range p.Changes {
		switch c.Note {
		case "worse":
			if !in.AllowWorse {
				return "", errors.New("The custom value for " + c.Key + " is worse than the server's original value; confirm it to apply.")
			}
		case "change", "custom":
		default:
			continue
		}
		before := c.Current
		if j, ok := next[c.Key]; ok {
			before = j[0]
		}
		if c.Value == before {
			delete(next, c.Key)
		} else {
			next[c.Key] = [3]string{before, c.Value, c.Group}
		}
		d.values[c.Key] = c.Value
		n++
	}
	if n == 0 {
		return "Nothing to change. " + demoMessage, nil
	}
	d.steps = append(d.steps, d.journal)
	d.journal, d.profile, d.last = next, profile, time.Now().Unix()
	return "Applied " + strconv.Itoa(n) + " setting(s). " + demoMessage, nil
}

func (d *Demo) optimizeDemo(r Request) (json.RawMessage, error) {
	if d.optimizer == nil {
		d.optimizer = newDemoOptimizer()
	}
	o := d.optimizer
	switch r.Action {
	case "optimize":
		profile, e := o.chosen(r.Optimize)
		if e != nil {
			return nil, e
		}
		return json.Marshal(o.view(profile))
	case "optimize-plan", "optimize-apply":
		groups, e := r.Optimize.groups()
		if e != nil {
			return nil, e
		}
		profile, e := o.chosen(r.Optimize)
		if e != nil {
			return nil, e
		}
		if _, e := r.Optimize.custom(); e != nil {
			return nil, e
		}
		if r.Action == "optimize-plan" {
			return json.Marshal(o.plan(groups, profile, r.Optimize.Set))
		}
		message, e := o.apply(groups, profile, r.Optimize)
		if e != nil {
			return nil, e
		}
		return json.Marshal(message)
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
		o.steps, o.last, o.profile = nil, 0, OptimizeProfile{Level: "balanced", Goal: "general"}
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
