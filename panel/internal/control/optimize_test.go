package control

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
)

func TestOptimizeProfileArgumentsAndBounds(t *testing.T) {
	if p, e := (OptimizeInput{}).profile(); e != nil || strings.Join(p, " ") != "- -" {
		t.Fatalf("saved profile: %v %v", p, e)
	}
	for _, bad := range []OptimizeInput{{Level: "turbo", Goal: "general"}, {Level: "balanced"}, {Level: "balanced", Goal: "x;id"}} {
		if _, e := bad.profile(); e == nil {
			t.Fatalf("accepted %+v", bad)
		}
	}
	in := OptimizeInput{Set: map[string]string{"net.core.somaxconn": "16384", "net.ipv4.tcp_rmem": "4096 131072 67108864"}}
	if c, e := in.custom(); e != nil || strings.Join(c, "|") != "net.core.somaxconn=16384|net.ipv4.tcp_rmem=4096 131072 67108864" {
		t.Fatalf("custom: %v %v", c, e)
	}
	for _, bad := range []map[string]string{{"net.core.somaxconn": "1;id"}, {"kernel.panic": "1"}, {"net.core.somaxconn": "$(id)"}} {
		if _, e := (OptimizeInput{Set: bad}).custom(); e == nil {
			t.Fatalf("accepted %v", bad)
		}
	}
	plan := parseOptimizePlan([]string{"relay"}, OptimizeProfile{Level: "aggressive", Goal: "users"},
		"change\trelay\tnet.ipv4.tcp_rmem\t4096 131072 6291456\t8192 262144 67108864\tbuffers\tchange\t-\t-\tn3 4096 268435456\n"+
			"change\trelay\tnet.core.default_qdisc\tcake\tcake\tpacing\tkept\t-\t-\tc fq,cake,fq_pie\n"+
			"change\trelay\tnet.ipv4.tcp_max_tw_buckets\t262144\t262144\ttw-buckets\toff\t-\t-\n")
	if len(plan.Changes) != 3 || plan.Changes[0].Kind != "triple" || plan.Changes[0].Max != 268435456 || plan.Changes[1].Kind != "choice" || len(plan.Changes[1].Choices) != 3 || plan.Changes[2].Kind != "" {
		t.Fatalf("plan: %+v", plan)
	}
	v, e := parseOptimizeStatus("meta\tfile\t/x\nmeta\tprofile\taggressive users\nmeta\tview\tconservative latency\nmeta\tcapped\t1\nmeta\tlast\t1700000000\n")
	if e != nil || v.Profile.Level != "aggressive" || v.View.Goal != "latency" || !v.Capped || v.Last != 1700000000 {
		t.Fatalf("status: %+v %v", v, e)
	}
	for spec, cases := range map[string]map[string]bool{
		"n 5 60":            {"5": true, "61": false, "4": false, "1 2": false},
		"n3 4096 268435456": {"4096 131072 33554432": true, "8192 4096 33554432": false, "4096 131072": false},
		"n2 1024 65535":     {"16384 65535": true, "65535 16384": false, "1000 2000": false, "2000 2000": false},
		"c fq,cake":         {"cake": true, "pfifo": false},
	} {
		for value, ok := range cases {
			if customValid(spec, value) != ok {
				t.Fatalf("%s %q", spec, value)
			}
		}
	}
}

func TestDemoOptimizeProfilesNeverGoBelowOriginal(t *testing.T) {
	d := NewDemo()
	ctx := context.Background()
	plan := func(in OptimizeInput) OptimizePlan {
		t.Helper()
		raw, e := d.Do(ctx, Request{Action: "optimize-plan", Optimize: in})
		var p OptimizePlan
		if e != nil || json.Unmarshal(raw, &p) != nil {
			t.Fatalf("plan: %s %v", raw, e)
		}
		return p
	}
	find := func(p OptimizePlan, key string) OptimizeChange {
		for _, c := range p.Changes {
			if c.Key == key {
				return c
			}
		}
		t.Fatalf("no %s", key)
		return OptimizeChange{}
	}
	users := plan(OptimizeInput{Groups: []string{"relay"}, Level: "aggressive", Goal: "users"})
	if c := find(users, "net.ipv4.ip_local_port_range"); c.Value != "16384 65535" || c.Note != "change" || c.Kind != "range" {
		t.Fatalf("ports: %+v", c)
	}
	// The demo host has 1 GiB, so aggressive keeps balanced buffers.
	if c := find(users, "net.core.rmem_max"); c.Value != "33554432" {
		t.Fatalf("capped buffers: %+v", c)
	}
	if _, e := d.Do(ctx, Request{Action: "optimize-apply", Optimize: OptimizeInput{Groups: []string{"relay"}, Level: "aggressive", Goal: "users"}}); e != nil {
		t.Fatal(e)
	}
	// A lighter profile returns keys toward, never below, their original values.
	light := plan(OptimizeInput{Groups: []string{"relay"}, Level: "conservative", Goal: "general"})
	if c := find(light, "net.ipv4.ip_local_port_range"); c.Value != "32768 60999" || c.Note != "change" {
		t.Fatalf("ports back: %+v", c)
	}
	if c := find(light, "net.ipv4.tcp_keepalive_time"); c.Value != "1800" || c.Current != "300" {
		t.Fatalf("keepalive: %+v", c)
	}
	if c := find(light, "net.ipv4.tcp_notsent_lowat"); c.Value != "4294967295" || c.Note != "change" {
		t.Fatalf("notsent back to original: %+v", c)
	}
	// Custom values: within bounds, and a worse one needs confirmation.
	worse := OptimizeInput{Groups: []string{"relay"}, Level: "balanced", Goal: "general", Set: map[string]string{"net.ipv4.tcp_keepalive_probes": "10", "net.ipv4.tcp_fin_timeout": "20"}}
	p := plan(worse)
	if find(p, "net.ipv4.tcp_fin_timeout").Note != "custom" || find(p, "net.ipv4.tcp_keepalive_probes").Note != "worse" {
		t.Fatalf("custom notes: %+v", p.Changes)
	}
	if _, e := d.Do(ctx, Request{Action: "optimize-apply", Optimize: worse}); e == nil || !strings.Contains(e.Error(), "worse") {
		t.Fatalf("worse value applied without confirmation: %v", e)
	}
	worse.AllowWorse = true
	if _, e := d.Do(ctx, Request{Action: "optimize-apply", Optimize: worse}); e != nil {
		t.Fatal(e)
	}
	if _, e := d.Do(ctx, Request{Action: "optimize-apply", Optimize: OptimizeInput{Groups: []string{"relay"}, Set: map[string]string{"net.ipv4.tcp_fin_timeout": "1"}}}); e == nil {
		t.Fatal("out-of-range custom value applied")
	}
	raw, _ := d.Do(ctx, Request{Action: "optimize"})
	var v OptimizeView
	if json.Unmarshal(raw, &v) != nil || v.Profile.Level != "balanced" || v.Last == 0 || v.Capped {
		t.Fatalf("view: %s", raw)
	}
	raw, _ = d.Do(ctx, Request{Action: "optimize", Optimize: OptimizeInput{Level: "aggressive", Goal: "latency"}})
	if json.Unmarshal(raw, &v) != nil || !v.Capped || v.View.Goal != "latency" {
		t.Fatalf("aggressive view: %s", raw)
	}
}
