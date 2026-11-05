package control

import (
	"context"
	"errors"
	"strconv"
	"strings"
	"time"

	"github.com/Sir-Adnan/GRE-Tunnel-Manager/panel/internal/health"
	"github.com/Sir-Adnan/GRE-Tunnel-Manager/panel/internal/model"
)

// DiagnoseCheck is one step of the guided check. Status is ok, warn, fail
// or info; the panel translates Key and suggests a fix.
type DiagnoseCheck struct {
	Key    string   `json:"key"`
	Status string   `json:"status"`
	Detail string   `json:"detail,omitempty"`
	RTT    *float64 `json:"rtt_ms,omitempty"`
}

// DiagnoseReport answers "why is this down" for one owner. Status is the
// worst check; Outage is the newest recorded outage when Health is on.
type DiagnoseReport struct {
	Owner  string          `json:"owner"`
	Time   time.Time       `json:"time"`
	Status string          `json:"status"`
	Checks []DiagnoseCheck `json:"checks"`
	Outage *health.Outage  `json:"outage,omitempty"`
}

var statusRank = map[string]int{"ok": 0, "info": 0, "warn": 1, "fail": 2}

func worst(checks []DiagnoseCheck) string {
	out := "ok"
	for _, c := range checks {
		if statusRank[c.Status] > statusRank[out] {
			out = c.Status
		}
	}
	return out
}

type diagnoseProbe struct {
	kind, address, key string
	port               int
}

func parseDiagnosis(out string) ([]DiagnoseCheck, []diagnoseProbe) {
	checks, probes := []DiagnoseCheck{}, []diagnoseProbe{}
	for _, line := range strings.Split(strings.TrimSpace(out), "\n") {
		f := strings.Split(line, "\t")
		switch {
		case len(f) == 4 && f[0] == "check" && oneOf(f[2], "ok", "warn", "fail", "info"):
			checks = append(checks, DiagnoseCheck{Key: f[1], Status: f[2], Detail: f[3]})
		case len(f) == 5 && f[0] == "probe" && len(probes) < 10:
			port, _ := strconv.Atoi(f[3])
			probes = append(probes, diagnoseProbe{kind: f[1], address: f[2], port: port, key: f[4]})
		}
	}
	return checks, probes
}

// diagnose runs the read-only Bash checks, then probes the listed
// endpoints from this server. UDP has no reliable probe: its destinations
// get a ping instead, reported as such.
func (m *Manager) diagnose(ctx context.Context, owner string) (DiagnoseReport, error) {
	if !model.IDPattern.MatchString(owner) && !greID.MatchString(owner) {
		return DiagnoseReport{}, errors.New("diagnosis supports connections and GRE tunnels")
	}
	out, e := m.call(ctx, "diagnose", "", owner)
	if e != nil {
		return DiagnoseReport{}, e
	}
	checks, probes := parseDiagnosis(out)
	targets := make([]health.Target, len(probes))
	for i, p := range probes {
		t := health.Target{Key: strconv.Itoa(i), Owner: owner, Kind: health.KindTCP, Address: p.address, Port: p.port}
		if p.kind != "tcp" {
			t.Kind, t.Port = health.KindICMP, 0
		}
		targets[i] = t
	}
	probeCtx, cancel := context.WithTimeout(ctx, 8*time.Second)
	results := health.Run(probeCtx, health.NetProber{Timeout: 3 * time.Second}, targets, 4)
	cancel()
	for i, p := range probes {
		r := results[strconv.Itoa(i)]
		c := DiagnoseCheck{Key: p.key, Status: "ok", Detail: targets[i].Endpoint()}
		if p.kind == "udp" {
			c.Key, c.Detail = p.key+"-ping", p.address
		}
		if r.OK {
			rtt := r.RTT
			c.RTT = &rtt
		} else {
			c.Status = "fail"
			if r.Error != "" {
				c.Detail += " · " + r.Error
			}
		}
		// A destination behind UDP may simply not answer pings.
		if p.kind == "udp" && !r.OK {
			c.Status = "warn"
		}
		checks = append(checks, c)
	}
	report := DiagnoseReport{Owner: owner, Time: time.Now().UTC(), Checks: checks, Status: worst(checks)}
	if m.Ops != nil {
		view := m.Ops.Health.View(time.Now().UTC(), time.UTC)
		for i := range view.Outages {
			if view.Outages[i].Owner == owner {
				o := view.Outages[i]
				report.Outage = &o
				break
			}
		}
	}
	return report, nil
}
