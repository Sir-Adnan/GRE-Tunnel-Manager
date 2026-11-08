package control

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/Sir-Adnan/GRE-Tunnel-Manager/panel/internal/health"
	"slices"
	"strings"
	"time"

	"github.com/Sir-Adnan/GRE-Tunnel-Manager/panel/internal/model"
)

// demoPoint is an in-memory restore point: the connections before a change.
type demoPoint struct {
	name        string
	connections []model.Connection
}

func demoPointName(t time.Time, n int) string {
	return fmt.Sprintf("%s-%d-%d.tsv", t.UTC().Format("20060102T150405"), 4000+n, 1000+n)
}

// seedHistory gives the demo two earlier states: before the relay and the
// pool were added, and before the pool's third destination.
func (d *Demo) seedHistory() {
	now := time.Now().UTC()
	all := slices.Clone(d.inventory.Connections)
	older := slices.Clone(all[:2])
	pool := all[3]
	pool.Targets = slices.Clone(pool.Targets[:2])
	if rows, e := pool.Rows(pool.ID); e == nil {
		pool.Revision = model.Revision(rows[0])
	}
	middle := append(slices.Clone(all[:3]), pool)
	d.points = []demoPoint{{demoPointName(now.Add(-72*time.Hour), 1), older}, {demoPointName(now.Add(-26*time.Hour), 2), middle}}
}

// rememberChange records a restore point when a mutation changed anything.
func (d *Demo) rememberChange(before []model.Connection) {
	changed := len(before) != len(d.inventory.Connections)
	for i := 0; !changed && i < len(before); i++ {
		changed = before[i].Revision != d.inventory.Connections[i].Revision
	}
	if !changed {
		return
	}
	d.points = append(d.points, demoPoint{demoPointName(time.Now(), len(d.points)+1), before})
	if len(d.points) > 30 {
		d.points = d.points[len(d.points)-30:]
	}
}

func (d *Demo) demoRevision() string {
	rows := []string{}
	for _, c := range d.inventory.Connections {
		rows = append(rows, c.Revision)
	}
	return model.Revision(strings.Join(rows, ","))
}

func (d *Demo) historyDemo(r Request) (json.RawMessage, error) {
	if d.points == nil {
		d.seedHistory()
	}
	data := historyData{revision: d.demoRevision(), total: len(d.points)}
	for i := len(d.points) - 1; i >= 0; i-- {
		data.points = append(data.points, historyPoint{name: d.points[i].name, connections: d.points[i].connections})
	}
	switch r.Action {
	case "history":
		return json.Marshal(historyView(data, d.inventory.Connections))
	case "history-review":
		review, e := reviewPoint(data, d.inventory.Connections, r.History.Point)
		if e != nil {
			return nil, e
		}
		return json.Marshal(review)
	}
	if r.History.Revision != data.revision {
		return nil, errors.New("Configuration changed; review the restore again.")
	}
	i := slices.IndexFunc(d.points, func(p demoPoint) bool { return p.name == r.History.Point })
	if i < 0 {
		return nil, errors.New("Restore point not found.")
	}
	before := slices.Clone(d.inventory.Connections)
	d.inventory.Connections = slices.Clone(d.points[i].connections)
	d.rememberChange(before)
	return json.Marshal("Saved and applied. " + demoMessage)
}

func (d *Demo) diagnoseDemo(owner string) (json.RawMessage, error) {
	if !model.IDPattern.MatchString(owner) && !greID.MatchString(owner) {
		return nil, errors.New("diagnosis supports connections and GRE tunnels")
	}
	rtt := func(v float64) *float64 { return &v }
	checks := []DiagnoseCheck{}
	if greID.MatchString(owner) {
		checks = []DiagnoseCheck{{Key: "service", Status: "ok", Detail: owner}, {Key: "interface", Status: "ok", Detail: "gre1"}, {Key: "local-address", Status: "ok", Detail: "203.0.113.10"},
			{Key: "inner-address", Status: "ok", Detail: "10.0.1.1/30"}, {Key: "rp-filter", Status: "ok"}, {Key: "gre-input", Status: "ok", Detail: "ACCEPT"},
			{Key: "conntrack", Status: "ok", Detail: "23517/262144"}, {Key: "peer-public", Status: "ok", Detail: "198.51.100.5", RTT: rtt(41.2)}, {Key: "peer-inner", Status: "fail", Detail: "10.0.1.2 · timeout"}}
	} else {
		i := slices.IndexFunc(d.inventory.Connections, func(c model.Connection) bool { return c.ID == owner })
		if i < 0 {
			return nil, errors.New("Connection not found.")
		}
		c := d.inventory.Connections[i]
		checks = append(checks, DiagnoseCheck{Key: "enabled", Status: map[bool]string{true: "ok", false: "fail"}[c.Enabled]})
		if c.Engine == "nftables" || c.Engine == "iptables" {
			checks = append(checks, DiagnoseCheck{Key: "forwarding", Status: "ok", Detail: "IPv4"}, DiagnoseCheck{Key: "rules", Status: "ok", Detail: "6"},
				DiagnoseCheck{Key: "entrance", Status: "ok", Detail: "all local addresses"},
				DiagnoseCheck{Key: "forward-policy", Status: "ok", Detail: "DROP, owned accept installed"},
				DiagnoseCheck{Key: "source-address", Status: "info", Detail: "masquerade"})
			if c.ID == "F000004" {
				checks = append(checks, DiagnoseCheck{Key: "failover", Status: "warn", Detail: "2"})
			}
		} else {
			checks = append(checks, DiagnoseCheck{Key: "service", Status: "ok", Detail: "gtm-" + c.ID}, DiagnoseCheck{Key: "listener", Status: "ok", Detail: "tcp/" + c.Ports})
		}
		checks = append(checks, DiagnoseCheck{Key: "conntrack", Status: "ok", Detail: "23517/262144"})
		for n, t := range c.Targets {
			checks = append(checks, DiagnoseCheck{Key: "route", Status: "ok", Detail: t.IP + " via eth0"})
			probe := DiagnoseCheck{Key: "destination", Status: "ok", Detail: fmt.Sprintf("%s:%d", t.IP, t.Port), RTT: rtt(38.5 + float64(n)*4)}
			if c.Protocol == "udp" {
				probe.Key, probe.Detail = "destination-ping", t.IP
			}
			if c.ID == "F000002" {
				probe.Status, probe.RTT, probe.Detail = "warn", nil, t.IP+" · timeout"
			}
			checks = append(checks, probe)
		}
	}
	return json.Marshal(DiagnoseReport{Owner: owner, Time: time.Now().UTC(), Checks: checks, Status: worst(checks)})
}

// demoPinger answers like a real tunnel: some jitter and one lost ping.
type demoPinger struct{ n *int }

func (p demoPinger) Probe(_ context.Context, t health.Target) health.Result {
	*p.n++
	if *p.n%20 == 13 {
		return health.Result{Error: "timeout"}
	}
	return health.Result{OK: true, RTT: 36 + float64((*p.n*7)%11) + float64(*p.n%3)/4}
}
