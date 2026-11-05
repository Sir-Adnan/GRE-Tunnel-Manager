package control

import (
	"context"
	"errors"
	"math"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/Sir-Adnan/GRE-Tunnel-Manager/panel/internal/health"
)

// greUnit is what a managed gre-tun-N unit declares.
type greUnit struct {
	ID     string
	Number int
	Iface  string
	Remote string
	Local  string
	// Address is this side's inner IPv4 address; Peer is the far side's.
	Address string
	Peer    string
}

var tunnelAdd = regexp.MustCompile(`ip (?:-6 )?tunnel add (gre(?:-out-)?[0-9]{1,3}) mode (?:gre|ip6gre) remote (\S+) local (\S+)`)

func parseGREUnit(path string) (greUnit, error) {
	base := strings.TrimSuffix(filepath.Base(path), ".service")
	m := greID.FindStringSubmatch(base)
	if m == nil {
		return greUnit{}, errors.New("not a GRE unit")
	}
	n, _ := strconv.Atoi(m[1])
	data, e := os.ReadFile(path)
	if e != nil || len(data) > 8192 {
		return greUnit{}, errors.New("GRE unit unreadable")
	}
	t := tunnelAdd.FindStringSubmatch(string(data))
	if t == nil {
		return greUnit{}, errors.New("unrecognized GRE unit")
	}
	remote, e1 := netip.ParseAddr(t[2])
	local, e2 := netip.ParseAddr(t[3])
	if e1 != nil || e2 != nil {
		return greUnit{}, errors.New("unrecognized GRE unit")
	}
	own, peer := 1, 2
	if strings.HasPrefix(t[1], "gre-out-") {
		own, peer = 2, 1
	}
	return greUnit{ID: base, Number: n, Iface: t[1], Remote: remote.String(), Local: local.String(),
		Address: "10.0." + m[1] + "." + strconv.Itoa(own), Peer: "10.0." + m[1] + "." + strconv.Itoa(peer)}, nil
}

// greUnits lists at most 32 managed GRE tunnels.
func (m *Manager) greUnits() []greUnit {
	paths, _ := filepath.Glob(filepath.Join(m.UnitDir, "gre-tun-*.service"))
	sort.Strings(paths)
	out := []greUnit{}
	for _, p := range paths {
		if u, e := parseGREUnit(p); e == nil {
			out = append(out, u)
		}
		if len(out) == 32 {
			break
		}
	}
	return out
}

// ProbeTunnel is one GRE tunnel checked from this server.
type ProbeTunnel struct {
	ID      string   `json:"id"`
	Remote  string   `json:"remote"`
	Local   string   `json:"local"`
	Address string   `json:"address"`
	Peer    string   `json:"peer"`
	Up      bool     `json:"up"`
	OK      bool     `json:"ok"`
	RTT     *float64 `json:"rtt_ms,omitempty"`
	Error   string   `json:"error,omitempty"`
}

type ProbeHost struct {
	CPU             *float64 `json:"cpu_percent,omitempty"`
	MemoryTotal     uint64   `json:"memory_total"`
	MemoryAvailable uint64   `json:"memory_available"`
	ConntrackCount  *uint64  `json:"conntrack_count,omitempty"`
	ConntrackMax    *uint64  `json:"conntrack_max,omitempty"`
}

// ProbeReport is what a Node tells its Controller about its side: host
// pressure and whether each GRE peer answers from here.
type ProbeReport struct {
	Time    time.Time     `json:"time"`
	Host    ProbeHost     `json:"host"`
	Tunnels []ProbeTunnel `json:"tunnels"`
}

func readUint(path string) *uint64 {
	data, e := os.ReadFile(path)
	if e != nil {
		return nil
	}
	v, e := strconv.ParseUint(strings.TrimSpace(string(data)), 10, 64)
	if e != nil {
		return nil
	}
	return &v
}

// nodeProbes pings every GRE peer once (bounded, in parallel).
func (m *Manager) nodeProbes(ctx context.Context) ProbeReport {
	t := m.telemetry.Sample()
	r := ProbeReport{Time: time.Now().UTC(), Tunnels: []ProbeTunnel{},
		Host: ProbeHost{CPU: t.CPU, MemoryTotal: t.MemoryTotal, MemoryAvailable: t.MemoryAvailable,
			ConntrackCount: readUint("/proc/sys/net/netfilter/nf_conntrack_count"), ConntrackMax: readUint("/proc/sys/net/netfilter/nf_conntrack_max")}}
	units := m.greUnits()
	targets := make([]health.Target, len(units))
	for i, u := range units {
		targets[i] = health.Target{Key: u.ID, Owner: u.ID, Kind: health.KindICMP, Address: u.Peer}
	}
	probe, cancel := context.WithTimeout(ctx, 6*time.Second)
	results := health.Run(probe, health.NetProber{Timeout: 2 * time.Second}, targets, 8)
	cancel()
	for _, u := range units {
		state, _ := os.ReadFile("/sys/class/net/" + u.Iface + "/operstate")
		_, exists := os.Stat("/sys/class/net/" + u.Iface)
		res := results[u.ID]
		p := ProbeTunnel{ID: u.ID, Remote: u.Remote, Local: u.Local, Address: u.Address, Peer: u.Peer, Up: exists == nil && strings.TrimSpace(string(state)) != "down", OK: res.OK, Error: res.Error}
		if res.OK {
			rtt := res.RTT
			p.RTT = &rtt
		}
		r.Tunnels = append(r.Tunnels, p)
	}
	return r
}

// QualityReport summarizes a burst of pings to the far end of a tunnel.
type QualityReport struct {
	Owner    string    `json:"owner"`
	Peer     string    `json:"peer"`
	Time     time.Time `json:"time"`
	Sent     int       `json:"sent"`
	Received int       `json:"received"`
	Loss     float64   `json:"loss_percent"`
	Min      *float64  `json:"min_ms,omitempty"`
	Avg      *float64  `json:"avg_ms,omitempty"`
	Max      *float64  `json:"max_ms,omitempty"`
	Jitter   *float64  `json:"jitter_ms,omitempty"`
	Samples  []float64 `json:"samples"`
}

const qualityPings = 20

// greQuality sends 20 pings, 200 ms apart, to the inner peer address.
func (m *Manager) greQuality(ctx context.Context, owner string) (QualityReport, error) {
	if !greID.MatchString(owner) {
		return QualityReport{}, errors.New("the quality test runs on GRE tunnels")
	}
	u, e := parseGREUnit(filepath.Join(m.UnitDir, owner+".service"))
	if e != nil {
		return QualityReport{}, e
	}
	return runQuality(ctx, health.NetProber{Timeout: time.Second}, owner, u.Peer, 200*time.Millisecond), nil
}

func runQuality(ctx context.Context, p health.Prober, owner, peer string, spacing time.Duration) QualityReport {
	r := QualityReport{Owner: owner, Peer: peer, Time: time.Now().UTC(), Samples: []float64{}}
	sum, previous, jitter, pairs := 0.0, -1.0, 0.0, 0
	for i := 0; i < qualityPings; i++ {
		if i > 0 {
			select {
			case <-ctx.Done():
				i = qualityPings
				continue
			case <-time.After(spacing):
			}
		}
		r.Sent++
		res := p.Probe(ctx, health.Target{Kind: health.KindICMP, Address: peer})
		if !res.OK {
			r.Samples = append(r.Samples, -1)
			continue
		}
		rtt := math.Round(res.RTT*100) / 100
		r.Received++
		r.Samples = append(r.Samples, rtt)
		sum += rtt
		if r.Min == nil || rtt < *r.Min {
			v := rtt
			r.Min = &v
		}
		if r.Max == nil || rtt > *r.Max {
			v := rtt
			r.Max = &v
		}
		if previous >= 0 {
			jitter += math.Abs(rtt - previous)
			pairs++
		}
		previous = rtt
	}
	if r.Sent > 0 {
		r.Loss = math.Round(float64(r.Sent-r.Received)*1000/float64(r.Sent)) / 10
	}
	if r.Received > 0 {
		avg := math.Round(sum/float64(r.Received)*100) / 100
		r.Avg = &avg
	}
	if pairs > 0 {
		j := math.Round(jitter/float64(pairs)*100) / 100
		r.Jitter = &j
	}
	return r
}
