package health

import (
	"errors"
	"io"
	"math"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

// HostSnapshot is read from /proc and /sys only; no subprocess is started.
type HostSnapshot struct {
	Time               time.Time `json:"time"`
	ConntrackCount     *uint64   `json:"conntrack_count,omitempty"`
	ConntrackMax       *uint64   `json:"conntrack_max,omitempty"`
	ConntrackPercent   *float64  `json:"conntrack_percent,omitempty"`
	Hashsize           *uint64   `json:"conntrack_buckets,omitempty"`
	EstablishedTimeout *uint64   `json:"tcp_established_timeout,omitempty"`
	// Drops, EarlyDrops and InsertFailed are increases since the previous sample.
	Drops        uint64   `json:"drops"`
	EarlyDrops   uint64   `json:"early_drops"`
	InsertFailed uint64   `json:"insert_failed"`
	CPU          *float64 `json:"cpu_percent,omitempty"`
	Steal        *float64 `json:"steal_percent,omitempty"`
	SoftIRQ      *float64 `json:"softirq_percent,omitempty"`
	IOWait       *float64 `json:"iowait_percent,omitempty"`
	ConntrackCLI bool     `json:"conntrack_cli"`
	Hints        []string `json:"hints"`
}

// Hint keys are stable API values; the interface translates them.
const (
	HintConntrackTimeout = "conntrackDefaultTimeout"
	HintConntrackHigh    = "conntrackHigh"
	HintConntrackDrops   = "conntrackDrops"
	HintConntrackBuckets = "conntrackBuckets"
	HintSteal            = "cpuSteal"
	HintSoftIRQ          = "cpuSoftIRQ"
)

type cpuTimes struct {
	total, idle, iowait, softirq, steal uint64
	valid                               bool
}

// HostSampler keeps the previous counters so each sample reports deltas.
type HostSampler struct {
	mu    sync.Mutex
	read  func(string) ([]byte, error)
	cpu   cpuTimes
	stats map[string]uint64
}

func NewHostSampler() *HostSampler { return &HostSampler{read: readSmall} }

func readSmall(path string) ([]byte, error) {
	f, e := os.Open(path)
	if e != nil {
		return nil, e
	}
	defer f.Close()
	b, e := io.ReadAll(io.LimitReader(f, 256*1024+1))
	if len(b) > 256*1024 {
		return nil, errors.New("kernel file exceeds size limit")
	}
	return b, e
}

func (h *HostSampler) number(path string) *uint64 {
	data, e := h.read(path)
	if e != nil {
		return nil
	}
	v, e := strconv.ParseUint(strings.TrimSpace(string(data)), 10, 64)
	if e != nil {
		return nil
	}
	return &v
}

func (h *HostSampler) Sample(now time.Time) *HostSnapshot {
	h.mu.Lock()
	defer h.mu.Unlock()
	s := &HostSnapshot{Time: now, Hints: []string{}}
	s.ConntrackCount = h.number("/proc/sys/net/netfilter/nf_conntrack_count")
	s.ConntrackMax = h.number("/proc/sys/net/netfilter/nf_conntrack_max")
	s.Hashsize = h.number("/sys/module/nf_conntrack/parameters/hashsize")
	s.EstablishedTimeout = h.number("/proc/sys/net/netfilter/nf_conntrack_tcp_timeout_established")
	if s.ConntrackCount != nil && s.ConntrackMax != nil && *s.ConntrackMax > 0 {
		p := round1(100 * float64(*s.ConntrackCount) / float64(*s.ConntrackMax))
		s.ConntrackPercent = &p
	}
	if data, e := h.read("/proc/net/stat/nf_conntrack"); e == nil {
		next := conntrackStats(string(data))
		if h.stats != nil {
			s.Drops = grow(h.stats["drop"], next["drop"])
			s.EarlyDrops = grow(h.stats["early_drop"], next["early_drop"])
			s.InsertFailed = grow(h.stats["insert_failed"], next["insert_failed"])
		}
		h.stats = next
	}
	if data, e := h.read("/proc/stat"); e == nil {
		next := parseCPU(string(data))
		if next.valid && h.cpu.valid && next.total > h.cpu.total {
			d := float64(next.total - h.cpu.total)
			share := func(a, b uint64) *float64 {
				if a < b {
					return nil
				}
				v := round1(100 * float64(a-b) / d)
				return &v
			}
			if next.idle >= h.cpu.idle {
				busy := round1(100 - 100*float64(next.idle-h.cpu.idle)/d)
				busy = math.Max(0, busy)
				s.CPU = &busy
			}
			s.Steal = share(next.steal, h.cpu.steal)
			s.SoftIRQ = share(next.softirq, h.cpu.softirq)
			s.IOWait = share(next.iowait, h.cpu.iowait)
		}
		h.cpu = next
	}
	s.Hints = hints(s)
	return s
}

func grow(old, next uint64) uint64 {
	if next < old {
		return 0
	}
	return next - old
}

// conntrackStats sums the per-CPU hexadecimal columns named by the header line.
func conntrackStats(text string) map[string]uint64 {
	lines := strings.Split(strings.TrimSpace(text), "\n")
	out := map[string]uint64{}
	if len(lines) < 2 {
		return out
	}
	names := strings.Fields(lines[0])
	for _, line := range lines[1:] {
		for i, field := range strings.Fields(line) {
			if i >= len(names) {
				break
			}
			if v, e := strconv.ParseUint(field, 16, 64); e == nil {
				out[names[i]] += v
			}
		}
	}
	return out
}

// parseCPU reads the aggregate line: user nice system idle iowait irq softirq steal.
func parseCPU(text string) cpuTimes {
	f := strings.Fields(strings.SplitN(text, "\n", 2)[0])
	if len(f) < 9 || f[0] != "cpu" {
		return cpuTimes{}
	}
	v := make([]uint64, 8)
	for i := range v {
		n, e := strconv.ParseUint(f[i+1], 10, 64)
		if e != nil {
			return cpuTimes{}
		}
		v[i] = n
	}
	t := cpuTimes{iowait: v[4], softirq: v[6], steal: v[7], valid: true}
	for _, n := range v {
		t.total += n
	}
	// iowait is idle time from the CPU's point of view.
	t.idle = v[3] + v[4]
	return t
}

func hints(s *HostSnapshot) []string {
	out := []string{}
	if s.EstablishedTimeout != nil && *s.EstablishedTimeout >= 86400 {
		out = append(out, HintConntrackTimeout)
	}
	if s.ConntrackPercent != nil && *s.ConntrackPercent >= 80 {
		out = append(out, HintConntrackHigh)
	}
	if s.Drops+s.EarlyDrops+s.InsertFailed > 0 {
		out = append(out, HintConntrackDrops)
	}
	if s.Hashsize != nil && s.ConntrackMax != nil && *s.Hashsize > 0 && *s.ConntrackMax > 8**s.Hashsize {
		out = append(out, HintConntrackBuckets)
	}
	if s.Steal != nil && *s.Steal >= 10 {
		out = append(out, HintSteal)
	}
	if s.SoftIRQ != nil && *s.SoftIRQ >= 25 {
		out = append(out, HintSoftIRQ)
	}
	return out
}
