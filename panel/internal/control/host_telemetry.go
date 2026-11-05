package control

import (
	"errors"
	"io"
	"os"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Read-only, on-demand kernel telemetry. No subprocesses, database, background
// collector or tunnel inventory scans. The zero value is ready to use.
type hostSampler struct {
	mu   sync.Mutex
	last hostSample
	view HostTelemetry
}
type HostTelemetry struct {
	Time            time.Time `json:"time"`
	Window          float64   `json:"window_seconds"`
	CPU             *float64  `json:"cpu_percent"`
	MemoryTotal     uint64    `json:"memory_total"`
	MemoryAvailable uint64    `json:"memory_available"`
	Received        *float64  `json:"received_per_second"`
	Sent            *float64  `json:"sent_per_second"`
	Interfaces      []string  `json:"interfaces"`
	Error           string    `json:"error,omitempty"`
}
type netBytes struct{ rx, tx uint64 }
type hostSample struct {
	time        time.Time
	total, idle uint64
	cpuValid    bool
	interfaces  map[string]netBytes
}

func readKernelFile(path string) ([]byte, error) {
	f, e := os.Open(path)
	if e != nil {
		return nil, e
	}
	defer f.Close()
	b, e := io.ReadAll(io.LimitReader(f, 1024*1024+1))
	if len(b) > 1024*1024 {
		return nil, errors.New("kernel telemetry file exceeds size limit")
	}
	return b, e
}
func (s *hostSampler) Sample() HostTelemetry {
	return s.sample(time.Now().UTC(), readKernelFile)
}
func (s *hostSampler) sample(now time.Time, read func(string) ([]byte, error)) HostTelemetry {
	s.mu.Lock()
	defer s.mu.Unlock()
	// Several open dashboards share one sample; 1-second polling still gets
	// a fresh window each time.
	if !s.view.Time.IsZero() && now.Sub(s.view.Time) < 900*time.Millisecond {
		return s.view
	}
	v := HostTelemetry{Time: now, Interfaces: []string{}}
	next := hostSample{time: now, interfaces: map[string]netBytes{}}
	stat, err := read("/proc/stat")
	if err == nil {
		next.total, next.idle, next.cpuValid = cpuTimes(string(stat))
	}
	if !next.cpuValid {
		v.Error = "CPU sample unavailable"
	}
	mem, err := read("/proc/meminfo")
	if err == nil {
		v.MemoryTotal, v.MemoryAvailable = memoryBytes(string(mem))
	}
	if v.MemoryTotal == 0 {
		v.Error = "Memory sample unavailable"
	}
	// Count only default-route interfaces to avoid adding the same packet on
	// a GRE/veth/bridge leg and its outer network leg. Include IPv4 and IPv6.
	route4, e4 := read("/proc/net/route")
	route6, e6 := read("/proc/net/ipv6_route")
	names := defaultInterfaces(string(route4), string(route6))
	dev, ed := read("/proc/net/dev")
	if ed == nil && (e4 == nil || e6 == nil) {
		next.interfaces = interfaceBytes(string(dev), names)
	}
	for name := range next.interfaces {
		v.Interfaces = append(v.Interfaces, name)
	}
	slices.Sort(v.Interfaces)
	window := now.Sub(s.last.time).Seconds()
	if window >= 0.9 && window <= 30 {
		v.Window = window
		if next.cpuValid && s.last.cpuValid && next.total > s.last.total && next.idle >= s.last.idle {
			total, idle := next.total-s.last.total, next.idle-s.last.idle
			if idle <= total {
				percent := 100 * float64(total-idle) / float64(total)
				v.CPU = &percent
			}
		}
		// Route changes and counter resets start a fresh baseline, never a spike.
		oldNames := make([]string, 0, len(s.last.interfaces))
		for n := range s.last.interfaces {
			oldNames = append(oldNames, n)
		}
		slices.Sort(oldNames)
		if len(v.Interfaces) > 0 && slices.Equal(v.Interfaces, oldNames) {
			rx, tx, valid := uint64(0), uint64(0), true
			for n, c := range next.interfaces {
				old := s.last.interfaces[n]
				if c.rx < old.rx || c.tx < old.tx {
					valid = false
					break
				}
				rx = addTraffic(rx, c.rx-old.rx)
				tx = addTraffic(tx, c.tx-old.tx)
			}
			if valid {
				a, b := float64(rx)/window, float64(tx)/window
				v.Received = &a
				v.Sent = &b
			}
		}
	}
	if len(v.Interfaces) == 0 {
		v.Error = "No default-route network counters available"
	}
	s.last = next
	s.view = v
	return v
}
func cpuTimes(text string) (total, idle uint64, valid bool) {
	line := strings.SplitN(text, "\n", 2)[0]
	f := strings.Fields(line)
	if len(f) < 5 || f[0] != "cpu" {
		return
	}
	// guest/guest_nice are already included in user/nice; do not count twice.
	for i := 1; i < len(f) && i <= 8; i++ {
		n, e := strconv.ParseUint(f[i], 10, 64)
		if e != nil {
			return 0, 0, false
		}
		total = addTraffic(total, n)
		if i == 4 || i == 5 {
			idle = addTraffic(idle, n)
		}
	}
	return total, idle, total >= idle
}
func memoryBytes(text string) (total, available uint64) {
	for _, line := range strings.Split(text, "\n") {
		f := strings.Fields(line)
		if len(f) != 3 || f[2] != "kB" {
			continue
		}
		n, e := strconv.ParseUint(f[1], 10, 54)
		if e != nil {
			continue
		}
		switch f[0] {
		case "MemTotal:":
			total = n * 1024
		case "MemAvailable:":
			available = n * 1024
		}
	}
	return total, min(total, available)
}
func defaultInterfaces(v4, v6 string) map[string]bool {
	names := map[string]bool{}
	for _, line := range strings.Split(v4, "\n") {
		f := strings.Fields(line)
		if len(f) < 8 || f[1] != "00000000" || f[7] != "00000000" {
			continue
		}
		flags, e := strconv.ParseUint(f[3], 16, 64)
		if e == nil && flags&1 != 0 && flags&0x200 == 0 && f[0] != "lo" && modelInterface(f[0]) {
			names[f[0]] = true
		}
	}
	for _, line := range strings.Split(v6, "\n") {
		f := strings.Fields(line)
		if len(f) != 10 || f[0] != strings.Repeat("0", 32) || f[1] != "00" {
			continue
		}
		flags, e := strconv.ParseUint(f[8], 16, 64)
		if e == nil && flags&1 != 0 && flags&0x200 == 0 && f[9] != "lo" && modelInterface(f[9]) {
			names[f[9]] = true
		}
	}
	return names
}
func interfaceBytes(text string, names map[string]bool) map[string]netBytes {
	result := map[string]netBytes{}
	for _, line := range strings.Split(text, "\n") {
		parts := strings.SplitN(line, ":", 2)
		if len(parts) != 2 {
			continue
		}
		name := strings.TrimSpace(parts[0])
		if !names[name] {
			continue
		}
		f := strings.Fields(parts[1])
		if len(f) < 16 {
			continue
		}
		rx, e1 := strconv.ParseUint(f[0], 10, 64)
		tx, e2 := strconv.ParseUint(f[8], 10, 64)
		if e1 == nil && e2 == nil {
			result[name] = netBytes{rx, tx}
		}
	}
	return result
}

func demoTelemetry() HostTelemetry {
	cpu, rx, tx := 12.5, 1250000.0, 2750000.0
	return HostTelemetry{Time: time.Now().UTC(), Window: 5, CPU: &cpu, MemoryTotal: 1073741824, MemoryAvailable: 805306368, Received: &rx, Sent: &tx, Interfaces: []string{"eth0"}, Error: ""}
}
