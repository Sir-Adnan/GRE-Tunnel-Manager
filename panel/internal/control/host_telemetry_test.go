package control

import (
	"fmt"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"
)

func TestHostTelemetryUsesDeltasCacheAndDefaultRoutes(t *testing.T) {
	files := map[string]string{
		"/proc/stat":           "cpu 100 0 0 900 0 0 0 0 80 0\n",
		"/proc/meminfo":        "MemTotal: 2048 kB\nMemAvailable: 1024 kB\n",
		"/proc/net/route":      "Iface Destination Gateway Flags RefCnt Use Metric Mask\neth0 00000000 0100000A 0003 0 0 100 00000000\n",
		"/proc/net/ipv6_route": strings.Repeat("0", 32) + " 00 " + strings.Repeat("0", 32) + " 00 " + strings.Repeat("0", 32) + " 00000001 00000000 00000000 00000001 eth0\n",
		"/proc/net/dev":        "eth0: 1000 0 0 0 0 0 0 0 2000 0 0 0 0 0 0 0\ngre1: 999999 0 0 0 0 0 0 0 999999 0 0 0 0 0 0 0\nlo: 99999 0 0 0 0 0 0 0 99999 0 0 0 0 0 0 0\n",
	}
	reads := 0
	read := func(path string) ([]byte, error) {
		reads++
		v, ok := files[path]
		if !ok {
			return nil, os.ErrNotExist
		}
		return []byte(v), nil
	}
	s := hostSampler{}
	now := time.Now().UTC()
	a := s.sample(now, read)
	if a.CPU != nil || a.Received != nil || a.MemoryTotal != 2048*1024 || len(a.Interfaces) != 1 || a.Interfaces[0] != "eth0" {
		t.Fatal(a)
	}
	s.sample(now.Add(time.Second), read)
	if reads != 5 {
		t.Fatal("cache bypass", reads)
	}
	files["/proc/stat"] = "cpu 150 0 0 950 0 0 0 0 100 0\n"
	files["/proc/net/dev"] = "eth0: 6000 0 0 0 0 0 0 0 12000 0 0 0 0 0 0 0\n"
	a = s.sample(now.Add(5*time.Second), read)
	if a.CPU == nil || *a.CPU != 50 || a.Received == nil || *a.Received != 1000 || *a.Sent != 2000 {
		t.Fatal(a)
	}
	files["/proc/net/dev"] = "eth0: 1 0 0 0 0 0 0 0 1 0 0 0 0 0 0 0\n"
	a = s.sample(now.Add(10*time.Second), read)
	if a.Received != nil {
		t.Fatal("reset spike", a)
	}
	a = s.sample(now.Add(time.Minute), read)
	if a.CPU != nil || a.Received != nil {
		t.Fatal("stale baseline", a)
	}
	files["/proc/stat"] = "cpu invalid\n"
	files["/proc/meminfo"] = ""
	a = s.sample(now.Add(65*time.Second), read)
	if a.Error == "" || a.CPU != nil || a.MemoryTotal != 0 {
		t.Fatal(a)
	}
}
func TestHostTelemetryIPv6OnlyAndRouteChange(t *testing.T) {
	v6 := fmt.Sprintf("%032d 00 %032d 00 %032d 00000001 00000000 00000000 00000001 ens3\n", 0, 0, 0)
	if n := defaultInterfaces("", v6); !n["ens3"] || len(n) != 1 {
		t.Fatal(n)
	}
	if n := defaultInterfaces("bad\n", strings.Replace(v6, "00000001 ens3", "00000201 ens3", 1)); len(n) != 0 {
		t.Fatal("reject route counted", n)
	}
	if total, idle, ok := cpuTimes("cpu 1 2 3 4 5 6 7 8 100 100\n"); !ok || total != 36 || idle != 9 {
		t.Fatal(total, idle, ok)
	}
}

func TestHostTelemetryDoesNotWaitForNetworkMutationLock(t *testing.T) {
	b := &Broker{Manager: NewManager()}
	b.mu.Lock()
	defer b.mu.Unlock()
	done := make(chan struct{})
	go func() {
		defer close(done)
		w := httptest.NewRecorder()
		b.ServeHTTP(w, httptest.NewRequest("POST", "/control", strings.NewReader(`{"action":"host-telemetry"}`)))
		if w.Code != 200 {
			t.Errorf("telemetry response: %d", w.Code)
		}
	}()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("telemetry queued behind a mutation")
	}
}
