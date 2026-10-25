//go:build linux

package control

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/Sir-Adnan/GRE-Tunnel-Manager/panel/internal/model"
)

func TestQuotaKernelStopsEstablishedRelayAndResumes(t *testing.T) {
	if os.Getenv("GTM_QUOTA_PRIVATE_NS") != "1" {
		if os.Geteuid() != 0 {
			t.Skip("requires root in isolated Linux namespace")
		}
		for _, bin := range []string{"unshare", "ip", "nft"} {
			if _, e := exec.LookPath(bin); e != nil {
				t.Skip(bin + " unavailable")
			}
		}
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		cmd := exec.CommandContext(ctx, "unshare", "-n", os.Args[0], "-test.run=^TestQuotaKernelStopsEstablishedRelayAndResumes$", "-test.v")
		cmd.Env = append(os.Environ(), "GTM_QUOTA_PRIVATE_NS=1")
		if b, e := cmd.CombinedOutput(); e != nil {
			t.Fatalf("private namespace: %v\n%s", e, b)
		}
		return
	}
	if b, e := exec.Command("ip", "link", "set", "lo", "up").CombinedOutput(); e != nil {
		t.Fatal(e, string(b))
	}
	l, e := net.Listen("tcp4", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	defer l.Close()
	go func() {
		for {
			c, e := l.Accept()
			if e != nil {
				return
			}
			go func() {
				defer c.Close()
				buf := make([]byte, 64)
				for {
					n, e := c.Read(buf)
					if e != nil {
						return
					}
					if _, e = c.Write(buf[:n]); e != nil {
						return
					}
				}
			}()
		}
	}()
	port := l.Addr().(*net.TCPAddr).Port
	conn, e := net.DialTimeout("tcp4", l.Addr().String(), time.Second)
	if e != nil {
		t.Fatal(e)
	}
	defer conn.Close()
	inv := Inventory{Connections: []model.Connection{{ID: "F000001", Engine: "haproxy", Enabled: true, Bind: "0.0.0.0", Ports: fmt.Sprint(port), Protocol: "tcp", Interface: "any"}}}
	m, e := NewMetrics(Executor{}, filepath.Join(t.TempDir(), "metrics.json"))
	if e != nil {
		t.Fatal(e)
	}
	ctx := context.Background()
	if _, e = m.Configure(ctx, MetricsSettings{Enabled: true, Interval: 15}, inv); e != nil {
		t.Fatal(e)
	}
	policy := TrafficPolicy{Limit: 1, Direction: "total", StopOnLimit: true}
	if _, e = m.Change(ctx, "metrics-policy", TrafficChange{ID: "F000001", Revision: m.View().Revision, Policy: policy}, inv); e != nil {
		t.Fatal(e)
	}
	conn.SetDeadline(time.Now().Add(time.Second))
	conn.Write([]byte("before"))
	buf := make([]byte, 64)
	if n, e := conn.Read(buf); e != nil || string(buf[:n]) != "before" {
		t.Fatal("baseline", n, e)
	}
	if e = m.Tick(ctx, inv); e != nil {
		t.Fatal(e)
	}
	if !m.View().Blocked["F000001"] {
		t.Fatal("guard not installed")
	}
	conn.SetDeadline(time.Now().Add(250 * time.Millisecond))
	conn.Write([]byte("blocked"))
	if n, e := conn.Read(buf); e == nil || n != 0 {
		t.Fatal("established flow bypassed quota", n, e)
	}
	// The host and another port remain usable while this listener is blocked.
	other, e := net.Listen("tcp4", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	defer other.Close()
	untouched, e := net.DialTimeout("tcp4", other.Addr().String(), time.Second)
	if e != nil {
		t.Fatal("unrelated listener blocked", e)
	}
	untouched.Close()
	if _, e = m.Change(ctx, "metrics-reset", TrafficChange{ID: "F000001", Revision: m.View().Revision}, inv); e != nil {
		t.Fatal(e)
	}
	if m.View().Blocked["F000001"] {
		t.Fatal("reset retained guard")
	}
	after, e := net.DialTimeout("tcp4", l.Addr().String(), time.Second)
	if e != nil {
		t.Fatal(e)
	}
	defer after.Close()
	after.SetDeadline(time.Now().Add(time.Second))
	after.Write([]byte("after"))
	if n, e := after.Read(buf); e != nil || string(buf[:n]) != "after" {
		t.Fatal("reset did not resume", n, e)
	}
}
