//go:build linux

package control

import (
	"context"
	"github.com/Sir-Adnan/GRE-Tunnel-Manager/panel/internal/model"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

type nativeConfigRunner struct{ demoConfigRunner }

func (r nativeConfigRunner) Run(ctx context.Context, name string, args []string, input string) (string, error) {
	if len(args) > 2 && args[2] == "config-render" {
		script, _ := filepath.Abs("../../../gre.sh")
		cmd := exec.CommandContext(ctx, "bash", script, "--api", "config-render")
		cmd.Stdin = strings.NewReader(input)
		cmd.Env = append(os.Environ(), "GTM_SERVER_LOOKUP=0")
		b, e := cmd.CombinedOutput()
		return string(b), e
	}
	return r.demoConfigRunner.Run(ctx, name, args, input)
}
func TestAllForwardProfilesRenderThroughRealBashAndHAProxy(t *testing.T) {
	for _, p := range model.Presets() {
		if !oneOf(p.Engine, "haproxy", "realm", "iptables", "nftables") {
			continue
		}
		t.Run(p.ID, func(t *testing.T) {
			c := model.Connection{ID: "F000001", Name: "Native profile", Engine: p.Engine, Protocol: p.Protocol, Bind: "192.0.2.10", Ports: "443", Strategy: p.Strategy, Enabled: true, SNAT: "masquerade", Interface: "any", Options: p.Options, Targets: []model.Target{{IP: "198.51.100.20", Port: 443, Weight: 1}}}
			if p.MaxTargets != 1 {
				c.Targets = append(c.Targets, model.Target{IP: "198.51.100.21", Port: 8443, Weight: 2})
			} else {
				c.Strategy = "single"
			}
			m := &Manager{Runner: nativeConfigRunner{}, ConfigDir: t.TempDir()}
			text, e := m.renderConnection(context.Background(), c)
			if e != nil || text == "" {
				t.Fatal(e, text)
			}
			if c.Engine == "haproxy" {
				if !strings.Contains(text, "timeout client-fin 30s") {
					t.Fatal("missing half-close budget", text)
				}
				if bin, e := exec.LookPath("haproxy"); e == nil {
					path := filepath.Join(t.TempDir(), "haproxy.cfg")
					os.WriteFile(path, []byte(text), 0600)
					if b, e := exec.Command(bin, "-c", "-f", path).CombinedOutput(); e != nil {
						t.Fatal(e, string(b))
					}
				}
			}
		})
	}
}
func TestNativeReviewRoundTripsRealRealmAndHAProxy(t *testing.T) {
	for _, engine := range []string{"haproxy", "realm"} {
		c := model.Connection{ID: "F000001", Name: "Native editor", Engine: engine, Protocol: "tcp", Bind: "192.0.2.10", Ports: "443", Strategy: "single", Enabled: false, SNAT: "masquerade", Interface: "any", Options: map[string]string{}, Targets: []model.Target{{IP: "198.51.100.20", Port: 443, Weight: 1}}}
		rows, _ := c.Rows(c.ID)
		cs, _, _ := model.ParseState(rows[0])
		c = cs[0]
		m := &Manager{Runner: nativeConfigRunner{demoConfigRunner{connections: []model.Connection{c}}}, ConfigDir: t.TempDir()}
		v, e := m.Configuration(context.Background(), ConfigInput{ID: c.ID, Revision: c.Revision})
		if e != nil {
			t.Fatal(e)
		}
		input := strings.ReplaceAll(v.Files[0].Text, "timeout client 3600s", "timeout client 7200s")
		input = strings.ReplaceAll(input, "timeout server 3600s", "timeout server 7200s")
		if engine == "realm" {
			input = strings.ReplaceAll(input, "udp_timeout = 30", "udp_timeout = 120")
		}
		next, _, e := m.ReviewConfiguration(context.Background(), ConfigInput{ID: c.ID, Revision: c.Revision, Format: "native", Text: input})
		if e != nil {
			t.Fatal(engine, e)
		}
		if next.Enabled {
			t.Fatal("preview enabled a stopped connection")
		}
	}
}
