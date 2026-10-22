package setup

import (
	"bytes"
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Sir-Adnan/GRE-Tunnel-Manager/panel/internal/config"
	"golang.org/x/crypto/bcrypt"
)

func console(input string, output *bytes.Buffer) Console {
	return Console{In: strings.NewReader(input), Out: output,
		Password: func() (string, error) { return "12345678", nil },
		Discover: func(context.Context) (string, error) { return "203.0.113.19", nil }}
}

func TestQuickInstallationAndUpgradeGuard(t *testing.T) {
	for _, protocol := range []string{"http", "https"} {
		t.Run(protocol, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "config.json")
			var out bytes.Buffer
			c := console("", &out)
			if e := c.Run(context.Background(), []string{"--quick", "--protocol", protocol, "--config", path}); e != nil {
				t.Fatal(e)
			}
			cfg, e := config.Load(path)
			if e != nil {
				t.Fatal(e)
			}
			if cfg.PublicHost != "203.0.113.19" || cfg.Scheme() != protocol || strings.HasSuffix(cfg.Listen, ":0") {
				t.Fatal(cfg)
			}
			_, after, found := strings.Cut(out.String(), "Password:  ")
			secret := strings.Split(after, "\n")[0]
			if !found || len(secret) != 32 || bcrypt.CompareHashAndPassword([]byte(cfg.PasswordHash), []byte(secret)) != nil || strings.Count(out.String(), secret) != 1 {
				t.Fatal("generated credential not printed exactly once")
			}
			if !strings.Contains(out.String(), protocol+"://203.0.113.19:") {
				t.Fatal(out.String())
			}
			before, _ := os.ReadFile(path)
			cert, _ := os.ReadFile(cfg.Certificate)
			out.Reset()
			if e = c.Run(context.Background(), []string{"--quick", "--config", path}); e == nil {
				t.Fatal("setup overwrote existing configuration")
			}
			afterConfig, _ := os.ReadFile(path)
			afterCert, _ := os.ReadFile(cfg.Certificate)
			if !bytes.Equal(before, afterConfig) || !bytes.Equal(cert, afterCert) || out.Len() != 0 {
				t.Fatal("upgrade changed credentials or certificate")
			}
			if protocol == "http" {
				if _, e := os.Stat(filepath.Join(filepath.Dir(path), "server.key")); !os.IsNotExist(e) {
					t.Fatal("HTTP generated TLS material")
				}
			}
		})
	}
}

func TestCustomSetupRepromptsAndUsesEightCharacterPassword(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	var out bytes.Buffer
	c := console("bad\n2\n2\npanel.example.com\n70000\n0\na\noperator\n", &out)
	c.Discover = func(context.Context) (string, error) { return "", errors.New("offline") }
	if e := c.Run(context.Background(), []string{"--config", path}); e != nil {
		t.Fatal(e, out.String())
	}
	cfg, e := config.Load(path)
	if e != nil {
		t.Fatal(e)
	}
	if cfg.PublicHost != "panel.example.com" || cfg.Username != "operator" || cfg.Scheme() != "http" || !strings.HasPrefix(cfg.URL(), "http://panel.example.com:") {
		t.Fatal(cfg)
	}
	if strings.Contains(out.String(), "12345678") || bcrypt.CompareHashAndPassword([]byte(cfg.PasswordHash), []byte("12345678")) != nil {
		t.Fatal("custom password exposed or rejected")
	}
}

func TestDiscoveryFailureAndInvalidArgumentsDoNotCreateConfig(t *testing.T) {
	for _, args := range [][]string{{"--quick"}, {"--quick", "--protocol", "ftp"}, {"--quick", "--port", "70000"}, {"--quick", "--address", "https://host:123"}, {"--quick", "--listen", "localhost"}, {"--quick", "--username", "a"}, {"--password", "secret"}, {"extra"}} {
		path := filepath.Join(t.TempDir(), "config.json")
		var out bytes.Buffer
		c := console("", &out)
		c.Discover = func(context.Context) (string, error) { return "", errors.New("discovery failed") }
		if e := c.Run(context.Background(), append(args, "--config", path)); e == nil {
			t.Fatal(args)
		}
		if _, e := os.Stat(path); !os.IsNotExist(e) {
			t.Fatal("failed setup wrote config", args)
		}
	}
}

func TestExplicitAddressSkipsDiscoveryAndOccupiedPortIsRejected(t *testing.T) {
	listener, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	defer listener.Close()
	_, port, _ := net.SplitHostPort(listener.Addr().String())
	path := filepath.Join(t.TempDir(), "config.json")
	var out bytes.Buffer
	c := console("", &out)
	c.Discover = func(context.Context) (string, error) { t.Fatal("explicit address performed discovery"); return "", nil }
	if e = c.Run(context.Background(), []string{"--quick", "--protocol", "http", "--address", "127.0.0.1", "--listen", "127.0.0.1", "--port", port, "--config", path}); e == nil {
		t.Fatal("occupied port accepted")
	}
	if strings.Contains(out.String(), "Password:") {
		t.Fatal("failed setup exposed credentials")
	}
	if _, e = os.Stat(path); !os.IsNotExist(e) {
		t.Fatal("occupied port wrote config")
	}
}

func TestIPv6QuickSetupPrintsAReachableBracketedURL(t *testing.T) {
	probe, e := net.Listen("tcp6", "[::1]:0")
	if e != nil {
		t.Skip("IPv6 loopback unavailable")
	}
	probe.Close()
	var out bytes.Buffer
	c := console("", &out)
	c.Discover = func(context.Context) (string, error) { return "::1", nil }
	path := filepath.Join(t.TempDir(), "config.json")
	if e = c.Run(context.Background(), []string{"--quick", "--protocol", "http", "--config", path}); e != nil {
		t.Fatal(e)
	}
	cfg, e := config.Load(path)
	if e != nil {
		t.Fatal(e)
	}
	if !strings.HasPrefix(cfg.Listen, "[::]:") || !strings.HasPrefix(cfg.URL(), "http://[::1]:") {
		t.Fatal(cfg.Listen, cfg.URL())
	}
}

func TestDiscoveryFallbackAndUntrustedResponses(t *testing.T) {
	bad := []string{"127.0.0.1", "10.1.2.3", "0.0.0.0", "::1", "169.254.1.1", "<html>error</html>", strings.Repeat("1", 130)}
	for _, body := range bad {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/bad" {
				w.Write([]byte(body))
			} else {
				w.Write([]byte("2001:4860:4860::8888\n"))
			}
		}))
		value, e := discover(context.Background(), server.Client(), []string{server.URL + "/bad", server.URL + "/good"})
		server.Close()
		if e != nil || value != "2001:4860:4860::8888" {
			t.Fatal(body, value, e)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, e := discover(ctx, http.DefaultClient, []string{"http://127.0.0.1:1"}); e == nil {
		t.Fatal("cancelled discovery succeeded")
	}
}
