package control

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Sir-Adnan/GRE-Tunnel-Manager/panel/internal/model"
)

type EngineRelease struct {
	ID          string `json:"id"`
	Version     string `json:"version"`
	Installed   string `json:"installed"`
	PeerVersion string `json:"peer_version,omitempty"`
	Supported   string `json:"supported"`
	Source      string `json:"source"`
	URL         string `json:"url"`
	Revision    string `json:"revision"`
	Update      bool   `json:"update"`
	Error       string `json:"error,omitempty"`
}
type releaseCache struct {
	mu     sync.Mutex
	until  time.Time
	values []EngineRelease
}

var pinnedEngines = map[string]struct{ repo, version string }{"realm": {"zhboner/realm", "2.9.6"}, "frp": {"fatedier/frp", "0.71.1"}, "rathole": {"rathole-org/rathole", "0.5.0"}}
var releaseTag = regexp.MustCompile(`^v?[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$`)

// No browser-provided URLs, redirects, tokens or release assets are accepted.
// A manual check is cached for five minutes and never upgrades a binary.
func latestEngine(ctx context.Context, client *http.Client, repo string) (string, error) {
	req, e := http.NewRequestWithContext(ctx, "GET", "https://api.github.com/repos/"+repo+"/releases/latest", nil)
	if e != nil {
		return "", e
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("User-Agent", "GRE-Tunnel-Manager")
	response, e := client.Do(req)
	if e != nil {
		return "", errors.New("official release source is unavailable")
	}
	defer response.Body.Close()
	if response.StatusCode != 200 {
		return "", errors.New("official release check failed or was rate limited")
	}
	b, e := io.ReadAll(io.LimitReader(response.Body, 524289))
	if e != nil || len(b) > 524288 {
		return "", errors.New("release response is too large")
	}
	var release struct {
		Tag        string `json:"tag_name"`
		Draft      bool   `json:"draft"`
		Prerelease bool   `json:"prerelease"`
	}
	if json.Unmarshal(b, &release) != nil || release.Draft || release.Prerelease || !releaseTag.MatchString(release.Tag) {
		return "", errors.New("no recognized stable release")
	}
	return strings.TrimPrefix(release.Tag, "v"), nil
}
func (m *Manager) engineReleases(ctx context.Context) []EngineRelease {
	m.releases.mu.Lock()
	defer m.releases.mu.Unlock()
	if time.Now().Before(m.releases.until) {
		return append([]EngineRelease{}, m.releases.values...)
	}
	client := &http.Client{Timeout: 4 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("release redirects are not accepted") }}
	installed := map[string]Component{}
	for _, c := range m.components(ctx) {
		installed[c.ID] = c
	}
	result := make([]EngineRelease, 6)
	var group sync.WaitGroup
	for i, id := range []string{"iptables", "nftables", "haproxy", "realm", "frp", "rathole"} {
		group.Add(1)
		go func(i int, id string) {
			defer group.Done()
			r := EngineRelease{ID: id, Installed: installed[id].Version, PeerVersion: installed[id].PeerVersion}
			if pin, ok := pinnedEngines[id]; ok {
				r.Source = "upstream"
				r.Supported = pin.version
				r.URL = "https://github.com/" + pin.repo + "/releases"
				var e error
				r.Version, e = latestEngine(ctx, client, pin.repo)
				if e != nil {
					r.Error = e.Error()
				}
				r.Update = needsPinnedUpdate(id, installed[id], pin.version)
				r.Revision = releaseRevision(r)
			} else {
				r.Source = "distribution"
				r.URL = map[string]string{"iptables": "https://www.netfilter.org/projects/iptables/", "nftables": "https://www.netfilter.org/projects/nftables/", "haproxy": "https://www.haproxy.org/"}[id]
				out, e := m.call(ctx, "component-policy", "", id)
				if e != nil {
					r.Error = "distribution package metadata is unavailable"
				} else {
					r.Revision = policyRevision(out)
					var packageInstalled string
					for _, line := range strings.Split(out, "\n") {
						f := strings.Fields(line)
						if len(f) == 2 && f[0] == "Candidate:" {
							r.Version = f[1]
						}
						if len(f) == 2 && f[0] == "Installed:" {
							packageInstalled = f[1]
						}
					}
					if r.Version == "" || r.Version == "(none)" {
						r.Error = "no candidate in configured package metadata"
					} else {
						r.Supported = r.Version
						if installed[id].Installed && packageInstalled != "(none)" && packageInstalled != "" && packageInstalled != r.Version {
							_, compareError := m.Runner.Run(ctx, "dpkg", []string{"--compare-versions", r.Version, "gt", packageInstalled}, "")
							r.Update = compareError == nil
						}
					}
				}
			}
			result[i] = r
		}(i, id)
	}
	group.Wait()
	m.releases.values = result
	m.releases.until = time.Now().Add(5 * time.Minute)
	return append([]EngineRelease{}, result...)
}
func releaseRevision(r EngineRelease) string {
	return policyRevision(r.ID + "\n" + r.Installed + "\n" + r.PeerVersion + "\n" + r.Supported)
}
func needsPinnedUpdate(id string, c Component, pin string) bool {
	if !c.Installed {
		return false
	}
	if id != "frp" {
		return newerEngine(pin, c.Version)
	}
	if c.Version == "" || c.PeerVersion == "" || newerEngine(c.Version, pin) || newerEngine(c.PeerVersion, pin) {
		return false
	}
	return newerEngine(pin, c.Version) || newerEngine(pin, c.PeerVersion)
}
func policyRevision(text string) string { return model.Revision(text) }
func newerEngine(candidate, installed string) bool {
	a, b := engineVersion.FindStringSubmatch(candidate), engineVersion.FindStringSubmatch(installed)
	if a == nil || b == nil {
		return false
	}
	x, y := strings.Split(a[1], "."), strings.Split(b[1], ".")
	for i := range x {
		n, _ := strconv.Atoi(x[i])
		m, _ := strconv.Atoi(y[i])
		if n != m {
			return n > m
		}
	}
	return false
}

func (m *Manager) updateEngine(ctx context.Context, r Request) (any, error) {
	if len(r.Components) != 1 || !digestValid(r.EngineRevision) {
		return nil, errors.New("select one checked engine version")
	}
	id := r.Components[0]
	if pin, ok := pinnedEngines[id]; ok {
		var found Component
		for _, c := range m.components(ctx) {
			if c.ID == id {
				found = c
			}
		}
		if !found.Installed || releaseRevision(EngineRelease{ID: id, Installed: found.Version, PeerVersion: found.PeerVersion, Supported: pin.version}) != r.EngineRevision {
			return nil, errors.New("engine changed; check versions again")
		}
		if !needsPinnedUpdate(id, found, pin.version) {
			return nil, errors.New("no newer verified engine version is available")
		}
		args := []string{id, found.Version}
		if id == "frp" {
			args = append(args, found.PeerVersion)
		}
		output, e := m.call(ctx, "component-update", "", args...)
		m.clearComponentCaches()
		return output, e
	}
	if !oneOf(id, "iptables", "nftables", "haproxy") {
		return nil, errors.New("unknown engine")
	}
	out, e := m.call(ctx, "component-policy", "", id)
	if e != nil {
		return nil, e
	}
	if policyRevision(out) != r.EngineRevision {
		return nil, errors.New("package metadata changed; check versions again")
	}
	output, e := m.call(ctx, "component-update", "", id, r.EngineRevision)
	m.clearComponentCaches()
	return output, e
}
func (m *Manager) clearComponentCaches() {
	m.probes.mu.Lock()
	m.probes.until = time.Time{}
	m.probes.mu.Unlock()
	m.releases.mu.Lock()
	m.releases.until = time.Time{}
	m.releases.mu.Unlock()
}
