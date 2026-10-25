package control

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
)

type releaseTransport func(*http.Request) (*http.Response, error)

func (f releaseTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
func TestOfficialReleaseSourceIsFixedAndResponsesBounded(t *testing.T) {
	for _, test := range []struct {
		body   string
		status int
		ok     bool
	}{
		{`{"tag_name":"v2.9.6"}`, 200, true},
		{`{"tag_name":"v3.0.0-rc1","prerelease":true}`, 200, false},
		{`{"tag_name":"$(id)"}`, 200, false},
		{strings.Repeat("x", 524289), 200, false},
		{`{}`, 403, false},
	} {
		client := &http.Client{Transport: releaseTransport(func(r *http.Request) (*http.Response, error) {
			if r.URL.String() != "https://api.github.com/repos/zhboner/realm/releases/latest" || r.Header.Get("Authorization") != "" {
				return nil, errors.New("wrong source or unexpected credentials")
			}
			return &http.Response{StatusCode: test.status, Body: io.NopCloser(strings.NewReader(test.body))}, nil
		})}
		version, e := latestEngine(context.Background(), client, "zhboner/realm")
		if (e == nil) != test.ok || test.ok && version != "2.9.6" {
			t.Fatal(version, e)
		}
	}
}
func TestEngineUpdateNeverDowngradesOrAcceptsUnknownVersions(t *testing.T) {
	for _, tt := range []struct {
		a, b string
		want bool
	}{{"2.9.6", "2.9.5", true}, {"2.9.6", "2.9.6", false}, {"2.9.6", "3.0.0", false}, {"0.71.1", "0.70.9", true}, {"2.9.6", "", false}} {
		if newerEngine(tt.a, tt.b) != tt.want {
			t.Fatal(tt)
		}
	}
	m := &Manager{Runner: &fakeRunner{}}
	for _, r := range []Request{{Action: "engine-update", Components: []string{"sh"}, EngineRevision: strings.Repeat("a", 64)}, {Action: "engine-update", Components: []string{"haproxy"}, EngineRevision: "old"}} {
		if _, e := m.Execute(context.Background(), r); e == nil {
			t.Fatal("invalid engine update accepted")
		}
	}
}

func TestFRPMaintenanceRepairsAnOlderPeerWithoutDowngradingEitherBinary(t *testing.T) {
	for _, test := range []struct {
		client, server string
		want           bool
	}{{"0.71.1", "0.70.9", true}, {"0.70.9", "0.71.1", true}, {"0.71.1", "0.71.1", false}, {"0.72.0", "0.70.9", false}, {"0.70.9", "", false}} {
		if needsPinnedUpdate("frp", Component{Installed: true, Version: test.client, PeerVersion: test.server}, "0.71.1") != test.want {
			t.Fatal(test)
		}
	}
	a := releaseRevision(EngineRelease{ID: "frp", Installed: "0.71.1", PeerVersion: "0.70.9", Supported: "0.71.1"})
	b := releaseRevision(EngineRelease{ID: "frp", Installed: "0.71.1", PeerVersion: "0.71.1", Supported: "0.71.1"})
	if a == b {
		t.Fatal("peer version missing from revision")
	}
}
