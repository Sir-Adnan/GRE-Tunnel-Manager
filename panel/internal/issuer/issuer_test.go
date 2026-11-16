package issuer

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/acme"
)

func testClient(t *testing.T) *acme.Client {
	key, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	return &acme.Client{Key: key}
}

func TestChallengeHandlerServesOnlyTheTokenPath(t *testing.T) {
	handler := challengeHandler("/.well-known/acme-challenge/abc", "abc.proof")
	cases := []struct {
		method, path string
		code         int
		body         string
	}{
		{"GET", "/.well-known/acme-challenge/abc", 200, "abc.proof"},
		{"HEAD", "/.well-known/acme-challenge/abc", 200, ""},
		{"GET", "/.well-known/acme-challenge/other", 404, ""},
		{"GET", "/", 404, ""},
		{"POST", "/.well-known/acme-challenge/abc", 404, ""},
	}
	for _, c := range cases {
		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, httptest.NewRequest(c.method, c.path, nil))
		if recorder.Code != c.code || (c.body != "" && recorder.Body.String() != c.body) {
			t.Fatalf("%s %s: %d %q", c.method, c.path, recorder.Code, recorder.Body.String())
		}
	}
}

func TestHTTP01ExplainsABusyPortAndClosesAfterCleanup(t *testing.T) {
	busy, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	defer busy.Close()
	client := testClient(t)
	challenge := &acme.Challenge{Type: "http-01", Token: "token-1"}
	_, e = HTTP01{Address: busy.Addr().String()}.Present(context.Background(), client, acme.AuthzID{Type: "ip", Value: "127.0.0.1"}, challenge)
	if e == nil || !strings.Contains(e.Error(), "already used by another service") {
		t.Fatal(e)
	}
	free, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	address := free.Addr().String()
	free.Close()
	cleanup, e := HTTP01{Address: address}.Present(context.Background(), client, acme.AuthzID{Type: "ip", Value: "127.0.0.1"}, challenge)
	if e != nil {
		t.Fatal(e)
	}
	response, e := http.Get("http://" + address + client.HTTP01ChallengePath("token-1"))
	if e != nil {
		t.Fatal(e)
	}
	body, _ := io.ReadAll(response.Body)
	response.Body.Close()
	want, _ := client.HTTP01ChallengeResponse("token-1")
	if string(body) != want {
		t.Fatalf("proof %q", body)
	}
	cleanup()
	if _, e = net.DialTimeout("tcp", address, time.Second); e == nil {
		t.Fatal("validation listener still open after cleanup")
	}
}

type fakeCloudflare struct {
	mu      sync.Mutex
	records map[string]map[string]any
	created int
	deleted int
	auth    string
}

func (f *fakeCloudflare) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.auth = r.Header.Get("Authorization")
	reply := func(result any) {
		json.NewEncoder(w).Encode(map[string]any{"success": true, "errors": []any{}, "result": result})
	}
	switch {
	case r.Method == "GET" && r.URL.Path == "/zones":
		if r.URL.Query().Get("name") == "example.com" {
			reply([]map[string]string{{"id": "zone-1"}})
			return
		}
		reply([]any{})
	case r.Method == "POST" && r.URL.Path == "/zones/zone-1/dns_records":
		var record map[string]any
		json.NewDecoder(r.Body).Decode(&record)
		f.created++
		f.records["rec-1"] = record
		reply(map[string]string{"id": "rec-1"})
	case r.Method == "DELETE" && r.URL.Path == "/zones/zone-1/dns_records/rec-1":
		f.deleted++
		delete(f.records, "rec-1")
		reply(map[string]string{"id": "rec-1"})
	default:
		w.WriteHeader(403)
		json.NewEncoder(w).Encode(map[string]any{"success": false, "errors": []map[string]any{{"code": 10000, "message": "Authentication error"}}})
	}
}

func TestCloudflareCreatesTheRecordInTheEnclosingZoneAndRemovesIt(t *testing.T) {
	fake := &fakeCloudflare{records: map[string]map[string]any{}}
	server := httptest.NewServer(fake)
	defer server.Close()
	client := testClient(t)
	want, _ := client.DNS01ChallengeRecord("token-2")
	looked := 0
	solver := Cloudflare{Token: "cf-token-abcdefghijklmnopqrstuvwxyz", API: server.URL, Poll: time.Millisecond, Wait: time.Second,
		Lookup: func(_ context.Context, name string) ([]string, error) {
			looked++
			if name != "_acme-challenge.panel.example.com" {
				t.Errorf("lookup %s", name)
			}
			if looked < 2 {
				return nil, nil
			}
			return []string{want}, nil
		}}
	cleanup, e := solver.Present(context.Background(), client, acme.AuthzID{Type: "dns", Value: "panel.example.com"}, &acme.Challenge{Type: "dns-01", Token: "token-2"})
	if e != nil {
		t.Fatal(e)
	}
	record := fake.records["rec-1"]
	if record["type"] != "TXT" || record["name"] != "_acme-challenge.panel.example.com" || record["content"] != want || looked != 2 {
		t.Fatal(record, looked)
	}
	if fake.auth != "Bearer cf-token-abcdefghijklmnopqrstuvwxyz" {
		t.Fatal("token not sent as a bearer header")
	}
	cleanup()
	if fake.deleted != 1 || len(fake.records) != 0 {
		t.Fatal("validation record left behind")
	}
}

func TestCloudflareErrorsNameTheProblemWithoutTheToken(t *testing.T) {
	fake := &fakeCloudflare{records: map[string]map[string]any{}}
	server := httptest.NewServer(fake)
	defer server.Close()
	token := "secret-token-abcdefghijklmnop"
	solver := Cloudflare{Token: token, API: server.URL}
	_, e := solver.Present(context.Background(), testClient(t), acme.AuthzID{Type: "dns", Value: "panel.other.net"}, &acme.Challenge{Type: "dns-01", Token: "x"})
	if e == nil || !strings.Contains(e.Error(), "no active Cloudflare zone") || strings.Contains(e.Error(), token) {
		t.Fatal(e)
	}
	_, e = solver.Present(context.Background(), testClient(t), acme.AuthzID{Type: "ip", Value: "203.0.113.5"}, &acme.Challenge{Type: "dns-01", Token: "x"})
	if e == nil || !strings.Contains(e.Error(), "IP addresses use HTTP validation") {
		t.Fatal(e)
	}
}

func TestSettingsValidation(t *testing.T) {
	good := Settings{Version: 1, Host: "panel.example.com", Directory: LetsEncrypt, Challenge: ChallengeHTTP, Email: "ops@example.com"}
	if e := good.Validate(); e != nil {
		t.Fatal(e)
	}
	bad := map[string]Settings{
		"http directory":   {Version: 1, Host: "panel.example.com", Directory: "http://ca.example/dir", Challenge: ChallengeHTTP},
		"ip over dns":      {Version: 1, Host: "203.0.113.7", Directory: LetsEncrypt, Challenge: ChallengeCloudflare},
		"unknown":          {Version: 1, Host: "panel.example.com", Directory: LetsEncrypt, Challenge: "tls-alpn-01"},
		"email":            {Version: 1, Host: "panel.example.com", Directory: LetsEncrypt, Challenge: ChallengeHTTP, Email: "ops@@example.com"},
		"profile":          {Version: 1, Host: "panel.example.com", Directory: LetsEncrypt, Challenge: ChallengeHTTP, Profile: "../x"},
		"host":             {Version: 1, Host: "https://panel.example.com", Directory: LetsEncrypt, Challenge: ChallengeHTTP},
		"validation addr":  {Version: 1, Host: "panel.example.com", Directory: LetsEncrypt, Challenge: ChallengeHTTP, HTTPAddress: "80"},
		"missing version":  {Host: "panel.example.com", Directory: LetsEncrypt, Challenge: ChallengeHTTP},
		"contact injected": {Version: 1, Host: "panel.example.com", Directory: LetsEncrypt, Challenge: ChallengeHTTP, Email: "a@example.com\nb"},
	}
	for name, value := range bad {
		if value.Validate() == nil {
			t.Error(name)
		}
	}
	if (Settings{Directory: LetsEncryptStaging}).Source() != "letsencrypt" || (Settings{Directory: "https://ca.example/dir"}).Source() != "acme" {
		t.Fatal("source")
	}
}

func TestStoreKeepsSecretsPrivateAndDisableKeepsTheAccount(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.json")
	os.WriteFile(configPath, []byte("{}"), 0640)
	store := Store{Dir: filepath.Join(dir, "acme"), StatusPath: filepath.Join(dir, "certificate.json"), ConfigPath: configPath}
	if _, managed, e := store.Settings(); managed || e != nil {
		t.Fatal(managed, e)
	}
	settings := Settings{Version: 1, Host: "panel.example.com", Directory: LetsEncrypt, Challenge: ChallengeCloudflare, Email: "ops@example.com"}
	if e := store.SaveSettings(settings); e != nil {
		t.Fatal(e)
	}
	if e := store.SaveToken("bad token"); e == nil {
		t.Fatal("invalid token accepted")
	}
	if e := store.SaveToken("abcdefghijklmnopqrstuvwxyz0123"); e != nil {
		t.Fatal(e)
	}
	first, e := store.AccountKey()
	if e != nil {
		t.Fatal(e)
	}
	again, e := store.AccountKey()
	if e != nil || !first.Public().(*ecdsa.PublicKey).Equal(again.Public()) {
		t.Fatal("account key not reused", e)
	}
	loaded, managed, e := store.Settings()
	if e != nil || !managed || loaded != settings {
		t.Fatal(loaded, managed, e)
	}
	if runtime.GOOS != "windows" {
		for _, name := range []string{"settings.json", "account.key", "cloudflare.token"} {
			info, e := os.Stat(filepath.Join(store.Dir, name))
			if e != nil || info.Mode().Perm() != 0600 {
				t.Fatal(name, info, e)
			}
		}
		if info, _ := os.Stat(store.Dir); info.Mode().Perm() != 0700 {
			t.Fatal("account directory mode", info.Mode())
		}
	}
	if e = store.Disable(); e != nil {
		t.Fatal(e)
	}
	if _, managed, _ = store.Settings(); managed {
		t.Fatal("renewal still configured")
	}
	if _, e = store.Token(); e == nil {
		t.Fatal("token kept after disable")
	}
	if _, e = os.Stat(filepath.Join(store.Dir, "account.key")); e != nil {
		t.Fatal("account key removed", e)
	}
}

func TestProblemKeepsTheCAExplanation(t *testing.T) {
	e := &acme.AuthorizationError{Identifier: "203.0.113.9", Errors: []error{&acme.Error{ProblemType: "urn:ietf:params:acme:error:connection", Detail: "203.0.113.9: Connection refused"}}}
	if got := problem(e); got != "203.0.113.9: Connection refused" {
		t.Fatal(got)
	}
	limited := &acme.Error{ProblemType: "urn:ietf:params:acme:error:rateLimited", Detail: "too many certificates", Header: http.Header{"Retry-After": []string{"3600"}}}
	if got := problem(limited); !strings.Contains(got, "too many certificates") || !strings.Contains(got, "rate limited") {
		t.Fatal(got)
	}
}
