package nodes

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Sir-Adnan/GRE-Tunnel-Manager/panel/internal/control"
)

type fixture struct {
	h           *Hub
	s           *httptest.Server
	dir         string
	failReports atomic.Int32
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	dir := t.TempDir()
	if e := Init(dir, "https://127.0.0.1:9443", "127.0.0.1:9443"); e != nil {
		t.Fatal(e)
	}
	h, e := Open(dir)
	if e != nil {
		t.Fatal(e)
	}
	f := &fixture{h: h, dir: dir}
	s := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/report" && f.failReports.CompareAndSwap(1, 0) {
			conn, _, e := w.(http.Hijacker).Hijack()
			if e == nil {
				conn.Close()
			}
			return
		}
		h.ServeHTTP(w, r)
	}))
	s.TLS, e = h.TLSConfig()
	if e != nil {
		t.Fatal(e)
	}
	cert, e := h.serverCertificate(nil)
	if e != nil {
		t.Fatal(e)
	}
	s.TLS.Certificates = []tls.Certificate{*cert}
	s.StartTLS()
	h.state.URL = s.URL
	t.Cleanup(func() { s.Close(); h.Close() })
	f.s = s
	return f
}
func (f *fixture) enroll(t *testing.T, name string) (identity, string) {
	t.Helper()
	inv, e := f.h.Invite(name)
	if e != nil {
		t.Fatal(e)
	}
	path := filepath.Join(t.TempDir(), "identity.json")
	if e = Enroll(context.Background(), path, inv.Code); e != nil {
		t.Fatal(e)
	}
	var id identity
	if e = readJSON(path, &id); e != nil {
		t.Fatal(e)
	}
	return id, path
}
func client(t *testing.T, id identity) *tls.Config {
	t.Helper()
	tc, e := agentTLS(id)
	if e != nil {
		t.Fatal(e)
	}
	return tc
}
func sample(t *testing.T) Report {
	t.Helper()
	raw, e := control.NewDemo().Do(context.Background(), control.Request{Action: "inventory"})
	if e != nil {
		t.Fatal(e)
	}
	return Report{Protocol: 1, Version: "1.3.0", Capabilities: []string{"inventory.read"}, Inventory: raw}
}
func send(t *testing.T, f *fixture, id identity, r Report) error {
	t.Helper()
	c := transport(client(t, id))
	defer c.CloseIdleConnections()
	var ack any
	return post(context.Background(), c, f.s.URL+"/v1/report", r, &ack)
}
func code(t *testing.T, inv Invitation) bootstrap {
	t.Helper()
	raw, e := base64.RawURLEncoding.DecodeString(inv.Code)
	if e != nil {
		t.Fatal(e)
	}
	var b bootstrap
	if e = json.Unmarshal(raw, &b); e != nil {
		t.Fatal(e)
	}
	return b
}
func encoded(b bootstrap) string {
	raw, _ := json.Marshal(b)
	return base64.RawURLEncoding.EncodeToString(raw)
}

func TestMultipleNodesStalenessAndPreservedInventory(t *testing.T) {
	f := newFixture(t)
	a, _ := f.enroll(t, "Tehran")
	b, _ := f.enroll(t, "Frankfurt")
	r := sample(t)
	if e := send(t, f, a, r); e != nil {
		t.Fatal(e)
	}
	if e := send(t, f, b, r); e != nil {
		t.Fatal(e)
	}
	v := f.h.Views()
	if len(v.Nodes) != 2 || v.Nodes[0].Status != "online" || v.Nodes[0].ID == v.Nodes[1].ID {
		t.Fatal(v)
	}
	rev := v.Nodes[0].InventoryRevision
	observed := *v.Nodes[0].Observed
	r.Inventory = nil
	r.Failure = &Problem{"inventory_unavailable", "Local inventory could not be read"}
	if e := send(t, f, a, r); e != nil {
		t.Fatal(e)
	}
	v = f.h.Views()
	if v.Nodes[0].Status != "degraded" || v.Nodes[0].InventoryRevision != rev || !v.Nodes[0].Observed.Equal(observed) {
		t.Fatal("failed read replaced last known inventory")
	}
	f.h.mu.Lock()
	f.h.now = func() time.Time { return time.Now().Add(4 * time.Minute) }
	f.h.mu.Unlock()
	v = f.h.Views()
	if v.Nodes[0].Status != "offline" || len(v.Nodes[0].Inventory) == 0 {
		t.Fatal("stale inventory not retained")
	}
}
func TestInvitationPinExpiryAndNoSecretPersistence(t *testing.T) {
	f := newFixture(t)
	inv, e := f.h.Invite("Test")
	if e != nil {
		t.Fatal(e)
	}
	b := code(t, inv)
	bytes, e := os.ReadFile(f.h.path)
	if e != nil {
		t.Fatal(e)
	}
	if strings.Contains(string(bytes), b.Token) {
		t.Fatal("plaintext invitation persisted")
	}
	bad := b
	bad.Pin = strings.Repeat("0", 64)
	if e = Enroll(context.Background(), filepath.Join(t.TempDir(), "id.json"), encoded(bad)); e == nil {
		t.Fatal("wrong CA pin accepted")
	}
	path := filepath.Join(t.TempDir(), "id.json")
	if e = Enroll(context.Background(), path, inv.Code); e != nil {
		t.Fatal(e)
	}
	if e = Enroll(context.Background(), filepath.Join(t.TempDir(), "id.json"), inv.Code); e == nil {
		t.Fatal("reused invitation")
	}
	before, _ := os.ReadFile(path)
	if e = Enroll(context.Background(), path, inv.Code); e == nil {
		t.Fatal("overwrote identity")
	}
	after, _ := os.ReadFile(path)
	if string(before) != string(after) {
		t.Fatal("identity changed")
	}
	other, e := f.h.Invite("Expired")
	if e != nil {
		t.Fatal(e)
	}
	f.h.now = func() time.Time { return time.Now().Add(11 * time.Minute) }
	if e = Enroll(context.Background(), filepath.Join(t.TempDir(), "id.json"), other.Code); e == nil {
		t.Fatal("expired invitation")
	}
}
func TestProtocolAuthorizationAndClosedAPI(t *testing.T) {
	f := newFixture(t)
	a, _ := f.enroll(t, "One")
	r := sample(t)
	r.Protocol = 2
	if e := send(t, f, a, r); e == nil || e.(*Problem).Code != "incompatible_protocol" {
		t.Fatal(e)
	}
	r = sample(t)
	r.Capabilities = []string{"shell"}
	if e := send(t, f, a, r); e == nil {
		t.Fatal("capability mismatch")
	}
	r = sample(t)
	r.Inventory = json.RawMessage(`{"version":"1","shell":"bad"}`)
	if e := send(t, f, a, r); e != nil {
		t.Fatal(e)
	}
	if strings.Contains(string(f.h.Views().Nodes[0].Inventory), "shell") {
		t.Fatal("unknown fields retained")
	}
	c := transport(client(t, a))
	defer c.CloseIdleConnections()
	var out any
	for _, path := range []string{"/control", "/v1/operations", "/v1/exec", "/api/inventory"} {
		if e := post(context.Background(), c, f.s.URL+path, map[string]string{"action": "delete"}, &out); e == nil {
			t.Fatal("remote write endpoint accepted", path)
		}
	}
	anonymous := transport(&tls.Config{MinVersion: tls.VersionTLS13, RootCAs: client(t, a).RootCAs})
	defer anonymous.CloseIdleConnections()
	if e := post(context.Background(), anonymous, f.s.URL+"/v1/report", sample(t), &out); e == nil {
		t.Fatal("anonymous report accepted")
	}
	other := newFixture(t)
	foreign, _ := other.enroll(t, "Foreign")
	if e := send(t, f, foreign, sample(t)); e == nil {
		t.Fatal("foreign CA accepted")
	}
}
func TestRotationRevocationAndRestart(t *testing.T) {
	f := newFixture(t)
	a, _ := f.enroll(t, "One")
	c := transport(client(t, a))
	defer c.CloseIdleConnections()
	k, key, e := newKey()
	if e != nil {
		t.Fatal(e)
	}
	csr, e := makeCSR(k)
	if e != nil {
		t.Fatal(e)
	}
	var rotated struct {
		Certificate []byte `json:"certificate"`
	}
	if e = post(context.Background(), c, f.s.URL+"/v1/rotate", rotateRequest{csr}, &rotated); e != nil {
		t.Fatal(e)
	}
	b := a
	b.Key = key
	b.Certificate = rotated.Certificate
	if e = send(t, f, b, sample(t)); e != nil {
		t.Fatal(e)
	}
	if e = send(t, f, a, sample(t)); e != nil {
		t.Fatal("old certificate overlap lost", e)
	}
	n := f.h.Views().Nodes[0]
	if e = f.h.Revoke(n.ID, "stale"); e == nil {
		t.Fatal("stale revocation accepted")
	}
	if e = f.h.Revoke(n.ID, n.Revision); e != nil {
		t.Fatal(e)
	}
	if e = send(t, f, b, sample(t)); e == nil || !fatal(e) {
		t.Fatal("revoked identity accepted")
	}
	if e = post(context.Background(), c, f.s.URL+"/v1/rotate", rotateRequest{csr}, &rotated); e == nil {
		t.Fatal("revoked identity rotated")
	}
	if _, e = Open(f.dir); e == nil {
		t.Fatal("concurrent Controller acquired state")
	}
	f.h.Close()
	h, e := Open(f.dir)
	if e != nil {
		t.Fatal(e)
	}
	defer h.Close()
	v := h.Views()
	if len(v.Nodes) != 1 || v.Nodes[0].Status != "revoked" || len(v.Nodes[0].Inventory) != 0 {
		t.Fatal("identity persistence or cache reset failed")
	}
}
func TestExpiredCertificateRejectedOnReusedTLSConnection(t *testing.T) {
	f := newFixture(t)
	id, _ := f.enroll(t, "Expiry")
	c := transport(client(t, id))
	defer c.CloseIdleConnections()
	var ack any
	if e := post(context.Background(), c, f.s.URL+"/v1/report", sample(t), &ack); e != nil {
		t.Fatal(e)
	}
	f.h.mu.Lock()
	f.h.now = func() time.Time { return time.Now().Add(31 * 24 * time.Hour) }
	f.h.mu.Unlock()
	e := post(context.Background(), c, f.s.URL+"/v1/report", sample(t), &ack)
	if e == nil || e.(*Problem).Code != "identity_expired" || !fatal(e) {
		t.Fatal("expired TLS identity remained authorized", e)
	}
}
func TestIssuedCredentialCannotOutliveAuthority(t *testing.T) {
	f := newFixture(t)
	ca, _ := parseCert(f.h.state.CA)
	pair, e := tls.X509KeyPair(f.h.state.CA, f.h.state.Key)
	if e != nil {
		t.Fatal(e)
	}
	ca.NotAfter = time.Now().Add(48 * time.Hour).Truncate(time.Second)
	shortCA, e := certificate(ca, ca, ca.PublicKey, pair.PrivateKey)
	if e != nil {
		t.Fatal(e)
	}
	key, _, e := newKey()
	if e != nil {
		t.Fatal(e)
	}
	csr, e := makeCSR(key)
	if e != nil {
		t.Fatal(e)
	}
	for _, host := range []string{"", "127.0.0.1"} {
		crt, _, e := sign(shortCA, f.h.state.Key, csr, randomID(), host)
		if e != nil {
			t.Fatal(e)
		}
		leaf, e := parseCert(crt)
		if e != nil {
			t.Fatal(e)
		}
		if !leaf.NotAfter.Equal(ca.NotAfter) {
			t.Fatal("credential outlives its authority")
		}
	}
}
func TestConcurrentEnrollmentConsumesOnce(t *testing.T) {
	f := newFixture(t)
	inv, e := f.h.Invite("One")
	if e != nil {
		t.Fatal(e)
	}
	paths := []string{filepath.Join(t.TempDir(), "a"), filepath.Join(t.TempDir(), "b")}
	var wg sync.WaitGroup
	results := make(chan error, 2)
	for _, p := range paths {
		wg.Add(1)
		go func(path string) { defer wg.Done(); results <- Enroll(context.Background(), path, inv.Code) }(p)
	}
	wg.Wait()
	close(results)
	wins := 0
	for e := range results {
		if e == nil {
			wins++
		}
	}
	if wins != 1 || len(f.h.Views().Nodes) != 1 {
		t.Fatal("invitation consumed more than once")
	}
}

type pausedBody struct {
	started chan struct{}
	resume  chan struct{}
	reader  io.Reader
	once    sync.Once
}

func (b *pausedBody) Read(p []byte) (int, error) {
	b.once.Do(func() { close(b.started) })
	<-b.resume
	return b.reader.Read(p)
}
func TestRevocationDoesNotWaitForSlowReportBody(t *testing.T) {
	f := newFixture(t)
	id, _ := f.enroll(t, "Slow")
	leaf, _ := parseCert(id.Certificate)
	ca, _ := parseCert(id.CA)
	raw, _ := json.Marshal(sample(t))
	body := &pausedBody{started: make(chan struct{}), resume: make(chan struct{}), reader: strings.NewReader(string(raw))}
	r := httptest.NewRequest("POST", "https://controller/v1/report", body)
	r.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{leaf}, VerifiedChains: [][]*x509.Certificate{{leaf, ca}}}
	w := httptest.NewRecorder()
	done := make(chan struct{})
	go func() { f.h.ServeHTTP(w, r); close(done) }()
	<-body.started
	n := f.h.Views().Nodes[0]
	revoked := make(chan error, 1)
	go func() { revoked <- f.h.Revoke(n.ID, n.Revision) }()
	select {
	case e := <-revoked:
		if e != nil {
			t.Fatal(e)
		}
	case <-time.After(time.Second):
		close(body.resume)
		<-done
		t.Fatal("slow body blocked revocation")
	}
	close(body.resume)
	<-done
	if w.Code != 403 || len(f.h.Views().Nodes[0].Inventory) != 0 {
		t.Fatal("revoked in-flight report was committed")
	}
}
func TestFailedPersistenceDoesNotRevokeInMemory(t *testing.T) {
	f := newFixture(t)
	a, _ := f.enroll(t, "One")
	old := f.h.path
	f.h.path = filepath.Join(f.dir, "missing", "controller.json")
	v := f.h.Views().Nodes[0]
	if e := f.h.Revoke(v.ID, v.Revision); e == nil {
		t.Fatal("save unexpectedly succeeded")
	}
	f.h.path = old
	if e := send(t, f, a, sample(t)); e != nil {
		t.Fatal("failed persistence changed memory")
	}
}
func TestAgentReportsAndCancelsWithoutQueue(t *testing.T) {
	f := newFixture(t)
	_, path := f.enroll(t, "Agent")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- (Agent{Path: path, Version: "1.3.0", Client: control.NewDemo()}).Run(ctx) }()
	deadline := time.Now().Add(5 * time.Second)
	for len(f.h.Views().Nodes[0].Inventory) == 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if len(f.h.Views().Nodes[0].Inventory) == 0 {
		t.Fatal("agent did not report")
	}
	cancel()
	select {
	case e := <-done:
		if e != nil {
			t.Fatal(e)
		}
	case <-time.After(time.Second):
		t.Fatal("agent did not cancel")
	}
	for _, n := range []int{0, 1, 7, 100} {
		d := backoff(n)
		if d < time.Second || d >= 65*time.Second {
			t.Fatal("unbounded retry", d)
		}
	}
}
func TestAgentRetriesAfterInterruptedReport(t *testing.T) {
	f := newFixture(t)
	_, path := f.enroll(t, "Reconnect")
	f.failReports.Store(1)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- (Agent{Path: path, Version: "1.3.0", Client: control.NewDemo()}).Run(ctx) }()
	deadline := time.Now().Add(5 * time.Second)
	for len(f.h.Views().Nodes[0].Inventory) == 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if f.failReports.Load() != 0 || len(f.h.Views().Nodes[0].Inventory) == 0 {
		t.Fatal("Agent did not reconnect after refused report")
	}
	cancel()
	if e := <-done; e != nil {
		t.Fatal(e)
	}
}
func TestAgentAutomaticallyRenewsAndPersistsIdentity(t *testing.T) {
	f := newFixture(t)
	id, path := f.enroll(t, "Renewal")
	leaf, e := parseCert(id.Certificate)
	if e != nil {
		t.Fatal(e)
	}
	ca, e := parseCert(id.CA)
	if e != nil {
		t.Fatal(e)
	}
	authority, e := tls.X509KeyPair(f.h.state.CA, f.h.state.Key)
	if e != nil {
		t.Fatal(e)
	}
	leaf.NotAfter = time.Now().Add(24 * time.Hour)
	id.Certificate, e = certificate(leaf, ca, leaf.PublicKey, authority.PrivateKey)
	if e != nil {
		t.Fatal(e)
	}
	if e = writeJSON(path, id, false); e != nil {
		t.Fatal(e)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- (Agent{Path: path, Version: "1.3.0", Client: control.NewDemo()}).Run(ctx) }()
	deadline := time.Now().Add(5 * time.Second)
	for len(f.h.Views().Nodes[0].Inventory) == 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if len(f.h.Views().Nodes[0].Inventory) == 0 {
		t.Fatal("renewed Agent did not report")
	}
	cancel()
	if e = <-done; e != nil {
		t.Fatal(e)
	}
	var renewed identity
	if e = readJSON(path, &renewed); e != nil {
		t.Fatal(e)
	}
	next, e := parseCert(renewed.Certificate)
	if e != nil {
		t.Fatal(e)
	}
	if next.SerialNumber.Cmp(leaf.SerialNumber) == 0 || time.Until(next.NotAfter) < 29*24*time.Hour || string(renewed.Key) != string(id.Key) {
		t.Fatal("renewal did not preserve key and replace certificate")
	}
	f.h.mu.Lock()
	serverLeaf, e := parseCert(f.h.state.Certificate)
	if e != nil {
		t.Fatal(e)
	}
	serverLeaf.NotAfter = time.Now().Add(24 * time.Hour)
	f.h.state.Certificate, e = certificate(serverLeaf, ca, serverLeaf.PublicKey, authority.PrivateKey)
	f.h.mu.Unlock()
	if e != nil {
		t.Fatal(e)
	}
	rotated, e := f.h.serverCertificate(nil)
	if e != nil {
		t.Fatal(e)
	}
	renewedServer, e := parseCert(pemCertificate(rotated.Certificate[0]))
	if e != nil || time.Until(renewedServer.NotAfter) < 300*24*time.Hour {
		t.Fatal("Controller certificate not renewed")
	}
}
func pemCertificate(b []byte) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: b})
}
func TestValidationAndBounds(t *testing.T) {
	if !validName("سرور خارج‌اروپا") {
		t.Fatal("Persian joiner rejected")
	}
	for _, u := range []string{"http://127.0.0.1:9443", "https://user:pass@host:9443", "https://host:9443/path", "https://host:9443?secret=x", "https://host:0"} {
		if validURL(u) {
			t.Fatal(u)
		}
	}
	for _, n := range []string{"", "\u200c", strings.Repeat("x", 65), "foo\nbar", "hidden\u202Etext"} {
		if validName(n) {
			t.Fatal(n)
		}
	}
	r := sample(t)
	r.Inventory = json.RawMessage(strings.Repeat(" ", MaxInventory+1))
	if validateReport(r) == nil {
		t.Fatal("oversized inventory")
	}
	f := newFixture(t)
	for i := 0; i < 16; i++ {
		if _, e := f.h.Invite("Node"); e != nil {
			t.Fatal(e)
		}
	}
	if _, e := f.h.Invite("Overflow"); e == nil {
		t.Fatal("unbounded tickets")
	}
	var p *Problem
	if !errors.As(problem("code", "message"), &p) {
		t.Fatal("structured problem")
	}
}
