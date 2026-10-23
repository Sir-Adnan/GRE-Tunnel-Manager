package nodes

import (
	"context"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Sir-Adnan/GRE-Tunnel-Manager/panel/internal/control"
)

func pairFixture(t *testing.T) (*fixture, PairRequest, identity) {
	t.Helper()
	f := newFixture(t)
	id, _ := f.enroll(t, "remote")
	r := sample(t)
	r.Capabilities = []string{"inventory.read", control.NodeOperationCapability}
	if e := post(context.Background(), transport(client(t, id)), f.s.URL+"/v1/report", r, &map[string]any{}); e != nil {
		t.Fatal(e)
	}
	remote := f.h.Views().Nodes[0]
	return f, PairRequest{ID: strings.Repeat("c", 32), Kind: "gre", Entrance: NodeChoice{ID: "local", Address: "192.0.2.1"}, Destination: NodeChoice{ID: id.ID, Revision: remote.Revision, Address: "198.51.100.2"}, GREID: 1, MTU: 1430}, id
}
func workFor(t *testing.T, h *Hub, node string, r *control.NodeResult) workReply {
	t.Helper()
	h.mu.Lock()
	defer h.mu.Unlock()
	out, e := h.work(node, r)
	if e != nil {
		t.Fatal(e)
	}
	return out
}
func ackTask(w workReply, state string) *control.NodeResult {
	if w.Task == nil {
		return nil
	}
	d := time.Now().Add(5 * time.Minute)
	return &control.NodeResult{ID: w.Task.ID, Stage: w.Task.Stage, State: state, Revision: strings.Repeat("a", 64), Deadline: &d}
}
func preparedPair(t *testing.T) (*fixture, PairRequest) {
	f, in, _ := pairFixture(t)
	if _, e := f.h.CreatePair(in); e != nil {
		t.Fatal(e)
	}
	local := workFor(t, f.h, "local", nil)
	remote := workFor(t, f.h, in.Destination.ID, nil)
	workFor(t, f.h, "local", ackTask(local, "prepared"))
	workFor(t, f.h, in.Destination.ID, ackTask(remote, "prepared"))
	return f, in
}
func appliedPair(t *testing.T) (*fixture, PairRequest) {
	f, in := preparedPair(t)
	local := workFor(t, f.h, "local", nil)
	if local.Task == nil || local.Task.Stage != "apply" || local.Task.Revision != strings.Repeat("a", 64) {
		t.Fatal(local)
	}
	if workFor(t, f.h, in.Destination.ID, nil).Task != nil {
		t.Fatal("destination applied before entrance")
	}
	workFor(t, f.h, "local", ackTask(local, "applied"))
	remote := workFor(t, f.h, in.Destination.ID, nil)
	workFor(t, f.h, in.Destination.ID, ackTask(remote, "applied"))
	if f.h.Pairs()[0].State != "awaiting_confirmation" {
		t.Fatal(f.h.Pairs())
	}
	return f, in
}
func TestPairSuccessRedactionAndIdempotency(t *testing.T) {
	f, in := appliedPair(t)
	initial := f.h.Pairs()[0]
	duplicate, e := f.h.CreatePair(in)
	if e != nil || duplicate.ID != initial.ID {
		t.Fatal(duplicate, e)
	}
	bad := in
	bad.MTU = 1400
	if _, e = f.h.CreatePair(bad); e == nil {
		t.Fatal("request ID reused")
	}
	if _, e = f.h.PairDecision(initial.ID, "stale", "confirm"); e == nil {
		t.Fatal("stale confirm")
	}
	if _, e = f.h.PairDecision(initial.ID, initial.Revision, "confirm"); e != nil {
		t.Fatal(e)
	}
	for _, node := range []string{"local", in.Destination.ID} {
		w := workFor(t, f.h, node, nil)
		if w.Task.Stage != "confirm" {
			t.Fatal(w)
		}
		workFor(t, f.h, node, ackTask(w, "committed"))
	}
	if f.h.Pairs()[0].State != "succeeded" {
		t.Fatal(f.h.Pairs())
	}
	// A restarted Controller resumes durable jobs without replaying old stages.
	f.h.Close()
	h, e := Open(f.dir)
	if e != nil {
		t.Fatal(e)
	}
	defer h.Close()
	if h.Pairs()[0].State != "succeeded" || workFor(t, h, "local", nil).Task != nil {
		t.Fatal("completed work replayed")
	}
	raw, _ := json.Marshal(h.Pairs())
	if strings.Contains(string(raw), "token") || strings.Contains(string(raw), "serials") {
		t.Fatal("private state disclosed")
	}
}
func TestPairOneSidedFailureAndRecovery(t *testing.T) {
	f, in := preparedPair(t)
	w := workFor(t, f.h, "local", nil)
	workFor(t, f.h, "local", ackTask(w, "applied"))
	w = workFor(t, f.h, in.Destination.ID, nil)
	workFor(t, f.h, in.Destination.ID, ackTask(w, "unknown"))
	if f.h.Pairs()[0].State != "rolling_back" {
		t.Fatal(f.h.Pairs())
	}
	w = workFor(t, f.h, "local", nil)
	if w.Task.Stage != "rollback" {
		t.Fatal(w)
	}
	workFor(t, f.h, "local", ackTask(w, "rolled_back"))
	w = workFor(t, f.h, in.Destination.ID, nil)
	workFor(t, f.h, in.Destination.ID, ackTask(w, "unknown"))
	if f.h.Pairs()[0].State != "needs_attention" {
		t.Fatal("uncertain create reported as success")
	}
}
func TestPairExpiredAfterReconnectAndRevocation(t *testing.T) {
	f, in := appliedPair(t)
	advanced := time.Now().Add(6 * time.Minute)
	f.h.now = func() time.Time { return advanced }
	w := workFor(t, f.h, in.Destination.ID, nil)
	if w.Task == nil || w.Task.Stage != "rollback" {
		t.Fatal("expired apply/confirm offered", w)
	}
	advanced = advanced.Add(3 * time.Minute)
	workFor(t, f.h, "local", nil)
	if f.h.Pairs()[0].State != "needs_attention" {
		t.Fatal(f.h.Pairs())
	}
	g, req, _ := pairFixture(t)
	_, e := g.h.CreatePair(req)
	if e != nil {
		t.Fatal(e)
	}
	if e = g.h.Revoke(req.Destination.ID, req.Destination.Revision); e != nil {
		t.Fatal(e)
	}
	if workFor(t, g.h, req.Destination.ID, nil).Task != nil {
		t.Fatal("revoked identity received work")
	}
}
func TestPairWorkRequiresMTLSAndExplicitCapability(t *testing.T) {
	f, in, id := pairFixture(t)
	if _, e := f.h.CreatePair(in); e != nil {
		t.Fatal(e)
	}
	tc := client(t, id)
	c := transport(tc)
	defer c.CloseIdleConnections()
	var got workReply
	if e := post(context.Background(), c, f.s.URL+"/v1/work", workRequest{}, &got); e != nil || got.Task == nil {
		t.Fatal(got, e)
	}
	// The endpoint still rejects anonymous clients even if they trust the CA.
	anonymous := tc.Clone()
	anonymous.Certificates = nil
	anon := transport(anonymous)
	defer anon.CloseIdleConnections()
	e := post(context.Background(), anon, f.s.URL+"/v1/work", workRequest{}, &got)
	if e == nil {
		t.Fatal("anonymous work accepted")
	}
	r := sample(t)
	if e = post(context.Background(), c, f.s.URL+"/v1/report", r, &map[string]any{}); e != nil {
		t.Fatal(e)
	}
	if e = post(context.Background(), c, f.s.URL+"/v1/work", workRequest{}, &got); e == nil {
		t.Fatal("read-only capability accepted")
	}
}

func TestPairFRPRemoteToRemoteKeepsTokenPrivate(t *testing.T) {
	f, in, _ := pairFixture(t)
	other, _ := f.enroll(t, "second remote")
	r := sample(t)
	r.Capabilities = []string{"inventory.read", control.NodeOperationCapability}
	if e := send(t, f, other, r); e != nil {
		t.Fatal(e)
	}
	v := f.h.Views().Nodes[1]
	in.Entrance = NodeChoice{ID: other.ID, Revision: v.Revision, Address: "192.0.2.1"}
	in.Kind = "frp"
	in.GREID = 0
	in.MTU = 0
	in.ControlPort = 7000
	in.PublicPort = 443
	in.LocalIP = "127.0.0.1"
	in.LocalPort = 8443
	in.Protocol = "tcp"
	in.Transport = "websocket"
	if _, e := f.h.CreatePair(in); e != nil {
		t.Fatal(e)
	}
	a := workFor(t, f.h, other.ID, nil)
	b := workFor(t, f.h, in.Destination.ID, nil)
	if a.Task.Spec.Reverse.Token != b.Task.Spec.Reverse.Token || len(a.Task.Spec.Reverse.Token) != 64 || a.Task.Spec.Reverse.Role != "entrance" || b.Task.Spec.Reverse.Role != "destination" {
		t.Fatal("inconsistent peer credentials")
	}
	raw, _ := json.Marshal(f.h.Pairs())
	if strings.Contains(string(raw), a.Task.Spec.Reverse.Token) || strings.Contains(string(raw), "local_ip") {
		t.Fatal("private request exposed in browser results")
	}
	if workFor(t, f.h, "local", nil).Task != nil {
		t.Fatal("unselected local Node received work")
	}
}

func TestPairPersistenceFailureAndInterruptedAcknowledgment(t *testing.T) {
	f, in := preparedPair(t)
	w := workFor(t, f.h, "local", nil)
	// A lost response redelivers exactly the same stage and preparation revision.
	again := workFor(t, f.h, "local", nil)
	if w.Task.ID != again.Task.ID || w.Task.Stage != again.Task.Stage || w.Task.Revision != again.Task.Revision {
		t.Fatal("unstable delivery")
	}
	previous := f.h.pairs[0]
	oldPath := f.h.path
	f.h.path = filepath.Join(t.TempDir(), "missing", "controller.json")
	f.h.mu.Lock()
	_, e := f.h.work("local", ackTask(w, "applied"))
	f.h.mu.Unlock()
	f.h.path = oldPath
	if e == nil || f.h.pairs[0].Revision != previous.Revision || f.h.pairs[0].Steps[0].Applied {
		t.Fatal("unpersisted result acknowledged")
	}
	workFor(t, f.h, "local", ackTask(w, "applied"))
	// Repeated results cannot advance a new stage or overwrite its stored state.
	workFor(t, f.h, "local", ackTask(w, "applied"))
	if workFor(t, f.h, in.Destination.ID, nil).Task.Stage != "apply" {
		t.Fatal("delivery stalled after retry")
	}
}

func TestPairRejectsUnboundedLocalMetadata(t *testing.T) {
	f, in, _ := pairFixture(t)
	in.Entrance.Revision = strings.Repeat("a", 10000)
	if _, e := f.h.CreatePair(in); e == nil {
		t.Fatal("unbounded local revision persisted")
	}
	if len(f.h.Pairs()) != 0 {
		t.Fatal("invalid metadata created a job")
	}
}
