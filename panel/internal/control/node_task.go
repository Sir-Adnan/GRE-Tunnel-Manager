package control

// Node operations deliberately have a smaller vocabulary than the local panel.
// A root-owned receipt makes delivery retryable; an interrupted create is never
// blindly replayed. Unconfirmed creates are leases, not permanent changes.
import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
)

const NodeOperationCapability = "connections.pair.v1"

type NodeSpec struct {
	Kind    string  `json:"kind"`
	GRE     GRE     `json:"gre"`
	Reverse Reverse `json:"reverse"`
}
type NodeTask struct {
	ID       string    `json:"id"`
	Stage    string    `json:"stage"`
	Expires  time.Time `json:"expires"`
	Revision string    `json:"revision"`
	Spec     NodeSpec  `json:"spec"`
}
type NodeResult struct {
	ID       string     `json:"id"`
	Stage    string     `json:"stage"`
	State    string     `json:"state"`
	Revision string     `json:"revision,omitempty"`
	Deadline *time.Time `json:"deadline,omitempty"`
	Code     string     `json:"code,omitempty"`
}
type nodeReceipt struct {
	Schema      int        `json:"schema"`
	Spec        NodeSpec   `json:"spec"`
	Result      NodeResult `json:"result"`
	Fingerprint string     `json:"fingerprint"`
	Expires     time.Time  `json:"expires"`
}
type NodeExecutor struct {
	Manager      *Manager
	Directory    string
	Now          func() time.Time
	nextRecovery time.Time
}

var taskID = regexp.MustCompile(`^[a-f0-9]{32}$`)
var taskHash = regexp.MustCompile(`^[a-f0-9]{64}$`)

func (s NodeSpec) Service() string {
	if s.Kind == "gre" {
		return "gre-tun-" + strconv.Itoa(s.GRE.ID)
	}
	return "gtm-frp-" + s.Reverse.Role + "-" + s.Reverse.Name
}
func (s NodeSpec) Validate() error {
	if s.Kind == "gre" {
		g := s.GRE
		a, e := netip.ParseAddr(g.Remote)
		b, f := netip.ParseAddr(g.Bind)
		if e != nil || f != nil || a.Zone() != "" || b.Zone() != "" || a.Is4In6() || b.Is4In6() || !a.IsGlobalUnicast() || !b.IsGlobalUnicast() || a == b || a.Is4() != b.Is4() || g.ID < 1 || g.ID > 250 || !oneOf(g.Role, "kharej", "iran") || g.MTU < 1280 || g.MTU > 1472 || (!a.Is4() && g.MTU > 1452) || s.Reverse != (Reverse{}) {
			return errors.New("invalid paired GRE settings")
		}
		return nil
	}
	r := s.Reverse
	if s.Kind != "frp" || s.GRE != (GRE{}) || r.Engine != "frp" || !oneOf(r.Transport, "tcp", "websocket", "quic") || r.Certificate != "" || r.Key != "" || r.Internal != 0 {
		return errors.New("unsupported paired connection")
	}
	h, e := netip.ParseAddr(r.Host)
	local, f := netip.ParseAddr(r.LocalIP)
	if e != nil || f != nil || !h.IsGlobalUnicast() || h.Is4In6() || local.IsUnspecified() || local.IsMulticast() || local.Is4In6() {
		return errors.New("invalid paired reverse addresses")
	}
	_, e = r.Input()
	return e
}
func taskDigest(v any) string {
	b, _ := json.Marshal(v)
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}
func (x *NodeExecutor) now() time.Time {
	if x.Now != nil {
		return x.Now()
	}
	return time.Now()
}
func (x *NodeExecutor) save(r nodeReceipt) error {
	if e := os.MkdirAll(x.Directory, 0700); e != nil {
		return e
	}
	b, e := json.Marshal(r)
	if e != nil {
		return e
	}
	f, e := os.CreateTemp(x.Directory, ".receipt-*")
	if e != nil {
		return e
	}
	defer os.Remove(f.Name())
	if e = f.Chmod(0600); e == nil {
		_, e = f.Write(b)
	}
	if e == nil {
		e = f.Sync()
	}
	c := f.Close()
	if e == nil {
		e = c
	}
	if e != nil {
		return e
	}
	if e = os.Rename(f.Name(), filepath.Join(x.Directory, r.Result.ID+".json")); e != nil {
		return e
	}
	if r.Result.State == "applied" && r.Result.Deadline != nil && (x.nextRecovery.IsZero() || r.Result.Deadline.Before(x.nextRecovery)) {
		x.nextRecovery = *r.Result.Deadline
	}
	return nil
}
func (x *NodeExecutor) load(id string) (nodeReceipt, error) {
	var r nodeReceipt
	f, e := os.Open(filepath.Join(x.Directory, id+".json"))
	if e != nil {
		return r, e
	}
	defer f.Close()
	info, e := f.Stat()
	if e != nil || !info.Mode().IsRegular() || info.Size() > 16384 {
		return r, errors.New("invalid receipt file")
	}
	b, e := io.ReadAll(io.LimitReader(f, 16385))
	if e != nil {
		return r, e
	}
	if len(b) > 16384 || json.Unmarshal(b, &r) != nil || r.Schema != 1 || r.Result.ID != id || r.Spec.Validate() != nil || r.Expires.IsZero() || !oneOf(r.Result.State, "prepared", "executing", "applied", "committed", "rolled_back", "failed", "unknown") || !oneOf(r.Result.Stage, "prepare", "apply", "confirm", "rollback") {
		return r, errors.New("invalid node receipt")
	}
	if oneOf(r.Result.State, "applied", "committed") && (!taskHash.MatchString(r.Fingerprint) || r.Result.Deadline == nil) {
		return r, errors.New("invalid applied receipt")
	}
	if r.Result.State == "prepared" && !taskHash.MatchString(r.Result.Revision) {
		return r, errors.New("invalid preparation receipt")
	}
	return r, nil
}
func (x *NodeExecutor) Execute(ctx context.Context, t NodeTask) (NodeResult, error) {
	bad := NodeResult{ID: t.ID, Stage: t.Stage, State: "failed", Code: "invalid_task"}
	if !taskID.MatchString(t.ID) || !oneOf(t.Stage, "prepare", "apply", "confirm", "rollback", "status") || t.Spec.Validate() != nil {
		return bad, nil
	}
	if !t.Expires.After(x.now()) || t.Expires.After(x.now().Add(11*time.Minute)) {
		bad.Code = "expired"
		return bad, nil
	}
	r, e := x.load(t.ID)
	if os.IsNotExist(e) {
		if t.Stage != "prepare" {
			bad.Code = "receipt_missing"
			return bad, nil
		}
		entries, e := os.ReadDir(x.Directory)
		if e != nil && !os.IsNotExist(e) {
			return bad, e
		}
		// Keep receipts until their authorization window has closed. Old job IDs
		// cannot execute again because expired requests are rejected above.
		count := 0
		for _, f := range entries {
			if strings.HasSuffix(f.Name(), ".json") {
				count++
			}
		}
		if count >= 256 {
			bad.Code = "receipt_capacity"
			return bad, nil
		}
		r = nodeReceipt{Schema: 1, Spec: t.Spec, Result: NodeResult{ID: t.ID, Stage: t.Stage, State: "prepared"}, Expires: t.Expires}
		out, e := x.check(ctx, t.Spec)
		if e != nil || !taskHash.MatchString(lastLine(out)) {
			bad.Code = "preflight_failed"
			r.Result = bad
		} else {
			r.Result.Revision = lastLine(out)
		}
		if e = x.save(r); e != nil {
			return bad, e
		}
		return r.Result, nil
	}
	if e != nil {
		return bad, e
	}
	if taskDigest(r.Spec) != taskDigest(t.Spec) {
		bad.Code = "idempotency_conflict"
		return bad, nil
	}
	if r.Result.State == "executing" {
		r.Result.State = "unknown"
		r.Result.Code = "interrupted"
		if e = x.save(r); e != nil {
			return bad, e
		}
	}
	if t.Stage == "status" {
		return r.Result, nil
	}
	if t.Stage == "prepare" || r.Result.State == "unknown" {
		return r.Result, nil
	}
	if t.Stage == "apply" {
		if r.Result.State != "prepared" {
			return r.Result, nil
		}
		if !r.Expires.After(x.now()) {
			bad.Code = "expired"
			return bad, nil
		}
		if t.Revision != r.Result.Revision {
			bad.Code = "revision_conflict"
			return bad, nil
		}
		// Persist before the first side effect. A crash here requires inspection,
		// never a second create against potentially existing network resources.
		r.Result.State = "executing"
		r.Result.Stage = "apply"
		deadline := x.now().Add(5 * time.Minute)
		r.Result.Deadline = &deadline
		if e = x.save(r); e != nil {
			return bad, e
		}
		out, e := x.apply(ctx, t.Spec, t.Revision)
		fp := lastLine(out)
		if e != nil || !taskHash.MatchString(fp) {
			r.Result.State = "unknown"
			r.Result.Code = "apply_needs_inspection"
			var exit interface{ ExitCode() int }
			if errors.As(e, &exit) && exit.ExitCode() == 75 {
				r.Result.State = "failed"
				r.Result.Code = "preflight_changed"
			}
		} else {
			r.Result.State = "applied"
			r.Fingerprint = fp
		}
	} else if t.Stage == "confirm" {
		if r.Result.State == "committed" {
			return r.Result, nil
		}
		if r.Result.State != "applied" || r.Result.Deadline == nil || !r.Result.Deadline.After(x.now()) {
			bad.Code = "confirmation_expired"
			return bad, nil
		}
		if _, e = x.Manager.call(ctx, "pair-verify", "", r.Spec.Service(), r.Fingerprint); e != nil {
			bad.Code = "resource_changed"
			return bad, nil
		}
		r.Result.State = "committed"
		r.Result.Stage = "confirm"
	} else if t.Stage == "rollback" {
		if r.Result.State == "rolled_back" {
			return r.Result, nil
		}
		if r.Result.State == "committed" && !r.Expires.After(x.now()) {
			bad.Code = "committed_resource"
			return bad, nil
		}
		if r.Result.State == "applied" || r.Result.State == "committed" {
			if _, e = x.Manager.call(ctx, "pair-delete", "", r.Spec.Service(), r.Fingerprint); e != nil {
				r.Result.State = "unknown"
				r.Result.Code = "rollback_needs_inspection"
			} else {
				r.Result.State = "rolled_back"
				r.Result.Code = ""
			}
		} else if r.Result.State == "prepared" || r.Result.State == "failed" {
			r.Result.State = "rolled_back"
			r.Result.Code = ""
		}
		r.Result.Stage = "rollback"
	}
	if e = x.save(r); e != nil {
		return bad, e
	}
	return r.Result, nil
}
func lastLine(s string) string {
	lines := strings.Split(strings.TrimSpace(s), "\n")
	return lines[len(lines)-1]
}
func (x *NodeExecutor) check(ctx context.Context, s NodeSpec) (string, error) {
	if s.Kind == "gre" {
		g := s.GRE
		return x.Manager.call(ctx, "pair-check-gre", "", strconv.Itoa(g.ID), g.Role, g.Remote, g.Bind, strconv.Itoa(g.MTU))
	}
	in, e := s.Reverse.Input()
	if e != nil {
		return "", e
	}
	return x.Manager.call(ctx, "pair-check-frp", in)
}
func (x *NodeExecutor) apply(ctx context.Context, s NodeSpec, rev string) (string, error) {
	if s.Kind == "gre" {
		g := s.GRE
		return x.Manager.call(ctx, "pair-apply-gre", "", rev, strconv.Itoa(g.ID), g.Role, g.Remote, g.Bind, strconv.Itoa(g.MTU))
	}
	in, e := s.Reverse.Input()
	if e != nil {
		return "", e
	}
	return x.Manager.call(ctx, "pair-apply-frp", in, rev)
}

// Recover is called under the broker mutex, including once at startup. Expiry
// never depends on the browser, Controller, or outbound Agent remaining online.
func (x *NodeExecutor) Recover(ctx context.Context) (err error) {
	defer func() {
		if err != nil {
			x.nextRecovery = time.Time{}
		}
	}()
	if x.nextRecovery.After(x.now()) {
		return nil
	}
	x.nextRecovery = x.now().Add(time.Hour)
	files, e := os.ReadDir(x.Directory)
	if os.IsNotExist(e) {
		return nil
	}
	if e != nil {
		return e
	}
	for _, f := range files {
		id := strings.TrimSuffix(f.Name(), ".json")
		if !taskID.MatchString(id) || f.IsDir() {
			continue
		}
		r, e := x.load(id)
		if e != nil {
			x.nextRecovery = time.Time{}
			return e
		}
		if r.Result.State == "executing" {
			r.Result.State = "unknown"
			r.Result.Code = "interrupted"
			if e = x.save(r); e != nil {
				x.nextRecovery = time.Time{}
				return e
			}
		}
		if r.Result.State == "applied" && r.Result.Deadline != nil && !r.Result.Deadline.After(x.now()) {
			var outcome NodeResult
			outcome, e = x.Execute(ctx, NodeTask{ID: id, Stage: "rollback", Expires: x.now().Add(time.Minute), Spec: r.Spec})
			if e != nil {
				x.nextRecovery = time.Time{}
				return e
			}
			if outcome.State == "unknown" {
				log.Printf("node lease recovery needs inspection: %s", id)
			}
		}
		if r.Result.State == "applied" && r.Result.Deadline != nil && r.Result.Deadline.After(x.now()) && r.Result.Deadline.Before(x.nextRecovery) {
			x.nextRecovery = *r.Result.Deadline
		}
		// Never prune unresolved changes or an active confirmation lease.
		if oneOf(r.Result.State, "committed", "rolled_back", "failed", "prepared") && x.now().Sub(r.Expires) > 48*time.Hour {
			if e = os.Remove(filepath.Join(x.Directory, f.Name())); e != nil {
				return e
			}
		}
	}
	return nil
}
