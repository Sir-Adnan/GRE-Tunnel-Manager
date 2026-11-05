package control

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"time"

	"github.com/Sir-Adnan/GRE-Tunnel-Manager/panel/internal/notify"
)

// SafeChange is a forwarding change that reverts itself unless confirmed:
// Point is the restore point saved just before the change and Revision the
// configuration right after it. Anything else changing the configuration
// first cancels the revert (it would undo that too).
type SafeChange struct {
	Action   string    `json:"action"`
	Summary  string    `json:"summary"`
	Point    string    `json:"point"`
	Revision string    `json:"revision"`
	Started  time.Time `json:"started"`
	Deadline time.Time `json:"deadline"`
}

// safeActions may arm a revert: they all save a restore point through gtm_commit.
var safeActions = map[string]bool{"create": true, "update": true, "delete": true, "enable": true, "disable": true}

func (o *Operations) loadSafe() {
	data, e := os.ReadFile(o.safePath)
	if e != nil {
		return
	}
	var s SafeChange
	if json.Unmarshal(data, &s) == nil && pointName.MatchString(s.Point) && digestValid(s.Revision) {
		o.safe = &s
	}
}

func (o *Operations) saveSafe() error {
	if o.safe == nil {
		if e := os.Remove(o.safePath); e != nil && !os.IsNotExist(e) {
			return e
		}
		return nil
	}
	data, e := json.Marshal(o.safe)
	if e != nil {
		return e
	}
	return writePrivate(o.safePath, data)
}

// newestPoint is the newest restore point and the current revision.
func (m *Manager) newestPoint(ctx context.Context) (string, string, error) {
	out, e := m.call(ctx, "history", "", "1")
	if e != nil {
		return "", "", e
	}
	d, e := parseHistory(out)
	if e != nil || len(d.points) == 0 || !digestValid(d.revision) {
		return "", "", errors.New("no restore point to return to")
	}
	return d.points[0].name, d.revision, nil
}

// armSafe records the change just applied; it reverts after minutes.
func (m *Manager) armSafe(ctx context.Context, r Request, now time.Time) error {
	o := m.Ops
	point, revision, e := m.newestPoint(ctx)
	if e != nil {
		return e
	}
	// The panel names the action in its own language; the summary is data.
	summary := strings.TrimSpace(r.Connection.Name + " " + r.Connection.Ports)
	if summary == "" && len(r.Selected) > 0 {
		ids := []string{}
		for _, s := range r.Selected {
			ids = append(ids, s.ID)
		}
		summary = strings.Join(ids, ", ")
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	o.safe = &SafeChange{Action: r.Action, Summary: truncate(summary, 120), Point: point, Revision: revision, Started: now, Deadline: now.Add(time.Duration(r.SafeMinutes) * time.Minute)}
	return o.saveSafe()
}

func (o *Operations) pendingSafe() *SafeChange {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.safe == nil {
		return nil
	}
	s := *o.safe
	return &s
}

func (o *Operations) clearSafe() error {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.safe = nil
	return o.saveSafe()
}

// revertSafe restores the point when nothing else changed since the change.
func (m *Manager) revertSafe(ctx context.Context, s SafeChange, reason string) error {
	o := m.Ops
	current, e := m.call(ctx, "recovery-revision", "")
	if e != nil {
		return e
	}
	if strings.TrimSpace(current) != s.Revision {
		_ = o.clearSafe()
		o.Notify.Emit(notify.Event{Kind: notify.KindChangeReverted, Name: s.Summary, Detail: "not reverted: the configuration changed again", Args: map[string]string{"skipped": "1"}})
		return errors.New("the configuration changed again; nothing was reverted")
	}
	_, e = m.call(ctx, "history-restore", "", s.Point, s.Revision)
	_ = o.clearSafe()
	o.invalidate()
	args := map[string]string{"reason": reason}
	detail := "restored the configuration from before the change"
	if e != nil {
		args["error"] = truncate(e.Error(), 160)
		detail = "revert failed: " + args["error"]
	}
	o.Notify.Emit(notify.Event{Kind: notify.KindChangeReverted, Name: s.Summary, Detail: detail, Args: args})
	return e
}

// safeChange serves change-pending, change-confirm and change-revert.
func (m *Manager) safeChange(ctx context.Context, r Request) (any, error) {
	if m.Ops == nil {
		return nil, errors.New("safe apply is unavailable on this broker")
	}
	s := m.Ops.pendingSafe()
	switch r.Action {
	case "change-pending":
		return map[string]any{"pending": s}, nil
	case "change-confirm":
		if s == nil {
			return map[string]any{"pending": nil}, nil
		}
		return map[string]any{"pending": nil}, m.Ops.clearSafe()
	case "change-revert":
		if s == nil {
			return nil, errors.New("no change is waiting for confirmation")
		}
		return map[string]any{"pending": nil}, m.revertSafe(ctx, *s, "manual")
	}
	return nil, errors.New("unknown action")
}

// checkSafe reverts an expired unconfirmed change. Called by the broker loop
// under the mutation lock.
func (m *Manager) checkSafe(ctx context.Context, now time.Time) {
	s := m.Ops.pendingSafe()
	if s == nil || now.Before(s.Deadline) {
		return
	}
	_ = m.revertSafe(ctx, *s, "timeout")
}
