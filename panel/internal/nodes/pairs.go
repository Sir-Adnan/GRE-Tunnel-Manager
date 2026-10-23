package nodes

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/Sir-Adnan/GRE-Tunnel-Manager/panel/internal/control"
)

func (h *Hub) choice(c NodeChoice) error {
	if c.ID == "local" {
		if c.Revision != "" {
			return problem("revision_conflict", "Local Node identity has no enrollment revision")
		}
		return nil
	}
	if !idPattern.MatchString(c.ID) || !idPattern.MatchString(c.Revision) {
		return problem("revision_conflict", "Refresh nodes before selecting an identity")
	}
	for _, n := range h.state.Nodes {
		if n.ID == c.ID && !n.Revoked && n.Revision == c.Revision {
			o, ok := h.cache[n.ID]
			if !ok || h.now().Sub(o.seen) > 3*time.Minute || o.report.Failure != nil || !hasOperations(o.report.Capabilities) {
				return problem("node_unavailable", "Refresh nodes; paired operations require an online Agent installed with --operations")
			}
			return nil
		}
	}
	return problem("revision_conflict", "Node identity changed; refresh nodes")
}
func (h *Hub) CreatePair(in PairRequest) (PairView, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.closed {
		return PairView{}, errors.New("Controller is stopping")
	}
	if !idPattern.MatchString(in.ID) {
		return PairView{}, problem("invalid_id", "A unique request ID is required")
	}
	raw, _ := json.Marshal(in)
	inputHash := digest(raw)
	for _, p := range h.pairs {
		if p.ID == in.ID {
			if p.InputHash != inputHash {
				return PairView{}, problem("idempotency_conflict", "Request ID already belongs to different settings")
			}
			return p.view(), nil
		}
	}
	if in.Entrance.ID == in.Destination.ID {
		return PairView{}, problem("invalid_nodes", "Choose two different servers")
	}
	if e := h.choice(in.Entrance); e != nil {
		return PairView{}, e
	}
	if e := h.choice(in.Destination); e != nil {
		return PairView{}, e
	}
	if in.Name == "" {
		in.Name = in.Kind + "-" + in.ID[:8]
	}
	if !validName(in.Name) {
		return PairView{}, problem("invalid_name", "Use a name with 1–64 visible characters")
	}
	p := pair{Schema: 1, ID: in.ID, Name: in.Name, Kind: in.Kind, InputHash: inputHash, Revision: randomID(), State: "preparing", Created: h.now()}
	p.Expires = p.Created.Add(10 * time.Minute)
	p.Steps[0] = pairStep{Node: in.Entrance.ID, NodeRevision: in.Entrance.Revision, Stage: "prepare"}
	p.Steps[1] = pairStep{Node: in.Destination.ID, NodeRevision: in.Destination.Revision, Stage: "prepare"}
	if in.Kind == "gre" {
		if in.ControlPort != 0 || in.PublicPort != 0 || in.LocalIP != "" || in.LocalPort != 0 || in.Protocol != "" || in.Transport != "" {
			return PairView{}, problem("invalid_request", "GRE does not accept reverse settings")
		}
		p.Steps[0].Spec = control.NodeSpec{Kind: "gre", GRE: control.GRE{ID: in.GREID, Role: "iran", Bind: in.Entrance.Address, Remote: in.Destination.Address, MTU: in.MTU}}
		p.Steps[1].Spec = control.NodeSpec{Kind: "gre", GRE: control.GRE{ID: in.GREID, Role: "kharej", Bind: in.Destination.Address, Remote: in.Entrance.Address, MTU: in.MTU}}
	} else if in.Kind == "frp" {
		if in.GREID != 0 || in.MTU != 0 {
			return PairView{}, problem("invalid_request", "FRP does not accept GRE settings")
		}
		token := randomID() + randomID()
		name := "pair-" + in.ID[:16]
		r := control.Reverse{Engine: "frp", Name: name, Role: "entrance", Host: in.Entrance.Address, Control: in.ControlPort, Public: in.PublicPort, LocalIP: in.LocalIP, LocalPort: in.LocalPort, Protocol: in.Protocol, Transport: in.Transport, Mux: true, Token: token, Group: name}
		p.Steps[0].Spec = control.NodeSpec{Kind: "frp", Reverse: r}
		r.Role = "destination"
		p.Steps[1].Spec = control.NodeSpec{Kind: "frp", Reverse: r}
	} else {
		return PairView{}, problem("unsupported_kind", "Choose GRE or FRP")
	}
	for _, s := range p.Steps {
		if e := s.Spec.Validate(); e != nil {
			return PairView{}, e
		}
	}
	next := []pair{}
	for _, old := range h.pairs {
		if one(old.State, "succeeded", "rolled_back") && h.now().Sub(old.Expires) > 48*time.Hour {
			continue
		}
		if !terminal(old) {
			for _, a := range old.Steps {
				for _, b := range p.Steps {
					if a.Node == b.Node {
						return PairView{}, problem("node_busy", "Finish the active connection on these servers first")
					}
				}
			}
		}
		next = append(next, old)
	}
	if len(next) >= 32 {
		return PairView{}, problem("capacity", "At most 32 retained pair jobs are supported")
	}
	next = append(next, p)
	if e := h.savePairs(next); e != nil {
		return PairView{}, e
	}
	return p.view(), nil
}
func (h *Hub) Pairs() []PairView {
	h.mu.Lock()
	defer h.mu.Unlock()
	out := []PairView{}
	for _, p := range h.pairs {
		out = append(out, p.view())
	}
	return out
}
func setStage(p *pair, i int, stage string) { p.Steps[i].Stage = stage; p.Steps[i].Result = nil }
func (h *Hub) advance(p *pair) {
	if terminal(*p) {
		return
	}
	now := h.now()
	if p.State != "rolling_back" {
		fail := !p.Expires.After(now)
		for _, s := range p.Steps {
			if s.Result != nil && one(s.Result.State, "failed", "unknown", "rolled_back") {
				fail = true
			}
			if s.Applied && s.Deadline != nil && !s.Deadline.After(now) && (s.Result == nil || s.Result.State != "committed") {
				fail = true
			}
		}
		if fail {
			p.State = "rolling_back"
			p.RecoveryUntil = now.Add(2 * time.Minute)
			for i, s := range p.Steps {
				if s.Stage == "apply" || s.Applied || s.Prepared {
					setStage(p, i, "rollback")
				}
			}
		}
	}
	a, b := p.Steps[0], p.Steps[1]
	switch p.State {
	case "preparing":
		if a.Prepared && b.Prepared {
			p.State = "applying"
			setStage(p, 0, "apply")
		}
	case "applying":
		if a.Applied && b.Stage == "prepare" {
			setStage(p, 1, "apply")
		}
		if a.Applied && b.Applied {
			p.State = "awaiting_confirmation"
		}
	case "confirming":
		if a.Result != nil && b.Result != nil && a.Result.State == "committed" && b.Result.State == "committed" {
			p.State = "succeeded"
		}
	case "rolling_back":
		if !p.RecoveryUntil.After(now) {
			for i, s := range p.Steps {
				if s.Stage == "rollback" && s.Result == nil {
					p.Steps[i].Result = &control.NodeResult{ID: p.ID, Stage: "rollback", State: "unknown", Code: "recovery_timeout"}
				}
			}
		}
		finished, attention := true, false
		for _, s := range p.Steps {
			if s.Stage == "rollback" && s.Result == nil {
				finished = false
			}
			if s.Result != nil && (s.Result.State == "unknown" || (s.Stage == "rollback" && s.Result.State != "rolled_back")) {
				attention = true
			}
		}
		if finished {
			p.State = "rolled_back"
			if attention {
				p.State = "needs_attention"
			}
		}
	}
}
func (h *Hub) PairDecision(id, revision, decision string) (PairView, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.closed {
		return PairView{}, errors.New("Controller is stopping")
	}
	next := append([]pair{}, h.pairs...)
	for i := range next {
		p := &next[i]
		if p.ID != id {
			continue
		}
		if p.Revision != revision {
			return PairView{}, problem("revision_conflict", "Refresh this connection before continuing")
		}
		if decision == "confirm" && p.State == "awaiting_confirmation" {
			h.advance(p)
			if p.State != "awaiting_confirmation" {
				return PairView{}, problem("confirmation_expired", "Confirmation expired; recovery is required")
			}
			p.State = "confirming"
			setStage(p, 0, "confirm")
			setStage(p, 1, "confirm")
		} else if decision == "rollback" && p.State != "succeeded" && p.State != "rolled_back" {
			p.State = "rolling_back"
			p.RecoveryUntil = h.now().Add(2 * time.Minute)
			for j, s := range p.Steps {
				setStage(p, j, "rollback")
				if s.Stage == "prepare" && !s.Prepared {
					p.Steps[j].Result = &control.NodeResult{ID: p.ID, Stage: "rollback", State: "rolled_back"}
				}
			}
			h.advance(p)
		} else {
			return PairView{}, problem("invalid_decision", "This action is unavailable in the current state")
		}
		p.Revision = randomID()
		if e := h.savePairs(next); e != nil {
			return PairView{}, e
		}
		return p.view(), nil
	}
	return PairView{}, problem("not_found", "Connection job not found")
}

type workRequest struct {
	Result *control.NodeResult `json:"result,omitempty"`
}
type workReply struct {
	Task *control.NodeTask `json:"task,omitempty"`
}

// Work is called only after mTLS authorization (or by the local worker). Each
// result is persisted before acknowledgment; retries cannot advance twice.
func (h *Hub) work(node string, result *control.NodeResult) (workReply, error) {
	next := append([]pair{}, h.pairs...)
	changed := false
	for i := range next {
		p := &next[i]
		if terminal(*p) {
			continue
		}
		before, _ := json.Marshal(p)
		for j, s := range p.Steps {
			if s.Node == "local" {
				continue
			}
			active := false
			for _, n := range h.state.Nodes {
				if n.ID == s.Node && !n.Revoked && n.Revision == s.NodeRevision {
					active = true
				}
			}
			if !active {
				state := "rolled_back"
				if s.Applied || one(s.Stage, "apply", "confirm") {
					state = "unknown"
				}
				p.Steps[j].Stage = "rollback"
				p.Steps[j].Result = &control.NodeResult{ID: p.ID, Stage: "rollback", State: state, Code: "identity_revoked"}
			}
		}
		for j := range p.Steps {
			s := &p.Steps[j]
			if s.Node == node && result != nil && result.ID == p.ID && result.Stage == s.Stage && s.Result == nil {
				if !one(result.State, "prepared", "applied", "committed", "rolled_back", "failed", "unknown") || len(result.Code) > 64 || (result.Revision != "" && !hashPattern.MatchString(result.Revision)) {
					return workReply{}, problem("invalid_result", "Invalid task result")
				}
				valid := one(result.State, "failed", "unknown", "rolled_back") || (s.Stage == "prepare" && result.State == "prepared" && hashPattern.MatchString(result.Revision)) || (s.Stage == "apply" && one(result.State, "applied", "committed") && result.Deadline != nil) || (s.Stage == "confirm" && result.State == "committed")
				if !valid || (result.Deadline != nil && result.Deadline.After(h.now().Add(6*time.Minute))) {
					return workReply{}, problem("invalid_result", "Task result does not match its stage")
				}
				// Only bounded state metadata is retained, never native command output.
				r := *result
				s.Result = &r
				if r.State == "prepared" {
					s.Prepared = true
					s.PreflightRevision = r.Revision
				}
				if one(r.State, "applied", "committed") {
					s.Applied = true
				}
				if r.Deadline != nil {
					s.Deadline = r.Deadline
				}
			}
		}
		h.advance(p)
		after, _ := json.Marshal(p)
		if string(before) != string(after) {
			p.Revision = randomID()
			changed = true
		}
	}
	if changed {
		if e := h.savePairs(next); e != nil {
			return workReply{}, e
		}
	}
	for _, p := range h.pairs {
		if terminal(p) {
			continue
		}
		for _, s := range p.Steps {
			if s.Node != node || s.Result != nil || (p.State == "awaiting_confirmation") || (s.Stage == "prepare" && p.State != "preparing") {
				continue
			}
			// Revocation or identity replacement also cancels previously queued work.
			authorized := node == "local"
			for _, n := range h.state.Nodes {
				if n.ID == node && !n.Revoked && n.Revision == s.NodeRevision {
					authorized = true
				}
			}
			if !authorized || h.closed {
				return workReply{}, nil
			}
			expires := p.Expires
			if s.Stage == "rollback" {
				expires = h.now().Add(2 * time.Minute)
			}
			rev := "" // Preparation revision survives changing stages.
			if s.Prepared {
				rev = s.PreflightRevision
			}
			return workReply{Task: &control.NodeTask{ID: p.ID, Stage: s.Stage, Expires: expires, Revision: rev, Spec: s.Spec}}, nil
		}
	}
	return workReply{}, nil
}

// RunOperations handles this Controller's local Node through its existing Unix
// broker. Remote Agents pull independently; no network request holds h.mu.
func (h *Hub) RunOperations(ctx context.Context, client control.Client) {
	timer := time.NewTicker(time.Second)
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
		}
		h.mu.Lock()
		work, e := h.work("local", nil)
		h.mu.Unlock()
		if e != nil || work.Task == nil {
			continue
		}
		c, cancel := context.WithTimeout(ctx, 11*time.Minute)
		raw, e := client.Do(c, control.Request{Action: "node-task", NodeTask: work.Task})
		cancel()
		if e != nil {
			continue
		}
		var result control.NodeResult
		if json.Unmarshal(raw, &result) != nil {
			continue
		}
		result.ID = work.Task.ID
		result.Stage = work.Task.Stage
		h.mu.Lock()
		_, _ = h.work("local", &result)
		h.mu.Unlock()
	}
}
