package nodes

import (
	"time"

	"github.com/Sir-Adnan/GRE-Tunnel-Manager/panel/internal/control"
)

type NodeChoice struct {
	ID       string `json:"id"`
	Revision string `json:"revision"`
	Address  string `json:"address"`
}
type PairRequest struct {
	ID          string     `json:"id"`
	Name        string     `json:"name"`
	Kind        string     `json:"kind"`
	Entrance    NodeChoice `json:"entrance"`
	Destination NodeChoice `json:"destination"`
	GREID       int        `json:"gre_id"`
	MTU         int        `json:"mtu"`
	ControlPort int        `json:"control_port"`
	PublicPort  int        `json:"public_port"`
	LocalIP     string     `json:"local_ip"`
	LocalPort   int        `json:"local_port"`
	Protocol    string     `json:"protocol"`
	Transport   string     `json:"transport"`
}
type pairStep struct {
	Node              string              `json:"node"`
	NodeRevision      string              `json:"node_revision"`
	Spec              control.NodeSpec    `json:"spec"`
	Stage             string              `json:"stage"`
	Result            *control.NodeResult `json:"result,omitempty"`
	Prepared          bool                `json:"prepared"`
	Applied           bool                `json:"applied"`
	PreflightRevision string              `json:"preflight_revision"`
	Deadline          *time.Time          `json:"deadline,omitempty"`
}
type pair struct {
	Schema        int         `json:"schema"`
	ID            string      `json:"id"`
	Name          string      `json:"name"`
	Kind          string      `json:"kind"`
	InputHash     string      `json:"input_hash"`
	Revision      string      `json:"revision"`
	State         string      `json:"state"`
	Created       time.Time   `json:"created"`
	Expires       time.Time   `json:"expires"`
	RecoveryUntil time.Time   `json:"recovery_until,omitempty"`
	Steps         [2]pairStep `json:"steps"`
}
type PairStepView struct {
	Node     string              `json:"node"`
	Service  string              `json:"service"`
	Stage    string              `json:"stage"`
	Result   *control.NodeResult `json:"result,omitempty"`
	Deadline *time.Time          `json:"deadline,omitempty"`
}
type PairView struct {
	ID       string          `json:"id"`
	Name     string          `json:"name"`
	Kind     string          `json:"kind"`
	Revision string          `json:"revision"`
	State    string          `json:"state"`
	Created  time.Time       `json:"created"`
	Expires  time.Time       `json:"expires"`
	Steps    [2]PairStepView `json:"steps"`
}

func (p pair) view() PairView {
	v := PairView{ID: p.ID, Name: p.Name, Kind: p.Kind, Revision: p.Revision, State: p.State, Created: p.Created, Expires: p.Expires}
	for i, s := range p.Steps {
		deadline := s.Deadline
		if deadline != nil && p.Expires.Before(*deadline) {
			limit := p.Expires
			deadline = &limit
		}
		v.Steps[i] = PairStepView{Node: s.Node, Service: s.Spec.Service(), Stage: s.Stage, Result: s.Result, Deadline: deadline}
	}
	return v
}
func one(s string, values ...string) bool {
	for _, v := range values {
		if s == v {
			return true
		}
	}
	return false
}
func terminal(p pair) bool { return one(p.State, "succeeded", "rolled_back", "needs_attention") }
