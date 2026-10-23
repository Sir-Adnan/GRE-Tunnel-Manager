package nodes

import (
	"errors"
	"os"
	"path/filepath"
	"time"
)

func (h *Hub) pairPath() string { return filepath.Join(filepath.Dir(h.path), "pairs.json") }
func (h *Hub) savePairs(next []pair) error {
	if e := writeJSON(h.pairPath(), next, false); e != nil {
		return e
	}
	h.pairs = next
	return nil
}
func (h *Hub) loadPairs() error {
	var saved []pair
	if e := readJSON(h.pairPath(), &saved); os.IsNotExist(e) {
		return nil
	} else if e != nil {
		return e
	}
	if len(saved) > 32 {
		return errors.New("pair job capacity exceeded")
	}
	seen := map[string]bool{}
	for _, p := range saved {
		if p.Schema != 1 || !idPattern.MatchString(p.ID) || !idPattern.MatchString(p.Revision) || !hashPattern.MatchString(p.InputHash) || !validName(p.Name) || seen[p.ID] || p.Expires.Sub(p.Created) != 10*time.Minute || !one(p.State, "preparing", "applying", "awaiting_confirmation", "confirming", "rolling_back", "succeeded", "rolled_back", "needs_attention") {
			return errors.New("invalid pair journal")
		}
		seen[p.ID] = true
		for _, s := range p.Steps {
			if (s.Node != "local" && !idPattern.MatchString(s.Node)) || s.Spec.Validate() != nil || !one(s.Stage, "prepare", "apply", "confirm", "rollback") {
				return errors.New("invalid pair step")
			}
			if (s.Node == "local" && s.NodeRevision != "") || (s.Node != "local" && !idPattern.MatchString(s.NodeRevision)) || (s.Prepared && !hashPattern.MatchString(s.PreflightRevision)) || (s.Applied && s.Deadline == nil) {
				return errors.New("invalid pair step revision or lease")
			}
		}
	}
	h.pairs = saved
	return nil
}
