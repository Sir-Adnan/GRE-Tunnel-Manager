package nodes

import "errors"

// Unresolved outcomes remain protected even after authorization expires.
func (h *Hub) CheckRetirement() error {
	h.mu.Lock()
	defer h.mu.Unlock()
	for _, p := range h.pairs {
		if p.State != "succeeded" && p.State != "rolled_back" {
			return errors.New("paired operations need completion or recovery before Controller removal")
		}
	}
	return nil
}
