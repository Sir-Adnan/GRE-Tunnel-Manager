package nodes

import "testing"

func TestRetirementRequiresResolvedPairs(t *testing.T) {
	for _, state := range []string{"preparing", "applying", "awaiting_confirmation", "confirming", "rolling_back", "needs_attention", "succeeded", "rolled_back"} {
		h := &Hub{pairs: []pair{{State: state}}}
		want := state == "succeeded" || state == "rolled_back"
		if (h.CheckRetirement() == nil) != want {
			t.Fatal(state)
		}
	}
}
