package control

import (
	"context"
	"errors"
	"strings"
	"testing"
)

type retireRunner struct {
	inventory string
	failAt    int
	calls     []string
}

func (r *retireRunner) Run(_ context.Context, name string, args []string, input string) (string, error) {
	r.calls = append(r.calls, name+" "+strings.Join(args, " ")+"\n"+input)
	if len(r.calls) == r.failAt {
		return "private native error", errors.New("failure")
	}
	return r.inventory, nil
}
func TestRetireMetricsIsScopedAndFailsClosed(t *testing.T) {
	for _, inventory := range []string{`{"nftables":[]}`, `{"nftables":[{"table":{"family":"inet","name":"gre_manager"}},{"table":{"family":"ip","name":"gtm_panel_metrics"}}]}`} {
		r := &retireRunner{inventory: inventory}
		if e := RetireMetrics(context.Background(), r); e != nil || len(r.calls) != 1 {
			t.Fatal(e, r.calls)
		}
	}
	for failAt := 0; failAt <= 3; failAt++ {
		r := &retireRunner{inventory: `{"nftables":[{"table":{"family":"inet","name":"gtm_panel_metrics"}}]}`, failAt: failAt}
		e := RetireMetrics(context.Background(), r)
		if (e == nil) != (failAt == 0) {
			t.Fatal(e, r.calls)
		}
		if e != nil && strings.Contains(e.Error(), "private native error") {
			t.Fatal("native output leaked")
		}
		for _, call := range r.calls[1:] {
			if !strings.HasSuffix(call, "delete table inet gtm_panel_metrics\n") {
				t.Fatal(call)
			}
		}
	}
	r := &retireRunner{inventory: `{broken`}
	if RetireMetrics(context.Background(), r) == nil || len(r.calls) != 1 {
		t.Fatal("invalid inventory accepted")
	}
}
