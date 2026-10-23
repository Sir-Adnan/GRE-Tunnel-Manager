package nodes

import (
	"context"
	"encoding/json"
	"net/http"
	"time"

	"github.com/Sir-Adnan/GRE-Tunnel-Manager/panel/internal/control"
)

func (h *Hub) serveWork(w http.ResponseWriter, r *http.Request) {
	if len(r.TLS.VerifiedChains) == 0 || len(r.TLS.PeerCertificates) == 0 {
		nodeError(w, 403, problem("identity_required", "A trusted node certificate is required"))
		return
	}
	crt := r.TLS.PeerCertificates[0]
	h.mu.Lock()
	_, e := h.identify(crt)
	h.mu.Unlock()
	if e != nil {
		nodeError(w, 403, e)
		return
	}
	var in workRequest
	if !nodeDecode(w, r, 4096, &in) {
		return
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	i, e := h.identify(crt)
	if e != nil {
		nodeError(w, 403, e)
		return
	}
	id := h.state.Nodes[i].ID
	if !hasOperations(h.cache[id].report.Capabilities) {
		nodeError(w, 403, problem("operations_disabled", "Agent has not advertised paired operations"))
		return
	}
	out, e := h.work(id, in.Result)
	if e != nil {
		nodeError(w, 409, e)
		return
	}
	nodeReply(w, 200, out)
}

// Pull work without opening inbound Agent ports. Lost acknowledgments are safe:
// the same task is redelivered to the root broker's durable receipt.
func (a Agent) pollWork(ctx context.Context, c *http.Client, address string, pending **control.NodeResult) error {
	var out workReply
	if e := post(ctx, c, address+"/v1/work", workRequest{Result: *pending}, &out); e != nil {
		return e
	}
	*pending = nil
	if out.Task == nil {
		return nil
	}
	if out.Task.Spec.Validate() != nil {
		return problem("invalid_task", "Controller sent unsupported work")
	}
	call, cancel := context.WithTimeout(ctx, 11*time.Minute)
	defer cancel()
	raw, e := a.Client.Do(call, control.Request{Action: "node-task", NodeTask: out.Task})
	if e != nil {
		return problem("broker_unavailable", "Local operation broker could not be reached")
	}
	var result control.NodeResult
	if json.Unmarshal(raw, &result) != nil {
		return problem("invalid_result", "Local broker returned an invalid result")
	}
	result.ID = out.Task.ID
	result.Stage = out.Task.Stage
	*pending = &result
	return nil
}
