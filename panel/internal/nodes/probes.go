package nodes

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/netip"
	"regexp"
	"time"

	"github.com/Sir-Adnan/GRE-Tunnel-Manager/panel/internal/control"
)

// ProbeProtocol versions the optional far-side sideband. Like traffic
// summaries it never changes capability negotiation; an older Controller
// simply rejects the endpoint.
const ProbeProtocol = 1
const maxProbeBody = 32768

var greUnitID = regexp.MustCompile(`^gre-tun-[0-9]{1,3}$`)

// ProbeSideband is one Agent post: its probe report and, when a speed
// test was requested, the responder's state.
type ProbeSideband struct {
	Protocol  int                 `json:"protocol"`
	Report    control.ProbeReport `json:"report"`
	SpeedTest *SpeedResponder     `json:"speed_test,omitempty"`
}

// SpeedResponder reports the Agent side of a speed test.
type SpeedResponder struct {
	ID    string `json:"id"`
	State string `json:"state"`
	Error string `json:"error,omitempty"`
}

// probeAck may ask the Agent to run a speed-test responder and to report
// again sooner while a test is pending.
type probeAck struct {
	Protocol    int         `json:"protocol"`
	SpeedTest   *SpeedOffer `json:"speed_test,omitempty"`
	NextSeconds int         `json:"next_seconds,omitempty"`
}

// SpeedOffer tells the Agent where to listen: its own inner tunnel address,
// a port and a one-time token, for at most Seconds per direction.
type SpeedOffer struct {
	ID      string `json:"id"`
	Address string `json:"address"`
	Port    int    `json:"port"`
	Token   string `json:"token"`
	Seconds int    `json:"seconds"`
}

func (o SpeedOffer) validate() error {
	a, e := netip.ParseAddr(o.Address)
	if e != nil || !a.Is4() || !a.IsPrivate() || o.Port < 20000 || o.Port > 60999 || !idPattern.MatchString(o.ID) || !hashPattern.MatchString(o.Token) || o.Seconds < 2 || o.Seconds > 10 {
		return errors.New("invalid speed test offer")
	}
	return nil
}

func (s ProbeSideband) validate() error {
	if s.Protocol != ProbeProtocol || len(s.Report.Tunnels) > 32 || s.Report.Time.IsZero() {
		return errors.New("invalid probe report")
	}
	for _, t := range s.Report.Tunnels {
		if !greUnitID.MatchString(t.ID) || len(t.Error) > 64 {
			return errors.New("invalid probe tunnel")
		}
		for _, a := range []string{t.Remote, t.Local, t.Address, t.Peer} {
			if _, e := netip.ParseAddr(a); e != nil {
				return errors.New("invalid probe address")
			}
		}
	}
	if r := s.SpeedTest; r != nil && (!idPattern.MatchString(r.ID) || len(r.Error) > 120 || (r.State != "starting" && r.State != "listening" && r.State != "done" && r.State != "failed")) {
		return errors.New("invalid speed test state")
	}
	return nil
}

type probeObservation struct {
	report control.ProbeReport
	seen   time.Time
}

// ProbeView is a Node's last far-side report.
type ProbeView struct {
	Seen   time.Time           `json:"seen"`
	Report control.ProbeReport `json:"report"`
}

func (h *Hub) serveProbes(w http.ResponseWriter, r *http.Request) {
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
	var in ProbeSideband
	if !nodeDecode(w, r, maxProbeBody, &in) {
		return
	}
	if e = in.validate(); e != nil {
		nodeError(w, 400, problem("invalid_probes", "Invalid bounded probe report"))
		return
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if _, e = h.identify(crt); e != nil {
		nodeError(w, 403, e)
		return
	}
	id := crt.Subject.CommonName
	h.probes[id] = probeObservation{report: in.Report, seen: h.now()}
	nodeReply(w, 200, h.speedAckLocked(id, in.SpeedTest))
}

// Probes returns a Node's last far-side report, if any.
func (h *Hub) probeView(id string) *ProbeView {
	o, ok := h.probes[id]
	if !ok {
		return nil
	}
	return &ProbeView{Seen: o.seen, Report: o.report}
}

// readProbes asks the local read-only broker to probe this side.
func readProbes(ctx context.Context, client control.Client) (control.ProbeReport, error) {
	raw, e := client.Do(ctx, control.Request{Action: "node-probes"})
	var r control.ProbeReport
	if e != nil || len(raw) > maxProbeBody || json.Unmarshal(raw, &r) != nil {
		return control.ProbeReport{}, errors.New("probes unavailable")
	}
	if len(r.Tunnels) > 32 {
		r.Tunnels = r.Tunnels[:32]
	}
	for i := range r.Tunnels {
		if len(r.Tunnels[i].Error) > 64 {
			r.Tunnels[i].Error = r.Tunnels[i].Error[:64]
		}
	}
	return r, nil
}
