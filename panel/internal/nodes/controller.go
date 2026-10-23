package nodes

import (
	"crypto/x509"
	"encoding/json"
	"io"
	"net/http"
	"time"
)

type enrollRequest struct {
	Protocol int    `json:"protocol"`
	Token    string `json:"token"`
	CSR      []byte `json:"csr"`
}
type identity struct {
	Schema      int    `json:"schema"`
	Protocol    int    `json:"protocol"`
	ID          string `json:"id"`
	URL         string `json:"url"`
	CA          []byte `json:"ca"`
	Certificate []byte `json:"certificate"`
	Key         []byte `json:"key,omitempty"`
}
type rotateRequest struct {
	CSR []byte `json:"csr"`
}

func nodeReply(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(value)
}
func nodeError(w http.ResponseWriter, status int, e error) {
	p, ok := e.(*Problem)
	if !ok {
		p = &Problem{"internal_error", "Controller could not save this change"}
	}
	nodeReply(w, status, p)
}
func nodeDecode(w http.ResponseWriter, r *http.Request, max int64, out any) bool {
	r.Body = http.MaxBytesReader(w, r.Body, max)
	d := json.NewDecoder(r.Body)
	d.DisallowUnknownFields()
	if d.Decode(out) != nil {
		nodeError(w, 400, problem("invalid_request", "Invalid request"))
		return false
	}
	var extra any
	if d.Decode(&extra) != io.EOF {
		nodeError(w, 400, problem("invalid_request", "One request required"))
		return false
	}
	return true
}
func (h *Hub) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		nodeError(w, 405, problem("method_not_allowed", "POST required"))
		return
	}
	select {
	case h.gate <- struct{}{}:
		defer func() { <-h.gate }()
	default:
		nodeError(w, 503, problem("busy", "Controller is busy"))
		return
	}
	if r.TLS == nil {
		nodeError(w, 403, problem("tls_required", "Encrypted agent transport is required"))
		return
	}
	if r.URL.Path == "/v1/enroll" {
		h.enroll(w, r)
		return
	}
	if r.URL.Path == "/v1/work" {
		h.serveWork(w, r)
		return
	}
	if r.URL.Path != "/v1/report" && r.URL.Path != "/v1/rotate" {
		nodeError(w, 404, problem("not_found", "Unknown node endpoint"))
		return
	}
	if len(r.TLS.VerifiedChains) == 0 || len(r.TLS.PeerCertificates) == 0 {
		nodeError(w, 403, problem("identity_required", "A trusted node certificate is required"))
		return
	}
	crt := r.TLS.PeerCertificates[0]
	h.mu.Lock()
	index, identityError := h.identify(crt)
	h.mu.Unlock()
	if identityError != nil {
		nodeError(w, 403, identityError)
		return
	}
	// Never hold the registry mutex while reading a network body. Reauthorize
	// after decoding so revocation can commit while a slow report is in flight.
	var report Report
	var rotation rotateRequest
	var inventory json.RawMessage
	if r.URL.Path == "/v1/rotate" {
		if !nodeDecode(w, r, 8192, &rotation) {
			return
		}
	} else {
		if !nodeDecode(w, r, MaxInventory+8192, &report) {
			return
		}
		if e := validateReport(report); e != nil {
			nodeError(w, 409, e)
			return
		}
		if report.Failure == nil {
			var e error
			inventory, e = canonicalInventory(report.Inventory)
			if e != nil {
				nodeError(w, 400, problem("invalid_report", "Invalid inventory"))
				return
			}
		}
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	index, identityError = h.identify(crt)
	if identityError != nil {
		nodeError(w, 403, identityError)
		return
	}
	if r.URL.Path == "/v1/rotate" {
		cert, s, e := sign(h.state.CA, h.state.Key, rotation.CSR, h.state.Nodes[index].ID, "")
		if e != nil {
			nodeError(w, 400, problem("invalid_csr", "Invalid P-256 certificate request"))
			return
		}
		next := h.state
		next.Nodes = append([]Node{}, h.state.Nodes...)
		n := next.Nodes[index]
		n.Serials = []string{crt.SerialNumber.String(), s}
		next.Nodes[index] = n
		if e = writeJSON(h.path, next, false); e != nil {
			nodeError(w, 500, e)
			return
		}
		h.state = next
		nodeReply(w, 200, map[string]any{"certificate": cert})
		return
	}
	id := h.state.Nodes[index].ID
	previous := h.cache[id]
	report.Inventory = nil // Retain only the canonical snapshot, never a second raw copy.
	o := observation{report: report, seen: h.now(), inventory: previous.inventory, observed: previous.observed, revision: previous.revision}
	if report.Failure == nil {
		o.inventory = inventory
		o.revision = digest(inventory)
		observed := o.seen
		o.observed = &observed
	}
	h.cache[id] = o
	nodeReply(w, 200, map[string]any{"protocol": Protocol, "capabilities": report.Capabilities, "interval_seconds": 60})
}

// TLS verifies certificates at handshake time. Recheck their lifetime for every
// request too, so a reused connection cannot outlive its credential.
func (h *Hub) identify(crt *x509.Certificate) (int, error) {
	if h.now().Before(crt.NotBefore) || !h.now().Before(crt.NotAfter) {
		return -1, problem("identity_expired", "Node certificate is expired or not yet valid")
	}
	i := h.activeIdentity(crt.Subject.CommonName, crt.SerialNumber.String())
	if i < 0 {
		return -1, problem("identity_revoked", "Node identity is unknown, revoked or stopping")
	}
	return i, nil
}

// activeIdentity requires h.mu. Certificate proof is checked by TLS and the
// request handler; this registry check also runs on reused TLS connections.
func (h *Hub) activeIdentity(id, serial string) int {
	if h.closed {
		return -1
	}
	for i, n := range h.state.Nodes {
		if n.ID == id && !n.Revoked {
			for _, s := range n.Serials {
				if s == serial {
					return i
				}
			}
		}
	}
	return -1
}

func (h *Hub) enroll(w http.ResponseWriter, r *http.Request) {
	var input enrollRequest
	if !nodeDecode(w, r, 8192, &input) {
		return
	}
	if input.Protocol != Protocol {
		nodeError(w, 409, problem("incompatible_protocol", "Agent protocol is incompatible"))
		return
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.closed {
		nodeError(w, 503, problem("stopping", "Controller is stopping"))
		return
	}
	index := -1
	for i, t := range h.state.Tickets {
		if t.Hash == digest([]byte(input.Token)) && t.Expires.After(h.now()) {
			index = i
		}
	}
	if index < 0 {
		nodeError(w, 403, problem("invalid_invitation", "Invitation expired or already used"))
		return
	}
	if len(h.state.Nodes) >= 64 {
		nodeError(w, 409, problem("capacity", "Node capacity reached"))
		return
	}
	id := randomID()
	cert, s, e := sign(h.state.CA, h.state.Key, input.CSR, id, "")
	if e != nil {
		nodeError(w, 400, problem("invalid_csr", "Invalid P-256 certificate request"))
		return
	}
	next := h.state
	next.Nodes = append(append([]Node{}, h.state.Nodes...), Node{ID: id, Name: h.state.Tickets[index].Name, Revision: randomID(), Serials: []string{s}, Created: h.now()})
	next.Tickets = nil
	for i, t := range h.state.Tickets {
		if i != index && t.Expires.After(h.now()) {
			next.Tickets = append(next.Tickets, t)
		}
	}
	if e = writeJSON(h.path, next, false); e != nil {
		nodeError(w, 500, e)
		return
	}
	h.state = next
	nodeReply(w, 200, identity{Schema: 1, Protocol: Protocol, ID: id, URL: h.state.URL, CA: h.state.CA, Certificate: cert})
}

// Server has a distinct TLS-only listener. Browser HTTP never weakens it.
func (h *Hub) Server() (*http.Server, error) {
	tlsConfig, e := h.TLSConfig()
	if e != nil {
		return nil, e
	}
	return &http.Server{Addr: h.ListenAddress(), Handler: h, TLSConfig: tlsConfig, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 15 * time.Second, WriteTimeout: 15 * time.Second, IdleTimeout: 60 * time.Second, MaxHeaderBytes: 8192}, nil
}
