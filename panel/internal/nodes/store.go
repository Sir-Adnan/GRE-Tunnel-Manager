package nodes

import (
	"crypto/ecdsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"sync"
	"time"

	"github.com/Sir-Adnan/GRE-Tunnel-Manager/panel/internal/config"
)

type ticket struct {
	Hash    string    `json:"hash"`
	Name    string    `json:"name"`
	Expires time.Time `json:"expires"`
}
type state struct {
	Schema      int      `json:"schema"`
	URL         string   `json:"url"`
	Listen      string   `json:"listen"`
	CA          []byte   `json:"ca"`
	Key         []byte   `json:"key"`
	Certificate []byte   `json:"certificate"`
	ServerKey   []byte   `json:"server_key"`
	Nodes       []Node   `json:"nodes"`
	Tickets     []ticket `json:"tickets"`
}
type observation struct {
	report    Report
	seen      time.Time
	observed  *time.Time
	inventory json.RawMessage
	revision  string
}
type Hub struct {
	mu     sync.Mutex
	path   string
	state  state
	cache  map[string]observation
	gate   chan struct{}
	now    func() time.Time
	lock   *os.File
	closed bool
}
type Invitation struct {
	Code    string    `json:"code"`
	Expires time.Time `json:"expires"`
}
type bootstrap struct {
	URL   string `json:"url"`
	Pin   string `json:"pin"`
	Token string `json:"token"`
}

var hashPattern = regexp.MustCompile(`^[a-f0-9]{64}$`)

func (s state) validate() error {
	if s.Schema != 1 || !validURL(s.URL) || len(s.Nodes) > 64 || len(s.Tickets) > 16 {
		return errors.New("invalid controller state")
	}
	h, p, e := net.SplitHostPort(s.Listen)
	if e != nil || net.ParseIP(h) == nil {
		return errors.New("invalid control listen address")
	}
	port, e := strconv.Atoi(p)
	if e != nil || port < 1 || port > 65535 {
		return errors.New("invalid control port")
	}
	seen := map[string]bool{}
	for _, n := range s.Nodes {
		if !idPattern.MatchString(n.ID) || !idPattern.MatchString(n.Revision) || !validName(n.Name) || n.Created.IsZero() || seen[n.ID] || len(n.Serials) < 1 || len(n.Serials) > 2 {
			return errors.New("invalid node registry")
		}
		seen[n.ID] = true
		for _, serial := range n.Serials {
			if len(serial) > 39 {
				return errors.New("invalid node serial")
			}
			v, ok := new(big.Int).SetString(serial, 10)
			if !ok || v.Sign() <= 0 || v.String() != serial {
				return errors.New("invalid node serial")
			}
		}
	}
	seen = map[string]bool{}
	for _, ticket := range s.Tickets {
		if !hashPattern.MatchString(ticket.Hash) || !validName(ticket.Name) || ticket.Expires.IsZero() || seen[ticket.Hash] {
			return errors.New("invalid enrollment registry")
		}
		seen[ticket.Hash] = true
	}
	return nil
}

func writeJSON(path string, value any, exclusive bool) error {
	b, e := json.MarshalIndent(value, "", "  ")
	if e != nil {
		return e
	}
	if exclusive {
		f, e := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if e != nil {
			return e
		}
		if _, e = f.Write(b); e == nil {
			e = f.Sync()
		}
		closeErr := f.Close()
		if e == nil {
			e = closeErr
		}
		if e != nil {
			os.Remove(path)
		}
		return e
	}
	f, e := os.CreateTemp(filepath.Dir(path), ".nodes-*")
	if e != nil {
		return e
	}
	defer os.Remove(f.Name())
	if e = f.Chmod(0600); e == nil {
		_, e = f.Write(b)
	}
	if e == nil {
		e = f.Sync()
	}
	closeErr := f.Close()
	if e == nil {
		e = closeErr
	}
	if e != nil {
		return e
	}
	return os.Rename(f.Name(), path)
}
func readJSON(path string, out any) error {
	f, e := os.Open(path)
	if e != nil {
		return e
	}
	defer f.Close()
	info, e := f.Stat()
	if e != nil {
		return e
	}
	if !info.Mode().IsRegular() || info.Size() > 1048576 {
		return errors.New("identity file must be regular and at most 1 MiB")
	}
	d := json.NewDecoder(io.LimitReader(f, 1048577))
	d.DisallowUnknownFields()
	if e = d.Decode(out); e != nil {
		return e
	}
	var extra any
	if d.Decode(&extra) != io.EOF {
		return errors.New("one identity object required")
	}
	return nil
}
func validURL(raw string) bool {
	u, e := url.Parse(raw)
	if e != nil || u.Scheme != "https" || u.User != nil || u.Path != "" || u.RawQuery != "" || u.Fragment != "" || !config.ValidHost(u.Hostname()) {
		return false
	}
	p, e := strconv.Atoi(u.Port())
	return e == nil && p >= 1 && p <= 65535
}

// Init exclusively creates an optional control plane. The caller must arrange
// ownership for the unprivileged panel service; it never changes tunnel state.
func Init(dir, address, listen string) error {
	if !filepath.IsAbs(dir) || !validURL(address) {
		return errors.New("absolute directory and https://IP_OR_DOMAIN:PORT are required")
	}
	h, p, e := net.SplitHostPort(listen)
	if e != nil || net.ParseIP(h) == nil {
		return errors.New("explicit local listen IP:port required")
	}
	n, e := strconv.Atoi(p)
	if e != nil || n < 1 || n > 65535 {
		return errors.New("invalid control port")
	}
	u, _ := url.Parse(address)
	ca, key, e := newAuthority()
	if e != nil {
		return e
	}
	sk, serverKey, e := newKey()
	if e != nil {
		return e
	}
	csr, e := makeCSR(sk)
	if e != nil {
		return e
	}
	crt, _, e := sign(ca, key, csr, "controller", u.Hostname())
	if e != nil {
		return e
	}
	if e = os.MkdirAll(dir, 0700); e != nil {
		return e
	}
	return writeJSON(filepath.Join(dir, "controller.json"), state{Schema: 1, URL: address, Listen: listen, CA: ca, Key: key, Certificate: crt, ServerKey: serverKey, Nodes: []Node{}, Tickets: []ticket{}}, true)
}
func Open(dir string) (*Hub, error) {
	h := &Hub{path: filepath.Join(dir, "controller.json"), cache: map[string]observation{}, gate: make(chan struct{}, 8), now: time.Now}
	f, e := os.OpenFile(filepath.Join(dir, "controller.lock"), os.O_CREATE|os.O_RDWR, 0600)
	if e != nil {
		return nil, e
	}
	if e = lockFile(f); e != nil {
		f.Close()
		return nil, errors.New("Controller state is already in use")
	}
	h.lock = f
	valid := false
	defer func() {
		if !valid {
			h.Close()
		}
	}()
	if e := readJSON(h.path, &h.state); e != nil {
		return nil, e
	}
	if e := h.state.validate(); e != nil {
		return nil, e
	}
	if _, e := h.TLSConfig(); e != nil {
		return nil, e
	}
	valid = true
	return h, nil
}

// CheckController validates existing state without acquiring the live process
// lease. Installers use it as the service account before restarting a panel.
func CheckController(dir string) error {
	h := &Hub{}
	if e := readJSON(filepath.Join(dir, "controller.json"), &h.state); e != nil {
		return e
	}
	if e := h.state.validate(); e != nil {
		return e
	}
	_, e := h.TLSConfig()
	return e
}
func (h *Hub) Close() error {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.closed = true
	if h.lock != nil {
		e := h.lock.Close()
		h.lock = nil
		return e
	}
	return nil
}
func (h *Hub) TLSConfig() (*tls.Config, error) {
	cert, e := tls.X509KeyPair(append(append([]byte{}, h.state.Certificate...), h.state.CA...), h.state.ServerKey)
	if e != nil {
		return nil, e
	}
	ca, e := parseCert(h.state.CA)
	if e != nil {
		return nil, e
	}
	if !ca.IsCA || ca.CheckSignatureFrom(ca) != nil || !ca.NotAfter.After(time.Now()) {
		return nil, errors.New("invalid or expired Controller authority")
	}
	if _, e = tls.X509KeyPair(h.state.CA, h.state.Key); e != nil {
		return nil, e
	}
	leaf, e := x509.ParseCertificate(cert.Certificate[0])
	if e != nil {
		return nil, e
	}
	u, _ := url.Parse(h.state.URL)
	if leaf.CheckSignatureFrom(ca) != nil || leaf.VerifyHostname(u.Hostname()) != nil {
		return nil, errors.New("Controller certificate does not match authority or endpoint")
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(h.state.CA) {
		return nil, errors.New("invalid node authority")
	}
	return &tls.Config{MinVersion: tls.VersionTLS13, GetCertificate: h.serverCertificate, ClientCAs: pool, ClientAuth: tls.VerifyClientCertIfGiven}, nil
}
func (h *Hub) serverCertificate(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.closed {
		return nil, errors.New("Controller is stopping")
	}
	leaf, e := parseCert(h.state.Certificate)
	if e != nil {
		return nil, e
	}
	if time.Until(leaf.NotAfter) < 30*24*time.Hour {
		block, _ := pem.Decode(h.state.ServerKey)
		if block == nil {
			return nil, errors.New("invalid controller key")
		}
		key, e := x509.ParsePKCS8PrivateKey(block.Bytes)
		if e != nil {
			return nil, e
		}
		ec, ok := key.(*ecdsa.PrivateKey)
		if !ok {
			return nil, errors.New("invalid controller key")
		}
		csr, e := makeCSR(ec)
		if e != nil {
			return nil, e
		}
		u, _ := url.Parse(h.state.URL)
		crt, _, e := sign(h.state.CA, h.state.Key, csr, "controller", u.Hostname())
		if e != nil {
			return nil, e
		}
		next := h.state
		next.Certificate = crt
		if e = writeJSON(h.path, next, false); e != nil {
			return nil, e
		}
		h.state = next
	}
	cert, e := tls.X509KeyPair(append(append([]byte{}, h.state.Certificate...), h.state.CA...), h.state.ServerKey)
	return &cert, e
}
func (h *Hub) ListenAddress() string { return h.state.Listen }
func (h *Hub) Invite(name string) (Invitation, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.closed {
		return Invitation{}, errors.New("Controller is stopping")
	}
	if !validName(name) {
		return Invitation{}, problem("invalid_name", "Use a node name with 1–64 visible characters")
	}
	if len(h.state.Nodes) >= 64 {
		return Invitation{}, problem("capacity", "Controller limit is 64 enrolled nodes, including revoked identities")
	}
	next := h.state
	next.Tickets = nil
	for _, t := range h.state.Tickets {
		if t.Expires.After(h.now()) {
			next.Tickets = append(next.Tickets, t)
		}
	}
	if len(next.Tickets) >= 16 {
		return Invitation{}, problem("capacity", "At most 16 active enrollment invitations are allowed")
	}
	token := randomID() + randomID()
	expires := h.now().Add(10 * time.Minute)
	next.Tickets = append(next.Tickets, ticket{digest([]byte(token)), name, expires})
	if e := writeJSON(h.path, next, false); e != nil {
		return Invitation{}, e
	}
	h.state = next
	ca, _ := parseCert(h.state.CA)
	b, _ := json.Marshal(bootstrap{h.state.URL, digest(ca.Raw), token})
	return Invitation{base64.RawURLEncoding.EncodeToString(b), expires}, nil
}
func (h *Hub) Revoke(id, revision string) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.closed {
		return errors.New("Controller is stopping")
	}
	next := h.state
	next.Nodes = append([]Node{}, h.state.Nodes...)
	for i, n := range next.Nodes {
		if n.ID == id {
			if n.Revision != revision {
				return problem("revision_conflict", "Refresh nodes before revoking this identity")
			}
			n.Revoked = true
			n.Revision = randomID()
			next.Nodes[i] = n
			if e := writeJSON(h.path, next, false); e != nil {
				return e
			}
			h.state = next
			return nil
		}
	}
	return problem("not_found", "Node not found")
}
func (h *Hub) Views() Listing {
	h.mu.Lock()
	defer h.mu.Unlock()
	out := Listing{Enabled: true, URL: h.state.URL, Protocol: Protocol, Nodes: []View{}}
	for _, n := range h.state.Nodes {
		v := View{ID: n.ID, Name: n.Name, Revision: n.Revision, Status: "waiting", Protocol: Protocol, Capabilities: []string{}}
		if o, ok := h.cache[n.ID]; ok {
			seen := o.seen
			v.LastSeen = &seen
			v.Observed = o.observed
			v.Version = o.report.Version
			v.Protocol = o.report.Protocol
			v.Capabilities = o.report.Capabilities
			v.Failure = o.report.Failure
			v.Inventory = append(json.RawMessage{}, o.inventory...)
			v.InventoryRevision = o.revision
			v.Status = "online"
			if o.report.Failure != nil {
				v.Status = "degraded"
			}
			if h.now().Sub(o.seen) > 3*time.Minute {
				v.Status = "offline"
			}
		}
		if n.Revoked {
			v.Status = "revoked"
		}
		out.Nodes = append(out.Nodes, v)
	}
	return out
}
