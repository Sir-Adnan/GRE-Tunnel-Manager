package nodes

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"time"

	"github.com/Sir-Adnan/GRE-Tunnel-Manager/panel/internal/control"
)

func transport(c *tls.Config) *http.Client {
	return &http.Client{Transport: &http.Transport{TLSClientConfig: c, MaxIdleConns: 1, MaxConnsPerHost: 1, IdleConnTimeout: 90 * time.Second}, Timeout: 20 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("agent redirects are refused") }}
}
func post(ctx context.Context, c *http.Client, address string, in, out any) error {
	b, e := json.Marshal(in)
	if e != nil {
		return e
	}
	req, e := http.NewRequestWithContext(ctx, "POST", address, bytes.NewReader(b))
	if e != nil {
		return e
	}
	req.Header.Set("Content-Type", "application/json")
	res, e := c.Do(req)
	if e != nil {
		return problem("connection_failed", "Cannot reach the trusted Controller")
	}
	defer res.Body.Close()
	b, e = io.ReadAll(io.LimitReader(res.Body, 65537))
	if e != nil || len(b) > 65536 {
		return problem("invalid_response", "Controller response exceeded the limit")
	}
	if res.StatusCode != 200 {
		var p Problem
		if json.Unmarshal(b, &p) == nil && p.Code != "" {
			return &p
		}
		return problem("controller_error", "Controller rejected the request")
	}
	return json.Unmarshal(b, out)
}

// Enroll pins the authority from an out-of-band invitation before sending its
// one-time secret. No trust-on-first-use, arbitrary CA store, or redirect follows.
func Enroll(ctx context.Context, path, code string) error {
	if !filepath.IsAbs(path) {
		return errors.New("absolute identity path required")
	}
	if _, e := os.Lstat(path); !os.IsNotExist(e) {
		return errors.New("agent identity already exists or cannot be inspected")
	}
	if len(code) > 4096 {
		return errors.New("invalid invitation")
	}
	raw, e := base64.RawURLEncoding.DecodeString(code)
	if e != nil {
		return errors.New("invalid invitation")
	}
	var b bootstrap
	if json.Unmarshal(raw, &b) != nil || !validURL(b.URL) || len(b.Pin) != 64 || len(b.Token) != 64 {
		return errors.New("invalid invitation")
	}
	u, _ := url.Parse(b.URL)
	tc := &tls.Config{MinVersion: tls.VersionTLS13, InsecureSkipVerify: true, VerifyConnection: func(s tls.ConnectionState) error {
		if len(s.PeerCertificates) < 2 {
			return errors.New("controller authority missing")
		}
		ca := s.PeerCertificates[len(s.PeerCertificates)-1]
		if digest(ca.Raw) != b.Pin {
			return errors.New("controller authority pin mismatch")
		}
		pool := x509.NewCertPool()
		pool.AddCert(ca)
		inter := x509.NewCertPool()
		for _, crt := range s.PeerCertificates[1 : len(s.PeerCertificates)-1] {
			inter.AddCert(crt)
		}
		_, e := s.PeerCertificates[0].Verify(x509.VerifyOptions{Roots: pool, Intermediates: inter, DNSName: u.Hostname(), KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}})
		return e
	}}
	k, key, e := newKey()
	if e != nil {
		return e
	}
	csr, e := makeCSR(k)
	if e != nil {
		return e
	}
	c := transport(tc)
	defer c.CloseIdleConnections()
	var id identity
	if e = post(ctx, c, b.URL+"/v1/enroll", enrollRequest{Protocol, b.Token, csr}, &id); e != nil {
		return e
	}
	id.Key = key
	if id.URL != b.URL || digestCert(id.CA) != b.Pin {
		return errors.New("enrollment identity mismatch")
	}
	if _, e = agentTLS(id); e != nil {
		return e
	}
	if e = os.MkdirAll(filepath.Dir(path), 0700); e != nil {
		return e
	}
	return writeJSON(path, id, true)
}
func digestCert(b []byte) string {
	crt, e := parseCert(b)
	if e != nil {
		return ""
	}
	return digest(crt.Raw)
}
func agentTLS(id identity) (*tls.Config, error) {
	if id.Schema != 1 || id.Protocol != Protocol || !idPattern.MatchString(id.ID) || !validURL(id.URL) {
		return nil, errors.New("invalid agent identity or protocol")
	}
	cert, e := tls.X509KeyPair(id.Certificate, id.Key)
	if e != nil {
		return nil, e
	}
	leaf, e := parseCert(id.Certificate)
	if e != nil || leaf.Subject.CommonName != id.ID {
		return nil, errors.New("agent certificate identity mismatch")
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(id.CA) {
		return nil, errors.New("invalid agent authority")
	}
	if _, e = leaf.Verify(x509.VerifyOptions{Roots: pool, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}); e != nil {
		return nil, e
	}
	return &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: pool, Certificates: []tls.Certificate{cert}}, nil
}

type Agent struct {
	Path       string
	Version    string
	Client     control.Client
	Notify     func(string)
	Operations bool
	Traffic    bool
}

func CheckIdentity(path string) error {
	var id identity
	if e := readJSON(path, &id); e != nil {
		return e
	}
	_, e := agentTLS(id)
	return e
}

func (a Agent) Run(ctx context.Context) error {
	lock, e := os.OpenFile(filepath.Join(filepath.Dir(a.Path), "agent.lock"), os.O_CREATE|os.O_RDWR, 0600)
	if e != nil {
		return e
	}
	defer lock.Close()
	if e = lockFile(lock); e != nil {
		return errors.New("Agent identity is already in use")
	}
	var id identity
	if e := readJSON(a.Path, &id); e != nil {
		return e
	}
	tc, e := agentTLS(id)
	if e != nil {
		return e
	}
	c := transport(tc)
	defer func() { c.CloseIdleConnections() }()
	delay := time.Duration(0)
	failures := 0
	lastCode := ""
	trafficCode := ""
	var pending *control.NodeResult
	nextReport := time.Time{}
	for {
		if delay > 0 {
			timer := time.NewTimer(delay)
			select {
			case <-ctx.Done():
				timer.Stop()
				return nil
			case <-timer.C:
			}
		}
		if ctx.Err() != nil {
			return nil
		}
		leaf, _ := parseCert(id.Certificate)
		if time.Until(leaf.NotAfter) < 7*24*time.Hour {
			block, _ := pem.Decode(id.Key)
			k, e := x509.ParsePKCS8PrivateKey(block.Bytes)
			if e != nil {
				return e
			}
			ec, ok := k.(*ecdsa.PrivateKey)
			if !ok {
				return errors.New("invalid agent key")
			}
			csr, e := makeCSR(ec)
			if e != nil {
				return e
			}
			var rotated struct {
				Certificate []byte `json:"certificate"`
			}
			e = post(ctx, c, id.URL+"/v1/rotate", rotateRequest{csr}, &rotated)
			if e == nil {
				next := id
				next.Certificate = rotated.Certificate
				var updated *tls.Config
				updated, e = agentTLS(next)
				if e == nil {
					e = writeJSON(a.Path, next, false)
				}
				if e == nil {
					c.CloseIdleConnections()
					c = transport(updated)
					id = next
				}
			}
			if e != nil {
				if fatal(e) {
					return e
				}
				delay = backoff(failures)
				failures++
				continue
			}
		}
		if a.Operations && time.Now().Before(nextReport) {
			e = a.pollWork(ctx, c, id.URL, &pending)
			if e != nil {
				if fatal(e) {
					return e
				}
				code := "work_unavailable"
				if p, ok := e.(*Problem); ok {
					code = p.Code
				}
				if code != lastCode && a.Notify != nil {
					a.Notify(code)
				}
				lastCode = code
				delay = backoff(failures)
				failures++
			} else {
				if lastCode != "" && a.Notify != nil {
					a.Notify("connected")
				}
				lastCode = ""
				delay = 5*time.Second + jitter(time.Second)
				failures = 0
			}
			continue
		}
		readCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
		raw, readErr := a.Client.Do(readCtx, control.Request{Action: "inventory"})
		cancel()
		r := Report{Protocol: Protocol, Version: a.Version, Capabilities: capabilities}
		if a.Operations {
			r.Capabilities = []string{"inventory.read", control.NodeOperationCapability}
		}
		if readErr != nil || len(raw) > MaxInventory {
			r.Failure = &Problem{"inventory_unavailable", "Local inventory could not be read"}
		} else {
			r.Inventory, readErr = canonicalInventory(raw)
			if readErr != nil {
				r.Inventory = nil
				r.Failure = &Problem{"inventory_unavailable", "Local inventory could not be read"}
			}
		}
		var ack struct {
			Protocol     int      `json:"protocol"`
			Capabilities []string `json:"capabilities"`
			Interval     int      `json:"interval_seconds"`
		}
		e = post(ctx, c, id.URL+"/v1/report", r, &ack)
		matched := len(ack.Capabilities) == 1 && ack.Capabilities[0] == "inventory.read"
		if a.Operations {
			matched = hasOperations(ack.Capabilities)
		}
		if e == nil && (ack.Protocol != Protocol || !matched) {
			e = problem("incompatible_protocol", "Controller protocol is incompatible")
		}
		if e != nil {
			if fatal(e) {
				return e
			}
			code := "connection_failed"
			if p, ok := e.(*Problem); ok {
				code = p.Code
			}
			if code != lastCode && a.Notify != nil {
				a.Notify(code)
			}
			lastCode = code
			delay = backoff(failures)
			failures++
			continue
		}
		if lastCode != "" && a.Notify != nil {
			a.Notify("connected")
		}
		lastCode = ""
		failures = 0
		// Optional sideband reports never change inventory/pair capability
		// negotiation. Older Controllers can reject this endpoint independently.
		if a.Traffic {
			trafficCtx, stop := context.WithTimeout(ctx, 15*time.Second)
			summary := readTraffic(trafficCtx, a.Client)
			stop()
			var ack struct {
				Protocol int `json:"protocol"`
			}
			trafficErr := post(ctx, c, id.URL+"/v1/traffic", summary, &ack)
			p, _ := trafficErr.(*Problem)
			if p != nil && (p.Code == "identity_revoked" || p.Code == "identity_expired" || p.Code == "identity_required") {
				return trafficErr
			}
			nextCode := ""
			if trafficErr != nil || ack.Protocol != TrafficProtocol {
				nextCode = "traffic_report_unavailable"
			}
			if a.Notify != nil && nextCode != trafficCode {
				if nextCode == "" {
					a.Notify("traffic_report_connected")
				} else {
					a.Notify(nextCode)
				}
			}
			trafficCode = nextCode
		}
		delay = 60*time.Second + jitter(10*time.Second)
		if a.Operations {
			nextReport = time.Now().Add(delay)
			delay = 0
		}
	}
}
func fatal(e error) bool {
	p, ok := e.(*Problem)
	return ok && (p.Code == "identity_revoked" || p.Code == "identity_expired" || p.Code == "identity_required" || p.Code == "incompatible_protocol" || p.Code == "incompatible_capabilities")
}
func jitter(max time.Duration) time.Duration {
	n, e := rand.Int(rand.Reader, big.NewInt(int64(max)))
	if e != nil {
		return 0
	}
	return time.Duration(n.Int64())
}
func backoff(n int) time.Duration {
	if n > 6 {
		n = 6
	}
	return time.Second*time.Duration(1<<n) + jitter(time.Second)
}
