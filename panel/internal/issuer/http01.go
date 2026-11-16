package issuer

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"syscall"
	"time"

	"golang.org/x/crypto/acme"
)

// HTTP01 answers one http-01 challenge from a temporary listener. Port 80
// is open only between Present and cleanup, a few seconds per order.
type HTTP01 struct {
	Address string // default ":80"; tests use another port
}

func (HTTP01) Type() string { return "http-01" }

func (s HTTP01) Present(_ context.Context, client *acme.Client, id acme.AuthzID, challenge *acme.Challenge) (func(), error) {
	response, e := client.HTTP01ChallengeResponse(challenge.Token)
	if e != nil {
		return nil, e
	}
	address := s.Address
	if address == "" {
		address = ":80"
	}
	listener, e := net.Listen("tcp", address)
	if e != nil {
		if errors.Is(e, syscall.EADDRINUSE) {
			return nil, fmt.Errorf("port %s is already used by another service; stop it briefly, or use DNS validation (Cloudflare) or an external ACME client", port(address))
		}
		return nil, fmt.Errorf("cannot open the validation port %s: %w", port(address), e)
	}
	server := &http.Server{Handler: challengeHandler(client.HTTP01ChallengePath(challenge.Token), response), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second, WriteTimeout: 10 * time.Second, MaxHeaderBytes: 8192}
	go server.Serve(listener)
	return func() { server.Close() }, nil
}

// challengeHandler serves exactly one path; everything else is 404, so the
// temporary listener exposes nothing about the panel or the server.
func challengeHandler(path, response string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != path || (r.Method != http.MethodGet && r.Method != http.MethodHead) {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/plain")
		w.Write([]byte(response))
	})
}

func port(address string) string {
	if _, p, e := net.SplitHostPort(address); e == nil {
		return p
	}
	return address
}
