// Package issuer obtains publicly trusted panel certificates over ACME
// (Let's Encrypt by default) for one public domain or IP address.
//
// It owns the ACME conversation and the challenge solvers only. Certificate
// validation, publication and reload stay in package certificates and the
// gtm-panel certificate command, so a failed order never touches the loaded
// certificate.
package issuer

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"

	"golang.org/x/crypto/acme"
)

const (
	LetsEncrypt        = "https://acme-v02.api.letsencrypt.org/directory"
	LetsEncryptStaging = "https://acme-staging-v02.api.letsencrypt.org/directory"
	// ShortLived is Let's Encrypt's profile for IP-address certificates
	// (about six days); IP identifiers are not issued under the default one.
	ShortLived = "shortlived"
)

// Solver proves control of one identifier for one challenge type.
type Solver interface {
	// Type is the ACME challenge type, such as "http-01" or "dns-01".
	Type() string
	// Present publishes the proof and returns its cleanup, which must run
	// whether or not validation succeeds.
	Present(ctx context.Context, client *acme.Client, id acme.AuthzID, challenge *acme.Challenge) (cleanup func(), err error)
}

type Request struct {
	Directory  string
	Host       string
	Email      string
	Profile    string // empty: ShortLived for IP addresses when offered, otherwise the CA default
	AccountKey crypto.Signer
	Solver     Solver
	HTTPClient *http.Client
	UserAgent  string
	Log        func(format string, args ...any)
}

type Result struct {
	CertificatePEM, KeyPEM []byte
	Profile                string
}

// Obtain runs one complete order. It never retries a failed validation:
// the CA counts failures, and the renewal timer is the retry schedule.
func Obtain(ctx context.Context, r Request) (Result, error) {
	var result Result
	if r.AccountKey == nil || r.Solver == nil || r.Host == "" {
		return result, errors.New("certificate request is incomplete")
	}
	logf := r.Log
	if logf == nil {
		logf = func(string, ...any) {}
	}
	client := &acme.Client{Key: r.AccountKey, DirectoryURL: r.Directory, HTTPClient: r.HTTPClient, UserAgent: r.UserAgent}
	directory, e := client.Discover(ctx)
	if e != nil {
		return result, fmt.Errorf("certificate authority is unreachable: %w", e)
	}
	account := &acme.Account{}
	if r.Email != "" {
		account.Contact = []string{"mailto:" + r.Email}
	}
	// Registration is idempotent for a known key: the CA answers with the
	// existing account, which the client then uses.
	if _, e = client.Register(ctx, account, acme.AcceptTOS); e != nil && !errors.Is(e, acme.ErrAccountAlreadyExists) {
		return result, fmt.Errorf("ACME account registration failed: %s", problem(e))
	}
	ip := net.ParseIP(r.Host)
	ids := acme.DomainIDs(r.Host)
	if ip != nil {
		ids = acme.IPIDs(ip.String())
	}
	result.Profile = r.Profile
	if result.Profile == "" && ip != nil {
		if _, offered := directory.Profiles[ShortLived]; offered {
			result.Profile = ShortLived
		}
	}
	var options []acme.OrderOption
	if result.Profile != "" {
		options = append(options, acme.WithOrderIssuanceProfile(acme.ProfileName(result.Profile)))
	}
	logf("Requesting a certificate for %s", r.Host)
	order, e := client.AuthorizeOrder(ctx, ids, options...)
	if e != nil {
		return result, fmt.Errorf("certificate order was refused: %s", problem(e))
	}
	for _, url := range order.AuthzURLs {
		if e = authorize(ctx, client, url, r.Solver, logf); e != nil {
			return result, e
		}
	}
	if order, e = client.WaitOrder(ctx, order.URI); e != nil {
		return result, fmt.Errorf("certificate order did not become ready: %s", problem(e))
	}
	key, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if e != nil {
		return result, e
	}
	template := &x509.CertificateRequest{}
	if ip != nil {
		template.IPAddresses = []net.IP{ip}
	} else {
		template.DNSNames = []string{r.Host}
	}
	csr, e := x509.CreateCertificateRequest(rand.Reader, template, key)
	if e != nil {
		return result, e
	}
	chain, _, e := client.CreateCertFromOrder(ctx, order, csr, true)
	if e != nil {
		return result, fmt.Errorf("certificate issuance failed: %s", problem(e))
	}
	for _, der := range chain {
		result.CertificatePEM = append(result.CertificatePEM, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})...)
	}
	raw, e := x509.MarshalPKCS8PrivateKey(key)
	if e != nil {
		return result, e
	}
	result.KeyPEM = pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: raw})
	return result, nil
}

func authorize(ctx context.Context, client *acme.Client, url string, solver Solver, logf func(string, ...any)) error {
	authz, e := client.GetAuthorization(ctx, url)
	if e != nil {
		return fmt.Errorf("authorization lookup failed: %s", problem(e))
	}
	if authz.Status == acme.StatusValid {
		return nil
	}
	var challenge *acme.Challenge
	for _, c := range authz.Challenges {
		if c.Type == solver.Type() {
			challenge = c
			break
		}
	}
	if challenge == nil {
		return fmt.Errorf("the certificate authority offers no %s challenge for %s", solver.Type(), authz.Identifier.Value)
	}
	logf("Proving control of %s with %s", authz.Identifier.Value, solver.Type())
	cleanup, e := solver.Present(ctx, client, authz.Identifier, challenge)
	if e != nil {
		return e
	}
	defer cleanup()
	if _, e = client.Accept(ctx, challenge); e != nil {
		return fmt.Errorf("challenge was not accepted: %s", problem(e))
	}
	if _, e = client.WaitAuthorization(ctx, authz.URI); e != nil {
		return fmt.Errorf("%s validation failed for %s: %s", solver.Type(), authz.Identifier.Value, problem(e))
	}
	return nil
}

// problem keeps the CA's own explanation (for example "Connection refused")
// and drops protocol noise. It never contains key or token material.
func problem(e error) string {
	var authz *acme.AuthorizationError
	if errors.As(e, &authz) {
		parts := []string{}
		for _, item := range authz.Errors {
			parts = append(parts, problem(item))
		}
		if len(parts) > 0 {
			return strings.Join(parts, "; ")
		}
	}
	var order *acme.OrderError
	if errors.As(e, &order) {
		if order.Problem != nil {
			return problem(order.Problem)
		}
		return "order status " + order.Status
	}
	var failure *acme.Error
	if errors.As(e, &failure) {
		text := failure.Detail
		if text == "" {
			text = failure.ProblemType
		}
		if wait, limited := acme.RateLimit(e); limited {
			text += fmt.Sprintf(" (rate limited; retry after %s)", wait.Round(time.Minute))
		}
		return text
	}
	return e.Error()
}
