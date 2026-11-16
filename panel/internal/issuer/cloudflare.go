package issuer

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"golang.org/x/crypto/acme"
)

const CloudflareAPI = "https://api.cloudflare.com/client/v4"

// Cloudflare answers dns-01 with a temporary TXT record. The token needs
// Zone → DNS → Edit (and Zone → Read) on the zone that holds the host; it is
// sent only to the Cloudflare API, never logged or returned in errors.
type Cloudflare struct {
	Token      string
	API        string // default CloudflareAPI
	HTTPClient *http.Client
	// Lookup reads TXT values to wait for propagation; default asks 1.1.1.1.
	Lookup func(ctx context.Context, name string) ([]string, error)
	Wait   time.Duration // propagation wait cap; default two minutes
	Poll   time.Duration // default five seconds
}

func (Cloudflare) Type() string { return "dns-01" }

func (c Cloudflare) Present(ctx context.Context, client *acme.Client, id acme.AuthzID, challenge *acme.Challenge) (func(), error) {
	if id.Type != "dns" {
		return nil, errors.New("DNS validation needs a domain; IP addresses use HTTP validation")
	}
	value, e := client.DNS01ChallengeRecord(challenge.Token)
	if e != nil {
		return nil, e
	}
	zone, e := c.zone(ctx, id.Value)
	if e != nil {
		return nil, e
	}
	name := "_acme-challenge." + strings.TrimSuffix(id.Value, ".")
	var created struct {
		ID string `json:"id"`
	}
	record := map[string]any{"type": "TXT", "name": name, "content": value, "ttl": 60, "comment": "GRE Tunnel Manager certificate validation; removed automatically"}
	if e = c.call(ctx, http.MethodPost, "/zones/"+url.PathEscape(zone)+"/dns_records", record, &created); e != nil {
		return nil, fmt.Errorf("could not create the validation TXT record: %w", e)
	}
	cleanup := func() {
		done, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		c.call(done, http.MethodDelete, "/zones/"+url.PathEscape(zone)+"/dns_records/"+url.PathEscape(created.ID), nil, nil)
	}
	c.propagate(ctx, name, value)
	return cleanup, nil
}

// zone finds the closest enclosing zone the token can see, so subdomains of
// a delegated zone work without extra configuration.
func (c Cloudflare) zone(ctx context.Context, host string) (string, error) {
	labels := strings.Split(strings.TrimSuffix(host, "."), ".")
	for i := 0; i < len(labels)-1; i++ {
		var zones []struct {
			ID string `json:"id"`
		}
		name := strings.Join(labels[i:], ".")
		if e := c.call(ctx, http.MethodGet, "/zones?status=active&name="+url.QueryEscape(name), nil, &zones); e != nil {
			return "", fmt.Errorf("Cloudflare zone lookup failed: %w", e)
		}
		if len(zones) == 1 {
			return zones[0].ID, nil
		}
	}
	return "", fmt.Errorf("no active Cloudflare zone for %s is visible to this token; it needs Zone → Read and DNS → Edit", host)
}

func (c Cloudflare) call(ctx context.Context, method, path string, body, result any) error {
	api := c.API
	if api == "" {
		api = CloudflareAPI
	}
	var reader io.Reader
	if body != nil {
		data, e := json.Marshal(body)
		if e != nil {
			return e
		}
		reader = bytes.NewReader(data)
	}
	request, e := http.NewRequestWithContext(ctx, method, api+path, reader)
	if e != nil {
		return e
	}
	request.Header.Set("Authorization", "Bearer "+c.Token)
	request.Header.Set("Content-Type", "application/json")
	httpClient := c.HTTPClient
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 30 * time.Second}
	}
	response, e := httpClient.Do(request)
	if e != nil {
		return errors.New("Cloudflare API is unreachable")
	}
	defer response.Body.Close()
	var envelope struct {
		Success bool `json:"success"`
		Errors  []struct {
			Code    int    `json:"code"`
			Message string `json:"message"`
		} `json:"errors"`
		Result json.RawMessage `json:"result"`
	}
	if e = json.NewDecoder(io.LimitReader(response.Body, 1<<20)).Decode(&envelope); e != nil {
		return fmt.Errorf("unexpected Cloudflare API response (HTTP %d)", response.StatusCode)
	}
	if !envelope.Success {
		messages := []string{}
		for _, item := range envelope.Errors {
			messages = append(messages, fmt.Sprintf("%d %s", item.Code, item.Message))
		}
		if len(messages) == 0 {
			messages = append(messages, fmt.Sprintf("HTTP %d", response.StatusCode))
		}
		return errors.New("Cloudflare: " + strings.Join(messages, "; "))
	}
	if result != nil && len(envelope.Result) > 0 {
		return json.Unmarshal(envelope.Result, result)
	}
	return nil
}

// propagate waits until a public resolver sees the record. A timeout is not
// fatal: the CA asks the authoritative servers, which are usually faster.
func (c Cloudflare) propagate(ctx context.Context, name, value string) {
	lookup, wait, poll := c.Lookup, c.Wait, c.Poll
	if lookup == nil {
		lookup = publicTXT
	}
	if wait <= 0 {
		wait = 2 * time.Minute
	}
	if poll <= 0 {
		poll = 5 * time.Second
	}
	deadline := time.Now().Add(wait)
	for {
		step, cancel := context.WithTimeout(ctx, 5*time.Second)
		values, _ := lookup(step, name)
		cancel()
		for _, v := range values {
			if v == value {
				return
			}
		}
		if time.Now().Add(poll).After(deadline) {
			return
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(poll):
		}
	}
}

func publicTXT(ctx context.Context, name string) ([]string, error) {
	resolver := &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, network, "1.1.1.1:53")
	}}
	return resolver.LookupTXT(ctx, name)
}
