// Package setup implements one-time installation, independent of the HTTP server.
package setup

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"strings"
	"time"
)

// Discover makes bounded HTTPS requests only during setup. Never runs in a daemon.
func Discover(ctx context.Context) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, 6*time.Second)
	defer cancel()
	client := &http.Client{Timeout: 3 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	return discover(ctx, client, []string{"https://api.ipify.org", "https://api6.ipify.org"})
}

func discover(ctx context.Context, client *http.Client, endpoints []string) (string, error) {
	for _, endpoint := range endpoints {
		req, e := http.NewRequestWithContext(ctx, "GET", endpoint, nil)
		if e != nil {
			continue
		}
		response, e := client.Do(req)
		if e != nil {
			continue
		}
		data, e := io.ReadAll(io.LimitReader(response.Body, 129))
		response.Body.Close()
		if e != nil || response.StatusCode != 200 || len(data) > 128 {
			continue
		}
		ip := net.ParseIP(strings.TrimSpace(string(data)))
		if ip != nil && ip.IsGlobalUnicast() && !ip.IsPrivate() {
			return ip.String(), nil
		}
	}
	return "", errors.New("public IP discovery failed; supply --address SERVER_IP or --address DOMAIN")
}
