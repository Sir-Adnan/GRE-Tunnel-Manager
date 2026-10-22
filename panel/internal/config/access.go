package config

import (
	"errors"
	"net"
	"strings"
	"unicode"
	"unicode/utf8"
)

// An omitted protocol is HTTPS, preserving configurations from v1.3.0.
func (c Config) Scheme() string {
	if c.Protocol == "http" {
		return "http"
	}
	return "https"
}

func ValidHost(host string) bool {
	if ip := net.ParseIP(host); ip != nil {
		return ip.IsGlobalUnicast() || ip.IsLoopback()
	}
	if len(host) == 0 || len(host) > 253 {
		return false
	}
	for _, label := range strings.Split(host, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, ch := range label {
			if !(ch >= 'a' && ch <= 'z' || ch >= 'A' && ch <= 'Z' || ch >= '0' && ch <= '9' || ch == '-') {
				return false
			}
		}
	}
	// Reject malformed numeric IPs instead of treating them as DNS names.
	return strings.ContainsAny(host, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")
}

func ValidatePassword(secret string) error {
	if !utf8.ValidString(secret) || utf8.RuneCountInString(secret) < 8 || len(secret) > 72 {
		return errors.New("password must contain at least 8 characters and at most 72 UTF-8 bytes")
	}
	for _, ch := range secret {
		if unicode.IsControl(ch) {
			return errors.New("password must not contain control characters")
		}
	}
	return nil
}

func (c Config) URL() string {
	host, port, _ := net.SplitHostPort(c.Listen)
	if c.PublicHost != "" {
		host = c.PublicHost
	} else if c.PublicIP != "" {
		host = c.PublicIP
	}
	if !ValidHost(host) {
		return ""
	}
	return c.Scheme() + "://" + net.JoinHostPort(host, port)
}
