package model

import (
	"errors"
	"regexp"
	"strconv"
	"strings"
)

// Routing is separate from health/transport options and versioned independently.
// Targets are one-based positions in this connection's destination list.
type Routing struct {
	Version     int     `json:"version"`
	Mode        string  `json:"mode"`
	Certificate string  `json:"certificate"`
	Rules       []Route `json:"rules"`
}
type Route struct {
	Host   string `json:"host"`
	Prefix string `json:"prefix"`
	Target int    `json:"target"`
}

var routeHost = regexp.MustCompile(`^[a-z0-9]([a-z0-9.-]{0,251}[a-z0-9])?$`)
var certificateID = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_-]{0,39}$`)

func (r Routing) Encode(targets int) (string, error) {
	if r.Version != 1 || !contains([]string{"sni", "http", "https"}, r.Mode) || len(r.Rules) > 16 {
		return "", errors.New("unsupported routing schema, mode or rule count")
	}
	cert := r.Certificate
	if r.Mode == "https" {
		if !certificateID.MatchString(cert) {
			return "", errors.New("select a provisioned certificate ID")
		}
	} else {
		if cert != "" {
			return "", errors.New("certificates are only used for HTTPS termination")
		}
		cert = "-"
	}
	rules := []string{}
	seen := map[string]bool{}
	for _, rule := range r.Rules {
		if !routeHost.MatchString(rule.Host) || strings.Contains(rule.Host, "..") || rule.Target < 1 || rule.Target > targets || (rule.Prefix != "" && (!healthPath.MatchString(rule.Prefix) || strings.ContainsRune(rule.Prefix, '~') || r.Mode == "sni")) {
			return "", errors.New("invalid route host, path or destination position")
		}
		key := rule.Host + "~" + rule.Prefix
		if seen[key] {
			return "", errors.New("duplicate route condition")
		}
		seen[key] = true
		path := rule.Prefix
		if path == "" {
			path = "-"
		}
		rules = append(rules, rule.Host+"~"+path+"~"+strconv.Itoa(rule.Target))
	}
	encoded := strings.Join(rules, ",")
	if encoded == "" {
		encoded = "-"
	}
	return "1|" + r.Mode + "|" + cert + "|" + encoded, nil
}
func parseRouting(s string) (*Routing, error) {
	p := strings.Split(s, "|")
	if len(p) != 4 || p[0] != "1" {
		return nil, errors.New("invalid routing record")
	}
	r := &Routing{Version: 1, Mode: p[1], Rules: []Route{}}
	if p[2] != "-" {
		r.Certificate = p[2]
	}
	if p[3] != "-" {
		for _, encoded := range strings.Split(p[3], ",") {
			f := strings.Split(encoded, "~")
			if len(f) != 3 {
				return nil, errors.New("invalid route")
			}
			target, e := strconv.Atoi(f[2])
			if e != nil {
				return nil, e
			}
			prefix := f[1]
			if prefix == "-" {
				prefix = ""
			}
			r.Rules = append(r.Rules, Route{f[0], prefix, target})
		}
	}
	return r, nil
}
