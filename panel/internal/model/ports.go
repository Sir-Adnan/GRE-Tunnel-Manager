package model

import (
	"errors"
	"fmt"
	"net/netip"
	"regexp"
	"strconv"
	"strings"
)

// SpanMax is the largest kernel range record (ports per rule), as in Bash.
const SpanMax = 4096

// Span is one port or an ascending inclusive range.
type Span struct{ First, Last int }

func (s Span) Len() int { return s.Last - s.First + 1 }
func (s Span) String() string {
	if s.First == s.Last {
		return strconv.Itoa(s.First)
	}
	return fmt.Sprintf("%d-%d", s.First, s.Last)
}
func (s Span) overlaps(o Span) bool { return s.First <= o.Last && o.First <= s.Last }

// ParseSpan reads "443" or "2000-2999" (at most SpanMax ports).
func ParseSpan(value string) (Span, error) {
	first, last, ranged := strings.Cut(value, "-")
	a, e := strconv.Atoi(first)
	if e != nil || a < 1 || a > 65535 || !number.MatchString(first) {
		return Span{}, errors.New("invalid port")
	}
	if !ranged {
		return Span{a, a}, nil
	}
	b, e := strconv.Atoi(last)
	if e != nil || !number.MatchString(last) || b <= a || b > 65535 || b-a >= SpanMax {
		return Span{}, fmt.Errorf("a range must ascend and contain at most %d ports", SpanMax)
	}
	return Span{a, b}, nil
}

// ParsePortSpans reads a comma or space separated list. Kernel engines keep each
// range as one span; relays expand ranges to single ports (at most 32 in total).
func ParsePortSpans(value string, kernel bool) ([]Span, error) {
	if len(value) > 1024 {
		return nil, errors.New("too many ports")
	}
	words := strings.Fields(strings.ReplaceAll(value, ",", " "))
	if len(words) == 0 {
		return nil, errors.New("enter a local port")
	}
	spans := []Span{}
	for _, word := range words {
		s, e := ParseSpan(word)
		if e != nil {
			return nil, e
		}
		if !kernel {
			if s.Len() > 32 {
				return nil, errors.New("range must contain at most 32 ports")
			}
			for p := s.First; p <= s.Last; p++ {
				dup := false
				for _, o := range spans {
					dup = dup || o.First == p
				}
				if !dup {
					spans = append(spans, Span{p, p})
				}
			}
		} else {
			for _, o := range spans {
				if o.overlaps(s) {
					return nil, errors.New("port ranges overlap")
				}
			}
			spans = append(spans, s)
		}
		if len(spans) > 32 {
			return nil, errors.New("at most 32 ports or ranges per operation")
		}
	}
	return spans, nil
}

// ParsePorts keeps the earlier single-port expansion for relays and imports.
func ParsePorts(value string) ([]int, error) {
	spans, e := ParsePortSpans(value, false)
	ports := []int{}
	for _, s := range spans {
		ports = append(ports, s.First)
	}
	return ports, e
}

// hostPattern is the Bash gtm_hostname contract: lowercase labels, letter TLD.
var hostPattern = regexp.MustCompile(`^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]([a-z0-9-]{0,61}[a-z0-9])?$`)

// ValidHostname reports whether value is a DNS name a destination may use.
func ValidHostname(value string) bool { return len(value) <= 253 && hostPattern.MatchString(value) }

// IsHost reports whether the target names a DNS name instead of an address.
func (t Target) IsHost() bool { return ValidHostname(t.IP) }

// PortText is "443" or "3000-3999".
func (t Target) PortText() string {
	if t.PortLast > t.Port {
		return fmt.Sprintf("%d-%d", t.Port, t.PortLast)
	}
	return strconv.Itoa(t.Port)
}

// Endpoint is the record spelling without the weight: "ip:port", "[v6]:port" or "name:port".
func (t Target) Endpoint() string {
	if strings.Contains(t.IP, ":") {
		return "[" + t.IP + "]:" + t.PortText()
	}
	return t.IP + ":" + t.PortText()
}

// ParseTarget reads one record destination "address:port[-port][@weight]".
func ParseTarget(value string) (Target, error) {
	endpoint, w, weighted := strings.Cut(value, "@")
	weight := 1
	if weighted {
		n, e := strconv.Atoi(w)
		if e != nil || !number.MatchString(w) {
			return Target{}, errors.New("invalid weight")
		}
		weight = n
	}
	i := strings.LastIndex(endpoint, ":")
	if i < 1 {
		return Target{}, errors.New("invalid destination")
	}
	host, port := endpoint[:i], endpoint[i+1:]
	if strings.HasPrefix(host, "[") && strings.HasSuffix(host, "]") {
		host = host[1 : len(host)-1]
		if a, e := netip.ParseAddr(host); e != nil || !a.Is6() {
			return Target{}, errors.New("invalid IPv6 destination")
		}
	} else if a, e := netip.ParseAddr(host); e == nil {
		if !a.Is4() {
			return Target{}, errors.New("IPv6 destinations need brackets")
		}
	} else if !ValidHostname(host) {
		return Target{}, errors.New("invalid destination address")
	}
	s, e := ParseSpan(port)
	if e != nil {
		return Target{}, e
	}
	t := Target{IP: host, Port: s.First, Weight: weight}
	if s.Last > s.First {
		t.PortLast = s.Last
	}
	return t, nil
}
