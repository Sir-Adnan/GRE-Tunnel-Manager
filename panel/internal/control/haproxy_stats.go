package control

import (
	"bufio"
	"context"
	"encoding/csv"
	"errors"
	"io"
	"net"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/Sir-Adnan/GRE-Tunnel-Manager/panel/internal/health"
)

// haproxyServer is one destination as HAProxy's own health check sees it.
type haproxyServer struct {
	Status   string
	Check    string
	Duration float64
	Sessions int
	Backup   bool
}

// readHAProxyStats asks one managed instance for "show stat" over its
// root-only stats socket. It returns the servers of the "destinations"
// backend by 1-based position (server names are target1, target2, ...).
func readHAProxyStats(ctx context.Context, socket string) (map[int]haproxyServer, error) {
	ctx, cancel := context.WithTimeout(ctx, time.Second)
	defer cancel()
	conn, e := (&net.Dialer{}).DialContext(ctx, "unix", socket)
	if e != nil {
		return nil, e
	}
	defer conn.Close()
	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	}
	if _, e = io.WriteString(conn, "show stat\n"); e != nil {
		return nil, e
	}
	return parseHAProxyStats(io.LimitReader(conn, 1<<20))
}

func parseHAProxyStats(r io.Reader) (map[int]haproxyServer, error) {
	reader := bufio.NewReader(r)
	header, e := reader.ReadString('\n')
	if e != nil || !strings.HasPrefix(header, "# ") {
		return nil, errors.New("unexpected HAProxy stats output")
	}
	columns := map[string]int{}
	for i, name := range strings.Split(strings.TrimSpace(strings.TrimPrefix(header, "# ")), ",") {
		columns[name] = i
	}
	for _, name := range []string{"pxname", "svname", "status", "check_status", "check_duration", "scur", "bck"} {
		if _, ok := columns[name]; !ok {
			return nil, errors.New("HAProxy stats lack column " + name)
		}
	}
	rows := csv.NewReader(reader)
	rows.FieldsPerRecord = -1
	out := map[int]haproxyServer{}
	for {
		row, e := rows.Read()
		if errors.Is(e, io.EOF) {
			break
		}
		if e != nil {
			return nil, e
		}
		field := func(name string) string {
			if i := columns[name]; i < len(row) {
				return row[i]
			}
			return ""
		}
		if field("pxname") != "destinations" || !strings.HasPrefix(field("svname"), "target") {
			continue
		}
		index, e := strconv.Atoi(strings.TrimPrefix(field("svname"), "target"))
		if e != nil || index < 1 || index > 32 {
			continue
		}
		duration, _ := strconv.ParseFloat(field("check_duration"), 64)
		sessions, _ := strconv.Atoi(field("scur"))
		out[index] = haproxyServer{Status: field("status"), Check: field("check_status"), Duration: duration, Sessions: sessions, Backup: field("bck") == "1"}
	}
	return out, nil
}

// result maps HAProxy's view to a health result. ok is false when the
// server has no active check, so the panel probes it itself.
func (s haproxyServer) result() (health.Result, bool) {
	status := strings.ToUpper(s.Status)
	if status == "" || strings.HasPrefix(status, "NO CHECK") {
		return health.Result{}, false
	}
	sessions := s.Sessions
	r := health.Result{Via: "haproxy", Sessions: &sessions, Backup: s.Backup}
	// "UP 1/3" is still serving while failing; "DOWN 1/2" is not yet back.
	switch {
	case strings.HasPrefix(status, "UP"), status == "NOLB", status == "DRAIN":
		r.OK, r.RTT = true, s.Duration
	case strings.HasPrefix(status, "MAINT"):
		r.Error = "maintenance"
	default:
		switch {
		case strings.Contains(s.Check, "TOUT"):
			r.Error = "timeout"
		case strings.Contains(s.Check, "CON"):
			r.Error = "refused"
		default:
			r.Error = "down"
		}
	}
	return r, true
}

// haproxyResults fills results for HAProxy destinations from each
// instance's own checks, which run every few seconds anyway.
func (o *Operations) haproxyResults(ctx context.Context, inventory Inventory, targets []health.Target) map[string]health.Result {
	out := map[string]health.Result{}
	stats := map[string]map[int]haproxyServer{}
	for _, c := range inventory.Connections {
		if c.Engine != "haproxy" || !c.Enabled {
			continue
		}
		servers, e := readHAProxyStats(ctx, filepath.Join(o.runDir, "haproxy", c.ID+".sock"))
		if e == nil {
			stats[c.ID] = servers
		}
	}
	for _, t := range targets {
		servers := stats[t.Owner]
		if servers == nil || t.Kind != health.KindTCP {
			continue
		}
		for _, index := range t.Indexes {
			if r, ok := servers[index].result(); ok {
				if previous, seen := out[t.Key]; !seen || (!previous.OK && r.OK) {
					out[t.Key] = r
				}
			}
		}
	}
	return out
}
