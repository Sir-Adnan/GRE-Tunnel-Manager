package control

import (
	"context"
	"errors"
	"strconv"
	"strings"
	"time"

	"github.com/Sir-Adnan/GRE-Tunnel-Manager/panel/internal/model"
)

// PathStage is one step of a connection's live packet path. Kernel stages
// (new, snat, out, back, blocked) are counters since the rules were last
// applied; relay stages (clients, upstream) are current socket counts.
// Address names the destination of out, back and upstream.
type PathStage struct {
	Key     string `json:"key"`
	Address string `json:"address,omitempty"`
	Packets uint64 `json:"packets"`
	Bytes   uint64 `json:"bytes"`
}

// ConnectionPath is one sample; the panel shows rates between samples.
// Drops names iptables backends whose FORWARD policy drops this
// connection's packets because the owned accept is missing.
type ConnectionPath struct {
	ID      string      `json:"id"`
	Engine  string      `json:"engine"`
	Enabled bool        `json:"enabled"`
	Time    time.Time   `json:"time"`
	Stages  []PathStage `json:"stages"`
	Drops   []string    `json:"drops"`
}

var pathKeys = map[string]bool{"new": true, "snat": true, "out": true, "back": true, "blocked": true, "clients": true, "upstream": true}

func parseConnectionPath(id, out string) ConnectionPath {
	path := ConnectionPath{ID: id, Stages: []PathStage{}, Drops: []string{}}
	for _, line := range strings.Split(strings.TrimSpace(out), "\n") {
		f := strings.Split(line, "\t")
		switch {
		case len(f) == 3 && f[0] == "engine":
			path.Engine, path.Enabled = f[1], f[2] == "1"
		case len(f) == 5 && f[0] == "stage" && pathKeys[f[1]] && len(path.Stages) < 64:
			packets, e1 := strconv.ParseUint(f[3], 10, 64)
			bytes, e2 := strconv.ParseUint(f[4], 10, 64)
			if e1 != nil || e2 != nil {
				continue
			}
			stage := PathStage{Key: f[1], Packets: packets, Bytes: bytes}
			if f[2] != "-" && len(f[2]) <= 64 {
				stage.Address = f[2]
			}
			path.Stages = append(path.Stages, stage)
		case len(f) == 2 && f[0] == "drop" && strings.HasPrefix(f[1], "ip") && len(path.Drops) < 4:
			path.Drops = append(path.Drops, f[1])
		}
	}
	return path
}

func (m *Manager) connectionPath(ctx context.Context, id string) (ConnectionPath, error) {
	if !model.IDPattern.MatchString(id) {
		return ConnectionPath{}, errors.New("invalid connection ID")
	}
	out, e := m.call(ctx, "connection-path", "", id)
	if e != nil {
		return ConnectionPath{}, e
	}
	path := parseConnectionPath(id, out)
	path.Time = time.Now().UTC()
	return path, nil
}
