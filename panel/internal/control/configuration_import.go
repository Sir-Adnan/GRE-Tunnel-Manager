package control

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"strings"
	"unicode/utf8"

	"github.com/Sir-Adnan/GRE-Tunnel-Manager/panel/internal/model"
)

type ImportInput struct {
	Engine   string `json:"engine"`
	Format   string `json:"format"`
	Text     string `json:"text"`
	Activate bool   `json:"activate"`
	Review   string `json:"review,omitempty"`
}
type ImportView struct {
	Connections []model.Connection `json:"connections"`
	Warnings    []string           `json:"warnings"`
	Files       []ConfigFile       `json:"files"`
	Review      string             `json:"review"`
}

func parseImport(in ImportInput) ([]model.Connection, []string, error) {
	if len(in.Text) > maxConfigText || !utf8.ValidString(in.Text) || strings.ContainsRune(in.Text, 0) {
		return nil, nil, errors.New("configuration must be valid UTF-8, at most 64 KiB")
	}
	var cs []model.Connection
	warnings := []string{}
	var e error
	switch {
	case in.Format == "haproxy" && in.Engine == "haproxy":
		cs, warnings, e = parseHAImport(in.Text)
	case in.Format == "realm" && in.Engine == "realm":
		cs, e = parseRealmImport(in.Text)
	case in.Format == "portfw":
		cs, warnings, e = parsePortfwImport(in.Text, in.Engine)
	case in.Format == "json" && oneOf(in.Engine, "haproxy", "realm", "iptables", "nftables"):
		d := json.NewDecoder(strings.NewReader(in.Text))
		d.DisallowUnknownFields()
		if strings.HasPrefix(strings.TrimSpace(in.Text), "[") {
			e = d.Decode(&cs)
		} else {
			var c model.Connection
			e = d.Decode(&c)
			if e == nil {
				cs = []model.Connection{c}
			}
		}
		if e == nil {
			var extra any
			if d.Decode(&extra) != io.EOF {
				e = errors.New("one JSON array required")
			}
		}
	default:
		e = errors.New("choose HAProxy text, Realm TOML, or managed JSON")
	}
	if e != nil {
		return nil, nil, e
	}
	if len(cs) < 1 || len(cs) > 32 {
		return nil, nil, errors.New("import requires 1–32 connections")
	}
	for i := range cs {
		if cs[i].Engine != in.Engine || cs[i].ID != "" || cs[i].Revision != "" {
			return nil, nil, errors.New("import new connections only; remove IDs and revisions")
		}
		cs[i].Enabled = in.Activate
		cs[i].Status = ""
		rows, e := cs[i].Rows("F000000")
		if e != nil {
			return nil, nil, fmt.Errorf("connection %d: %w", i+1, e)
		}
		if len(rows) != 1 {
			return nil, nil, errors.New("use one port per imported connection")
		}
		canonical, _, err := model.ParseState(rows[0])
		if err != nil {
			return nil, nil, err
		}
		canonical[0].ID = ""
		canonical[0].Revision = ""
		cs[i] = canonical[0]
	}
	return cs, warnings, nil
}

func importConflicts(existing, incoming []model.Connection) error {
	all := append(append([]model.Connection{}, existing...), incoming...)
	for i := len(existing); i < len(all); i++ {
		a := all[i]
		addr, _ := netip.ParseAddr(a.Bind)
		for j := 0; j < i; j++ {
			b := all[j]
			peer, _ := netip.ParseAddr(b.Bind)
			if a.Ports != b.Ports || (a.Protocol != b.Protocol && a.Protocol != "both" && b.Protocol != "both") {
				continue
			}
			if addr.BitLen() == peer.BitLen() && (addr == peer || addr.IsUnspecified() || peer.IsUnspecified()) {
				return fmt.Errorf("port %s overlaps %s; edit the import before saving", a.Ports, b.Name)
			}
		}
	}
	return nil
}
func importDigest(in ImportInput, generation string) string {
	in.Review = ""
	b, _ := json.Marshal(in)
	s := sha256.Sum256(append(b, []byte("\n"+generation)...))
	return hex.EncodeToString(s[:])
}
func (m *Manager) importConfiguration(ctx context.Context, in ImportInput, apply bool) (any, error) {
	if in.Format == "portfw" {
		// The rules come from the server, never from the browser.
		out, e := m.call(ctx, "portfw-rules", "")
		if e != nil {
			return nil, e
		}
		in.Text = out
	}
	cs, warnings, e := parseImport(in)
	if e != nil {
		return nil, e
	}
	generation, e := m.call(ctx, "recovery-revision", "")
	if e != nil {
		return nil, e
	}
	generation = strings.TrimSpace(generation)
	if !digestValid(generation) {
		return nil, errors.New("cannot read server revision")
	}
	existing, _, e := m.state(ctx)
	if e != nil {
		return nil, e
	}
	if e = importConflicts(existing, cs); e != nil {
		return nil, e
	}
	review := importDigest(in, generation)
	if apply {
		if in.Review != review {
			return nil, errors.New("configuration or server changed; review the import again")
		}
		rows := []string{}
		for _, c := range cs {
			r, e := c.Rows("F000000")
			if e != nil {
				return nil, e
			}
			rows = append(rows, r...)
		}
		output, e := m.call(ctx, "create-reviewed", generation+"\n"+strings.Join(rows, "\n")+"\n")
		if e != nil {
			return nil, e
		}
		return map[string]any{"ok": true, "count": len(cs), "output": output}, nil
	}
	v := ImportView{Connections: cs, Warnings: warnings, Files: []ConfigFile{}, Review: review}
	for i, c := range cs {
		c.ID = "F000000"
		text, e := m.renderConnection(ctx, c)
		if e != nil {
			return nil, e
		}
		v.Files = append(v.Files, ConfigFile{Name: fmt.Sprintf("import-%d.conf", i+1), Text: text, Kind: "generated"})
	}
	return v, nil
}
