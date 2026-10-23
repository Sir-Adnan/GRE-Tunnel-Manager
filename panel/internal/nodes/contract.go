// Package nodes implements the optional, read-only control plane. It has no
// remote operation type, command field, or path to the privileged write API.
package nodes

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"regexp"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/Sir-Adnan/GRE-Tunnel-Manager/panel/internal/control"
)

const Protocol = 1
const DefaultControllerDir = "/var/lib/gre-manager-nodes"
const DefaultAgentPath = "/var/lib/gre-manager-agent/identity.json"
const MaxInventory = 262144

var idPattern = regexp.MustCompile(`^[a-f0-9]{32}$`)
var versionPattern = regexp.MustCompile(`^[0-9]+\.[0-9]+\.[0-9]+([+-][a-zA-Z0-9.-]+)?$`)
var capabilities = []string{"inventory.read"}

type Problem struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

func (p *Problem) Error() string         { return p.Message }
func problem(code, message string) error { return &Problem{code, message} }

type Report struct {
	Protocol     int             `json:"protocol"`
	Version      string          `json:"version"`
	Capabilities []string        `json:"capabilities"`
	Inventory    json.RawMessage `json:"inventory,omitempty"`
	Failure      *Problem        `json:"failure,omitempty"`
}
type Node struct {
	ID       string    `json:"id"`
	Name     string    `json:"name"`
	Revision string    `json:"revision"`
	Serials  []string  `json:"serials"`
	Revoked  bool      `json:"revoked"`
	Created  time.Time `json:"created"`
}
type View struct {
	ID                string          `json:"id"`
	Name              string          `json:"name"`
	Revision          string          `json:"revision"`
	Local             bool            `json:"local"`
	Status            string          `json:"status"`
	LastSeen          *time.Time      `json:"last_seen,omitempty"`
	Observed          *time.Time      `json:"observed,omitempty"`
	InventoryRevision string          `json:"inventory_revision,omitempty"`
	Protocol          int             `json:"protocol"`
	Version           string          `json:"version,omitempty"`
	Capabilities      []string        `json:"capabilities"`
	Inventory         json.RawMessage `json:"inventory,omitempty"`
	Failure           *Problem        `json:"failure,omitempty"`
}
type Listing struct {
	Enabled  bool   `json:"enabled"`
	URL      string `json:"url,omitempty"`
	Protocol int    `json:"protocol"`
	Nodes    []View `json:"nodes"`
}

func digest(b []byte) string { h := sha256.Sum256(b); return hex.EncodeToString(h[:]) }
func validName(s string) bool {
	if !utf8.ValidString(s) || utf8.RuneCountInString(s) > 64 || strings.TrimSpace(s) == "" {
		return false
	}
	visible := false
	for _, r := range s {
		if unicode.IsControl(r) || (unicode.In(r, unicode.Cf) && r != '\u200c' && r != '\u200d') {
			return false
		}
		if !unicode.IsSpace(r) && !unicode.In(r, unicode.Cf) {
			visible = true
		}
	}
	return visible
}
func validateReport(r Report) error {
	if r.Protocol != Protocol {
		return problem("incompatible_protocol", "Agent protocol is incompatible; install a matching Agent")
	}
	if len(r.Version) > 40 || !versionPattern.MatchString(r.Version) {
		return problem("invalid_report", "Invalid application version")
	}
	if len(r.Capabilities) != 1 || r.Capabilities[0] != "inventory.read" {
		return problem("incompatible_capabilities", "Read-only inventory capability is required")
	}
	if r.Failure != nil {
		if r.Failure.Code != "inventory_unavailable" || r.Failure.Message != "Local inventory could not be read" || len(r.Inventory) != 0 {
			return problem("invalid_report", "Invalid inventory failure")
		}
		return nil
	}
	if len(r.Inventory) == 0 || len(r.Inventory) > MaxInventory {
		return problem("inventory_too_large", "Inventory must fit within 256 KiB")
	}
	var inv control.Inventory
	if json.Unmarshal(r.Inventory, &inv) != nil || inv.Version == "" || len(inv.Host.Hostname) > 256 {
		return problem("invalid_report", "Invalid inventory")
	}
	// Canonicalize to the known inventory schema before retaining or presenting it.
	return nil
}
func canonicalInventory(raw json.RawMessage) (json.RawMessage, error) {
	var inv control.Inventory
	if e := json.Unmarshal(raw, &inv); e != nil {
		return nil, errors.New("invalid inventory")
	}
	b, e := json.Marshal(inv)
	if len(b) > MaxInventory {
		return nil, errors.New("canonical inventory exceeds 256 KiB")
	}
	return b, e
}
