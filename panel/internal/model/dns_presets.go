package model

import (
	_ "embed"
	"encoding/json"
)

//go:embed dns_presets.json
var dnsPresetsJSON []byte

// DNSPreset is a named public resolver pair; the terminal menu and the panel share the list.
type DNSPreset struct {
	ID      string   `json:"id"`
	Name    string   `json:"name"`
	Group   string   `json:"group"`
	Servers []string `json:"servers"`
	IPv6    []string `json:"ipv6"`
}

// DNSPresets returns the server DNS presets.
func DNSPresets() []DNSPreset {
	var out []DNSPreset
	if e := json.Unmarshal(dnsPresetsJSON, &out); e != nil {
		panic(e)
	}
	return out
}
