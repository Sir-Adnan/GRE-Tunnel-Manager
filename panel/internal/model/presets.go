package model

import (
	_ "embed"
	"encoding/json"
	"maps"
)

type Localized map[string]string
type Preset struct {
	ID         string            `json:"id"`
	Engine     string            `json:"engine"`
	Label      Localized         `json:"label"`
	Help       Localized         `json:"help"`
	Protocol   string            `json:"protocol,omitempty"`
	Strategy   string            `json:"strategy,omitempty"`
	Options    map[string]string `json:"options,omitempty"`
	MaxTargets int               `json:"max_targets,omitempty"`
	MTU        int               `json:"mtu,omitempty"`
	Transport  string            `json:"transport,omitempty"`
	Mux        *bool             `json:"mux,omitempty"`
}

//go:embed presets.json
var presetJSON []byte

func Presets() []Preset {
	var presets []Preset
	if e := json.Unmarshal(presetJSON, &presets); e != nil {
		panic("invalid built-in preset catalog")
	}
	// Each caller owns its maps; no user draft can mutate the built-in catalog.
	for i := range presets {
		presets[i].Options = maps.Clone(presets[i].Options)
	}
	return presets
}
