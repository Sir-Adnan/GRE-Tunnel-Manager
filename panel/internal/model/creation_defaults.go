package model

import (
	_ "embed"
	"encoding/json"
	"maps"
)

//go:embed creation_defaults.json
var creationDefaultsJSON []byte

// WithCreationDefaults is used only when creating a new forward. Never apply it
// while reading, editing or reconciling existing records: absent legacy fields
// keep their original adapter semantics. Explicit user values always win.
func (c Connection) WithCreationDefaults() Connection {
	var defaults map[string]map[string]string
	if err := json.Unmarshal(creationDefaultsJSON, &defaults); err != nil {
		panic("invalid creation defaults")
	}
	options := maps.Clone(defaults[c.Engine])
	if options == nil {
		return c
	}
	maps.Copy(options, c.Options)
	c.Options = options
	return c
}
