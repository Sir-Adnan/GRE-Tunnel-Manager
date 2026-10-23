package control

import (
	"encoding/json"
	"os"
	"path/filepath"
	"time"
)

// Record action metadata only. Never persist request bodies, tokens, keys,
// passwords, generated native configs or command output in the audit log.
func audit(request Request, operationError error) error {
	if request.Action == "inventory" || request.Action == "metrics" || request.Action == "metrics-history" || request.Action == "capabilities" {
		return nil
	}
	directory := "/var/lib/gre-manager-panel"
	if e := os.MkdirAll(directory, 0700); e != nil {
		return e
	}
	path := filepath.Join(directory, "audit.jsonl")
	if info, e := os.Stat(path); e == nil && info.Size() > 1048576 {
		if e = os.Rename(path, path+".1"); e != nil {
			return e
		}
	}
	action := request.Action
	if len(action) > 40 {
		action = action[:40]
	}
	record := struct {
		Time    time.Time `json:"time"`
		Action  string    `json:"action"`
		Success bool      `json:"success"`
	}{Time: time.Now().UTC(), Action: action, Success: operationError == nil}
	file, e := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
	if e != nil {
		return e
	}
	defer file.Close()
	return json.NewEncoder(file).Encode(record)
}
