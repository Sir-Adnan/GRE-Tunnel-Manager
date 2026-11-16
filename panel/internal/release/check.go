package release

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"time"
)

// CheckPath records the daily update check. It is root-only; the panel
// reads it through the broker.
const CheckPath = "/var/lib/gre-manager-panel/update.json"

// Check is the result of the most recent update check. It never contains
// anything but public release numbers and a short error.
type Check struct {
	Version int       `json:"version"`
	Current string    `json:"current"`
	Latest  string    `json:"latest,omitempty"`
	Checked time.Time `json:"checked"`
	Error   string    `json:"error,omitempty"`
}

// Available reports a newer published release than the installed one.
func (c Check) Available() bool {
	return Valid(c.Latest) && Valid(c.Current) && Compare(c.Latest, c.Current) > 0
}

// LoadCheck reads a saved check. A missing file is not an error.
func LoadCheck(path string) (Check, error) {
	var c Check
	data, e := readLimited(path, 4096)
	if errors.Is(e, os.ErrNotExist) {
		return c, nil
	}
	if e != nil {
		return c, e
	}
	d := json.NewDecoder(bytes.NewReader(data))
	d.DisallowUnknownFields()
	if e = d.Decode(&c); e != nil || c.Version != 1 {
		return Check{}, errors.New("update check record is damaged")
	}
	return c, nil
}

// SaveCheck replaces the record atomically.
func SaveCheck(path string, c Check) error {
	c.Version = 1
	if len(c.Error) > 200 {
		c.Error = c.Error[:200]
	}
	return saveRecord(path, c)
}

// RunUnit is the transient systemd unit that runs an update started from the
// panel. It is not a child of the broker, so it survives the broker restart
// the update causes.
const RunUnit = "gre-manager-panel-update.service"

// RunPath records the most recent update started from the panel. It is
// root-only; the panel reads it through the broker.
const RunPath = "/var/lib/gre-manager-panel/update-run.json"

// Run states.
const (
	RunRunning   = "running"
	RunSucceeded = "succeeded"
	RunFailed    = "failed"
)

// Run is one update started from the panel ("gtm update --record").
type Run struct {
	Version  int       `json:"version"`
	State    string    `json:"state"`
	From     string    `json:"from"`
	To       string    `json:"to,omitempty"`
	Started  time.Time `json:"started"`
	Finished time.Time `json:"finished,omitzero"`
	Error    string    `json:"error,omitempty"`
}

// LoadRun reads the record. A missing file returns an empty Run.
func LoadRun(path string) (Run, error) {
	var r Run
	data, e := readLimited(path, 4096)
	if errors.Is(e, os.ErrNotExist) {
		return r, nil
	}
	if e != nil {
		return r, e
	}
	d := json.NewDecoder(bytes.NewReader(data))
	d.DisallowUnknownFields()
	if e = d.Decode(&r); e != nil || r.Version != 1 || (r.State != RunRunning && r.State != RunSucceeded && r.State != RunFailed) {
		return Run{}, errors.New("update run record is damaged")
	}
	return r, nil
}

// SaveRun replaces the record atomically.
func SaveRun(path string, r Run) error {
	r.Version = 1
	if len(r.Error) > 300 {
		r.Error = r.Error[:300]
	}
	return saveRecord(path, r)
}

func saveRecord(path string, value any) error {
	data, e := json.MarshalIndent(value, "", "  ")
	if e != nil {
		return e
	}
	f, e := os.CreateTemp(filepath.Dir(path), ".panel-*")
	if e != nil {
		return e
	}
	name := f.Name()
	defer os.Remove(name)
	if _, e = f.Write(append(data, '\n')); e == nil {
		e = f.Chmod(0600)
	}
	if ce := f.Close(); e == nil {
		e = ce
	}
	if e != nil {
		return e
	}
	return os.Rename(name, path)
}
