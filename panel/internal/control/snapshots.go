package control

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Sir-Adnan/GRE-Tunnel-Manager/panel/internal/notify"
)

// SnapshotSettings schedule local recovery snapshots. Snapshots are the
// recovery document of a portable backup, stored root-only on this server
// (they hold reverse-tunnel secrets); downloading one seals it with a
// password into a regular .gtm-backup file.
type SnapshotSettings struct {
	Enabled   bool   `json:"enabled"`
	Frequency string `json:"frequency"`
	Time      string `json:"time"`
	Weekday   int    `json:"weekday"`
	Keep      int    `json:"keep"`
	Traffic   bool   `json:"traffic"`
}

func DefaultSnapshotSettings() SnapshotSettings {
	return SnapshotSettings{Frequency: "daily", Time: "03:30", Keep: 14}
}

var clockPattern = regexp.MustCompile(`^([01][0-9]|2[0-3]):([0-5][0-9])$`)
var snapshotName = regexp.MustCompile(`^gtm-[0-9]{8}T[0-9]{6}\.json$`)

func (s SnapshotSettings) Validate() error {
	switch {
	case s.Frequency != "daily" && s.Frequency != "weekly":
		return errors.New("frequency must be daily or weekly")
	case !clockPattern.MatchString(s.Time):
		return errors.New("time must be HH:MM")
	case s.Weekday < 0 || s.Weekday > 6:
		return errors.New("weekday must be 0–6")
	case s.Keep < 1 || s.Keep > 60:
		return errors.New("keep 1–60 snapshots")
	}
	return nil
}

// nextSnapshot is the first scheduled time after after, in loc.
func nextSnapshot(s SnapshotSettings, after time.Time, loc *time.Location) time.Time {
	m := clockPattern.FindStringSubmatch(s.Time)
	if m == nil {
		return time.Time{}
	}
	hour, _ := strconv.Atoi(m[1])
	minute, _ := strconv.Atoi(m[2])
	local := after.In(loc)
	for d := 0; d <= 8; d++ {
		day := local.AddDate(0, 0, d)
		t := time.Date(day.Year(), day.Month(), day.Day(), hour, minute, 0, 0, loc)
		if !t.After(after) || (s.Frequency == "weekly" && int(t.Weekday()) != s.Weekday) {
			continue
		}
		return t.UTC()
	}
	return time.Time{}
}

type SnapshotInfo struct {
	Name        string    `json:"name"`
	Created     time.Time `json:"created"`
	Size        int64     `json:"size"`
	Connections int       `json:"connections"`
	Resources   int       `json:"resources"`
	Traffic     bool      `json:"traffic"`
}

type SnapshotView struct {
	Settings  SnapshotSettings `json:"settings"`
	Revision  uint64           `json:"revision"`
	Timezone  string           `json:"timezone"`
	Next      *time.Time       `json:"next,omitempty"`
	Last      *time.Time       `json:"last,omitempty"`
	LastError string           `json:"last_error,omitempty"`
	Snapshots []SnapshotInfo   `json:"snapshots"`
}

// SnapshotInput carries one snapshot change.
type SnapshotInput struct {
	Settings *SnapshotSettings `json:"settings,omitempty"`
	Revision uint64            `json:"revision"`
	Name     string            `json:"name,omitempty"`
}

type snapshotState struct {
	Settings  SnapshotSettings `json:"settings"`
	Revision  uint64           `json:"revision"`
	Anchor    time.Time        `json:"anchor"`
	Last      *time.Time       `json:"last,omitempty"`
	LastError string           `json:"last_error,omitempty"`
}

// Snapshots owns the schedule file and the snapshot directory.
type Snapshots struct {
	mu    sync.Mutex
	path  string
	dir   string
	state snapshotState
}

func OpenSnapshots(path, dir string) (*Snapshots, error) {
	s := &Snapshots{path: path, dir: dir, state: snapshotState{Settings: DefaultSnapshotSettings(), Anchor: time.Now().UTC()}}
	data, e := os.ReadFile(path)
	if errors.Is(e, os.ErrNotExist) {
		return s, nil
	}
	if e != nil {
		return nil, e
	}
	if e = json.Unmarshal(data, &s.state); e != nil {
		return nil, e
	}
	return s, nil
}

func (s *Snapshots) saveLocked() error {
	data, e := json.Marshal(s.state)
	if e != nil {
		return e
	}
	if e = os.MkdirAll(filepath.Dir(s.path), 0700); e != nil {
		return e
	}
	temp := s.path + ".tmp"
	if e = os.WriteFile(temp, data, 0600); e != nil {
		return e
	}
	return os.Rename(temp, s.path)
}

func (s *Snapshots) list() []SnapshotInfo {
	out := []SnapshotInfo{}
	entries, _ := os.ReadDir(s.dir)
	for _, entry := range entries {
		if !snapshotName.MatchString(entry.Name()) || !entry.Type().IsRegular() {
			continue
		}
		info := SnapshotInfo{Name: entry.Name()}
		if fi, e := entry.Info(); e == nil {
			info.Size = fi.Size()
		}
		var d recoveryDocument
		if data, e := os.ReadFile(filepath.Join(s.dir, entry.Name())); e == nil && json.Unmarshal(data, &d) == nil {
			info.Created, info.Connections, info.Resources, info.Traffic = d.Created, len(d.Connections), len(d.Resources), d.Traffic != nil
		}
		out = append(out, info)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name > out[j].Name })
	return out
}

func (s *Snapshots) View(loc *time.Location) SnapshotView {
	s.mu.Lock()
	defer s.mu.Unlock()
	v := SnapshotView{Settings: s.state.Settings, Revision: s.state.Revision, Timezone: loc.String(), Last: s.state.Last, LastError: s.state.LastError, Snapshots: s.list()}
	if s.state.Settings.Enabled {
		if next := nextSnapshot(s.state.Settings, s.anchorLocked(), loc); !next.IsZero() {
			v.Next = &next
		}
	}
	return v
}

func (s *Snapshots) anchorLocked() time.Time {
	if s.state.Last != nil && s.state.Last.After(s.state.Anchor) {
		return *s.state.Last
	}
	return s.state.Anchor
}

func (s *Snapshots) Configure(now time.Time, in SnapshotSettings, revision uint64) error {
	if e := in.Validate(); e != nil {
		return e
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if revision != s.state.Revision {
		return errors.New("backup schedule changed; reload and try again")
	}
	// A new schedule counts from now: no catch-up run for past times.
	s.state.Settings, s.state.Anchor = in, now
	s.state.Revision++
	return s.saveLocked()
}

// Due reports whether a scheduled snapshot should run now.
func (s *Snapshots) Due(now time.Time, loc *time.Location) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.state.Settings.Enabled {
		return false
	}
	next := nextSnapshot(s.state.Settings, s.anchorLocked(), loc)
	return !next.IsZero() && !now.Before(next)
}

func (s *Snapshots) settings() SnapshotSettings {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.state.Settings
}

// write stores one document and prunes the oldest beyond keep.
func (s *Snapshots) write(now time.Time, d recoveryDocument, keep int) (SnapshotInfo, error) {
	data, e := json.Marshal(d)
	if e != nil {
		return SnapshotInfo{}, e
	}
	if e = os.MkdirAll(s.dir, 0700); e != nil {
		return SnapshotInfo{}, e
	}
	if e = os.Chmod(s.dir, 0700); e != nil {
		return SnapshotInfo{}, e
	}
	name := "gtm-" + now.UTC().Format("20060102T150405") + ".json"
	path := filepath.Join(s.dir, name)
	temp := path + ".tmp"
	if e = os.WriteFile(temp, data, 0600); e != nil {
		return SnapshotInfo{}, e
	}
	if e = os.Rename(temp, path); e != nil {
		return SnapshotInfo{}, e
	}
	list := s.list()
	for i := keep; i < len(list); i++ {
		_ = os.Remove(filepath.Join(s.dir, list[i].Name))
	}
	return SnapshotInfo{Name: name, Created: d.Created, Size: int64(len(data)), Connections: len(d.Connections), Resources: len(d.Resources), Traffic: d.Traffic != nil}, nil
}

func (s *Snapshots) record(now time.Time, failure error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if failure != nil {
		s.state.LastError = truncate(failure.Error(), 300)
		// Failed runs also advance the schedule; the next one retries.
		s.state.Anchor = now
	} else {
		s.state.Last, s.state.LastError = &now, ""
	}
	_ = s.saveLocked()
}

func (s *Snapshots) read(name string) (recoveryDocument, error) {
	var d recoveryDocument
	if !snapshotName.MatchString(name) {
		return d, errors.New("invalid snapshot name")
	}
	data, e := os.ReadFile(filepath.Join(s.dir, name))
	if e != nil {
		return d, errors.New("snapshot not found")
	}
	return d, json.Unmarshal(data, &d)
}

func (s *Snapshots) remove(name string) error {
	if !snapshotName.MatchString(name) {
		return errors.New("invalid snapshot name")
	}
	if e := os.Remove(filepath.Join(s.dir, name)); e != nil {
		return errors.New("snapshot not found")
	}
	return nil
}

// createSnapshot takes the manager lock like a portable export, then
// writes the snapshot and reports the result as a notification.
func (m *Manager) createSnapshot(ctx context.Context, scheduled bool) (SnapshotInfo, error) {
	s := m.Ops.Snapshots
	now := time.Now().UTC()
	info, e := func() (SnapshotInfo, error) {
		if e := os.MkdirAll(m.ConfigDir, 0700); e != nil {
			return SnapshotInfo{}, e
		}
		lock, e := nodeLease(filepath.Join(m.ConfigDir, "manager.lock"))
		if e != nil {
			return SnapshotInfo{}, errors.New("manager is busy; the snapshot will retry")
		}
		defer lock.Close()
		settings := s.settings()
		d, e := m.recoverySnapshot(ctx, settings.Traffic && m.Metrics != nil)
		if e != nil {
			return SnapshotInfo{}, e
		}
		if d, _, e = validateRecovery(d, BackupInput{}); e != nil {
			return SnapshotInfo{}, e
		}
		return s.write(now, d, settings.Keep)
	}()
	s.record(now, e)
	if scheduled || e != nil {
		if e != nil {
			m.Ops.Notify.Emit(notify.Event{Kind: notify.KindBackupFailed, Detail: truncate(e.Error(), 200)})
		} else {
			m.Ops.Notify.Emit(notify.Event{Kind: notify.KindBackup, Detail: fmt.Sprintf("%s · %d connections", info.Name, info.Connections), Args: map[string]string{"name": info.Name, "connections": strconv.Itoa(info.Connections)}})
		}
	}
	return info, e
}

func (m *Manager) snapshots(ctx context.Context, r Request) (any, error) {
	if m.Ops == nil || m.Ops.Snapshots == nil {
		return nil, errors.New("scheduled backups are unavailable on this broker")
	}
	s, in, loc := m.Ops.Snapshots, r.Snapshot, m.Ops.Maintenance.Location()
	switch r.Action {
	case "snapshots":
	case "snapshots-configure":
		if in.Settings == nil {
			return nil, errors.New("settings required")
		}
		if e := s.Configure(time.Now().UTC(), *in.Settings, in.Revision); e != nil {
			return nil, e
		}
	case "snapshots-run":
		info, e := m.createSnapshot(ctx, false)
		if e != nil {
			return nil, e
		}
		return "Saved snapshot " + info.Name + ".", nil
	case "snapshots-delete":
		if e := s.remove(in.Name); e != nil {
			return nil, e
		}
		return "Deleted snapshot " + in.Name + ".", nil
	default:
		return nil, errors.New("unsupported operation")
	}
	return s.View(loc), nil
}

// sealSnapshot downloads one snapshot as a password-protected backup.
func (m *Manager) sealSnapshot(in BackupInput) (BackupDownload, error) {
	if m.Ops == nil || m.Ops.Snapshots == nil {
		return BackupDownload{}, errors.New("scheduled backups are unavailable on this broker")
	}
	d, e := m.Ops.Snapshots.read(in.Snapshot)
	if e != nil {
		return BackupDownload{}, e
	}
	if d, _, e = validateRecovery(d, BackupInput{}); e != nil {
		return BackupDownload{}, e
	}
	archive, e := sealBackup(d, in.Password)
	return BackupDownload{Filename: "tunnel-manager-" + strings.TrimSuffix(strings.TrimPrefix(in.Snapshot, "gtm-"), ".json") + ".gtm-backup", Archive: archive}, e
}
