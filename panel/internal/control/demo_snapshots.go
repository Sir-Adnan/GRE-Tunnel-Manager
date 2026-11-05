package control

import (
	"encoding/json"
	"errors"
	"slices"
	"time"
)

// demoSnapshots keeps the schedule and snapshot list in memory; no files.
type demoSnapshots struct {
	settings SnapshotSettings
	revision uint64
	anchor   time.Time
	last     *time.Time
	list     []SnapshotInfo
}

func newDemoSnapshots(now time.Time) *demoSnapshots {
	s := &demoSnapshots{settings: SnapshotSettings{Enabled: true, Frequency: "daily", Time: "03:30", Keep: 14}, anchor: now}
	for i := 3; i >= 1; i-- {
		at := time.Date(now.Year(), now.Month(), now.Day()-i, 0, 0, 0, 0, time.UTC).Add(3*time.Hour + 30*time.Minute)
		s.list = append([]SnapshotInfo{{Name: "gtm-" + at.Format("20060102T150405") + ".json", Created: at, Size: 41_000 + int64(i)*350, Connections: 4}}, s.list...)
		s.last = &at
	}
	return s
}

func (d *Demo) snapshotsDemo(r Request) (json.RawMessage, error) {
	now := time.Now().UTC()
	if d.snaps == nil {
		d.snaps = newDemoSnapshots(now)
	}
	s, in := d.snaps, r.Snapshot
	switch r.Action {
	case "snapshots-configure":
		if in.Settings == nil {
			return nil, errors.New("settings required")
		}
		if e := in.Settings.Validate(); e != nil {
			return nil, e
		}
		if in.Revision != s.revision {
			return nil, errors.New("backup schedule changed; reload and try again")
		}
		s.settings, s.anchor = *in.Settings, now
		s.revision++
	case "snapshots-run":
		info := SnapshotInfo{Name: "gtm-" + now.Format("20060102T150405") + ".json", Created: now, Size: 42_100, Connections: len(d.inventory.Connections), Traffic: s.settings.Traffic}
		s.list = append([]SnapshotInfo{info}, s.list...)
		if len(s.list) > s.settings.Keep {
			s.list = s.list[:s.settings.Keep]
		}
		s.last = &now
		return json.Marshal("Saved snapshot " + info.Name + ". " + demoMessage)
	case "snapshots-delete":
		i := slices.IndexFunc(s.list, func(x SnapshotInfo) bool { return x.Name == in.Name })
		if i < 0 {
			return nil, errors.New("snapshot not found")
		}
		s.list = slices.Delete(s.list, i, i+1)
		return json.Marshal("Deleted snapshot " + in.Name + ". " + demoMessage)
	}
	v := SnapshotView{Settings: s.settings, Revision: s.revision, Timezone: "Asia/Tehran", Last: s.last, Snapshots: slices.Clone(s.list)}
	if s.settings.Enabled {
		anchor := s.anchor
		if s.last != nil && s.last.After(anchor) {
			anchor = *s.last
		}
		loc, _ := time.LoadLocation("Asia/Tehran")
		if loc == nil {
			loc = time.UTC
		}
		next := nextSnapshot(s.settings, anchor, loc)
		v.Next = &next
	}
	return json.Marshal(v)
}

func (d *Demo) prometheusDemo(r Request) (json.RawMessage, error) {
	if d.prom == nil {
		d.prom = &Prometheus{}
	}
	switch r.Action {
	case "prometheus-settings":
		return json.Marshal(d.prom.View())
	case "prometheus-configure":
		v, e := d.prom.Configure(r.Prometheus)
		if e != nil {
			return nil, e
		}
		return json.Marshal(v)
	}
	if !d.prom.Allowed(r.Prometheus.Token) {
		return nil, errors.New("unauthorized")
	}
	return json.Marshal(prometheusText(d.inventory.Host.Hostname, nil, &d.metrics, demoTelemetry(), 0))
}
