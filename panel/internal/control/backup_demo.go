package control

import (
	"context"
	"encoding/json"
	"errors"
	"strconv"
	"strings"
	"time"

	"github.com/Sir-Adnan/GRE-Tunnel-Manager/panel/internal/model"
)

func (d *Demo) backup(_ context.Context, r Request) (json.RawMessage, error) {
	if r.Action == "backup-export" {
		doc := recoveryDocument{Version: 1, Created: time.Now().UTC(), ManagerVersion: d.inventory.Version, Host: d.inventory.Host.Hostname, Counter: d.counter, Connections: d.inventory.Connections, Resources: []BackupResource{}}
		if len(d.inventory.Resources) > 0 {
			return nil, errors.New("demo backup cannot export simulated GRE/reverse secrets; use a clean demo inventory")
		}
		if r.Backup.IncludeTraffic {
			doc.Traffic = &d.metrics
		}
		archive, e := sealBackup(doc, r.Backup.Password)
		if e != nil {
			return nil, e
		}
		return json.Marshal(BackupDownload{"tunnel-manager-demo.gtm-backup", archive})
	}
	doc, review, e := prepareRecovery(r.Backup)
	if e != nil {
		return nil, e
	}
	data, _ := json.Marshal(d.inventory)
	review.Revision = model.Revision(string(data)) + ":" + model.Revision(string(mustMetricsJSON(d.metrics)))
	if len(d.inventory.Connections) > 0 || len(d.inventory.Resources) > 0 {
		review.Blockers = append(review.Blockers, "recoveryExisting")
	}
	if r.Backup.IncludeTraffic && doc.Traffic != nil && (d.metrics.Settings.Enabled || len(d.metrics.Counters) > 0 || len(d.metrics.Policies) > 0) {
		review.Blockers = append(review.Blockers, "recoveryTrafficExisting")
	}
	if r.Action == "backup-review" {
		return json.Marshal(review)
	}
	if r.Backup.Revision != review.Revision || len(review.Blockers) > 0 {
		return nil, errors.New("review again on an empty demo installation")
	}
	d.inventory.Connections = doc.Connections
	d.counter = doc.Counter
	for i := range d.inventory.Connections {
		c := &d.inventory.Connections[i]
		c.Enabled = false
		c.Status = "disabled"
		rows, _ := c.Rows(c.ID)
		c.Revision = model.Revision(rows[0])
		n, _ := strconv.Atoi(strings.TrimPrefix(c.ID, "F"))
		if n > d.counter {
			d.counter = n
		}
	}
	// Simulate restored resource inventory without making host files.
	for _, r := range doc.Resources {
		resource := Resource{Name: r.Name, Configured: true, Status: "inactive"}
		if g := r.GRE; g != nil {
			resource.ID = "gre-tun-" + strconv.Itoa(g.ID)
			resource.Engine = "gre"
			resource.Role = g.Role
		} else {
			resource.ID = "gtm-" + r.Reverse.Engine + "-" + r.Reverse.Role + "-" + r.Reverse.Name
			resource.Engine = r.Reverse.Engine
			resource.Role = r.Reverse.Role
		}
		d.inventory.Resources = append(d.inventory.Resources, resource)
	}
	if r.Backup.IncludeTraffic && doc.Traffic != nil {
		d.metrics = cloneMetrics(*doc.Traffic)
		d.metrics.Settings.Enabled = false
		d.metrics.Revision++
		for id, c := range d.metrics.Counters {
			c.LastReceived = 0
			c.LastSent = 0
			d.metrics.Counters[id] = c
		}
	}
	return json.Marshal(map[string]any{"ok": true, "paused": true, "restored": len(review.Items)})
}
func mustMetricsJSON(v MetricsView) []byte { b, _ := json.Marshal(v); return b }
