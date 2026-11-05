package control

import (
	"context"
	"encoding/json"
	"time"

	"github.com/Sir-Adnan/GRE-Tunnel-Manager/panel/internal/notify"
)

// demoNotices seeds a short, realistic history. The demo never sends
// anything: the center has no delivery worker and Test only records.
func demoNotices(now time.Time) *notify.Center {
	c := notify.New()
	c.Host = "edge-01"
	for _, e := range []notify.Event{
		{Time: now.Add(-6 * time.Hour), Kind: notify.KindBackup, Detail: "gtm-20260105T0300.json · 42 KB"},
		{Time: now.Add(-3 * time.Hour), Kind: notify.KindMaintenance, Name: "Nightly relay restart", Detail: "Would restart the service. (2)"},
		{Time: now.Add(-62 * time.Minute), Kind: notify.KindDown, Owner: "F000002", Name: "WireGuard Stockholm", Detail: "198.51.100.30 · timeout"},
		{Time: now.Add(-55 * time.Minute), Kind: notify.KindUp, Owner: "F000002", Name: "WireGuard Stockholm", Detail: "down for 7m"},
		{Time: now.Add(-20 * time.Minute), Kind: notify.KindFailover, Owner: "F000004", Name: "Reality pool", Detail: "no new flows to destination 2"},
	} {
		c.Emit(e)
	}
	_ = c.MarkRead([]uint64{1, 2}, false)
	return c
}

func (d *Demo) notificationsDemo(r Request) (json.RawMessage, error) {
	if d.notices == nil {
		d.notices = demoNotices(time.Now().UTC())
	}
	if r.Action == "notifications-test" {
		d.notices.Emit(notify.Event{Kind: notify.KindTest, Detail: "Demo: no message was sent."})
		return json.Marshal(d.notices.View())
	}
	result, e := notificationAction(context.Background(), d.notices, r, notify.Sender{})
	if e != nil {
		return nil, e
	}
	return json.Marshal(result)
}
