package control

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/Sir-Adnan/GRE-Tunnel-Manager/panel/internal/health"
	"github.com/Sir-Adnan/GRE-Tunnel-Manager/panel/internal/notify"
)

// NotifyInput carries one notification change.
type NotifyInput struct {
	Settings *notify.Settings `json:"settings,omitempty"`
	Revision uint64           `json:"revision"`
	IDs      []uint64         `json:"ids,omitempty"`
	All      bool             `json:"all,omitempty"`
}

// notifications serves the notification actions of the real broker.
func (m *Manager) notifications(ctx context.Context, r Request) (any, error) {
	if m.Ops == nil || m.Ops.Notify == nil {
		return nil, errors.New("notifications are unavailable on this broker")
	}
	return notificationAction(ctx, m.Ops.Notify, r, notify.Sender{})
}

func notificationAction(ctx context.Context, c *notify.Center, r Request, sender notify.Sender) (any, error) {
	in := r.Notify
	switch r.Action {
	case "notifications":
	case "notifications-read":
		if e := c.MarkRead(in.IDs, in.All); e != nil {
			return nil, e
		}
	case "notifications-clear":
		if e := c.Clear(); e != nil {
			return nil, e
		}
	case "notifications-configure":
		if in.Settings == nil {
			return nil, errors.New("settings required")
		}
		if e := c.Configure(*in.Settings, in.Revision); e != nil {
			return nil, e
		}
	case "notifications-test":
		test, cancel := context.WithTimeout(ctx, 40*time.Second)
		defer cancel()
		if e := c.Test(test, sender); e != nil {
			return nil, e
		}
	default:
		return nil, errors.New("unsupported operation")
	}
	return c.View(), nil
}

// healthEvents reports owners that went down or came back between two
// status snapshots. Owners new to the monitor report only when down.
func healthEvents(c *notify.Center, now time.Time, before, after map[string]health.OwnerState) {
	for owner, s := range after {
		previous, known := before[owner]
		switch {
		case s.Status == health.StatusDown && (!known || previous.Status != health.StatusDown):
			detail := s.Endpoint
			if s.Error != "" {
				detail = strings.TrimSpace(detail + " · " + s.Error)
			}
			c.Emit(notify.Event{Time: now, Kind: notify.KindDown, Owner: owner, Name: s.Name, Detail: detail})
		case known && previous.Status == health.StatusDown && (s.Status == health.StatusUp || s.Status == health.StatusDegraded):
			c.Emit(notify.Event{Time: now, Kind: notify.KindUp, Owner: owner, Name: s.Name, Detail: "down for " + shortDuration(now.Sub(previous.Since))})
		}
	}
}

func shortDuration(d time.Duration) string {
	switch {
	case d < time.Minute:
		return fmt.Sprintf("%ds", int(d.Seconds()))
	case d < time.Hour:
		return fmt.Sprintf("%dm", int(d.Minutes()))
	case d < 48*time.Hour:
		return fmt.Sprintf("%dh %dm", int(d.Hours()), int(d.Minutes())%60)
	}
	return fmt.Sprintf("%dd", int(d.Hours()/24))
}

// failoverDetail describes an exclusion list for a notification.
func failoverDetail(list string) string {
	if list == "-" || list == "" {
		return "every destination receives new flows again"
	}
	return "no new flows to destination " + strings.ReplaceAll(list, ",", ", ")
}
