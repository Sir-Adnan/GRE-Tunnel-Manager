package control

import (
	"context"
	"strings"
	"testing"

	"github.com/Sir-Adnan/GRE-Tunnel-Manager/panel/internal/notify"
)

func TestNodeChangeBecomesNotification(t *testing.T) {
	c := notify.New()
	id := strings.Repeat("a", 32)
	for _, change := range []NodeChange{
		{ID: id, Name: "Exit Amsterdam", Seconds: 190},
		{ID: id, Name: "Exit Amsterdam", Online: true, Seconds: 1320},
	} {
		if _, e := notificationAction(context.Background(), c, Request{Action: "notifications-node", Notify: NotifyInput{Node: &change}}, notify.Sender{}); e != nil {
			t.Fatal(e)
		}
	}
	events := c.View().Events
	if len(events) != 2 {
		t.Fatalf("events: %+v", events)
	}
	online, offline := events[0], events[1]
	if offline.Kind != notify.KindNodeOffline || offline.Severity != notify.SeverityWarning || offline.Name != "Exit Amsterdam" || offline.Args["seconds"] != "190" || offline.Args["node"] != id {
		t.Fatalf("offline: %+v", offline)
	}
	if online.Kind != notify.KindNodeOnline || online.Severity != notify.SeverityInfo || online.Detail != "offline for 22m" {
		t.Fatalf("online: %+v", online)
	}
	if got := offline.Text("fa", "edge"); !strings.Contains(got, "Exit Amsterdam") || !strings.Contains(got, "3 دقیقه") {
		t.Fatalf("persian text: %q", got)
	}
	if got := online.Text("en", ""); !strings.Contains(got, "Node Exit Amsterdam is back online") || !strings.Contains(got, "Offline for 22m") {
		t.Fatalf("english text: %q", got)
	}
}

func TestNodeChangeValidation(t *testing.T) {
	c := notify.New()
	good := strings.Repeat("b", 32)
	for name, change := range map[string]*NodeChange{
		"missing":       nil,
		"bad id":        {ID: "../etc", Name: "x"},
		"upper id":      {ID: strings.Repeat("B", 32), Name: "x"},
		"empty name":    {ID: good, Name: "  "},
		"control":       {ID: good, Name: "a\nb"},
		"long name":     {ID: good, Name: strings.Repeat("n", 65)},
		"negative time": {ID: good, Name: "x", Seconds: -1},
	} {
		if _, e := notificationAction(context.Background(), c, Request{Action: "notifications-node", Notify: NotifyInput{Node: change}}, notify.Sender{}); e == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if len(c.View().Events) != 0 {
		t.Fatal("rejected changes emitted events")
	}
	if !LightAction("notifications-node") || PublicOperation("notifications-node") || ReadAction("notifications-node") {
		t.Fatal("node changes must be a light action no browser can start")
	}
}
