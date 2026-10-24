package control

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/Sir-Adnan/GRE-Tunnel-Manager/panel/internal/model"
)

func TestDemoCreatedAndDisabledRecordsHaveInspectableRevisions(t *testing.T) {
	ctx := context.Background()
	d := NewDemo()
	c := d.inventory.Connections[0]
	c.ID = ""
	c.Revision = ""
	c.Ports = "9447"
	c.Name = "New default"
	c.Options = nil
	if _, err := d.Do(ctx, Request{Action: "create", Connection: c}); err != nil {
		t.Fatal(err)
	}
	c = d.inventory.Connections[len(d.inventory.Connections)-1]
	if c.Options["maxconn"] != "100000" || c.Options["log"] != "off" {
		t.Fatal(c.Options)
	}
	inspect := func(c model.Connection) {
		t.Helper()
		data, err := d.Do(ctx, Request{Action: "configuration", Configuration: ConfigInput{ID: c.ID, Revision: c.Revision}})
		if err != nil {
			t.Fatal(err)
		}
		var view ConfigView
		if err = json.Unmarshal(data, &view); err != nil || len(view.Files) != 1 {
			t.Fatal(err, string(data))
		}
	}
	inspect(c)
	if _, err := d.Do(ctx, Request{Action: "disable", Selected: []Selection{{ID: c.ID, Revision: c.Revision}}}); err != nil {
		t.Fatal(err)
	}
	c = d.inventory.Connections[len(d.inventory.Connections)-1]
	if c.Enabled || c.Status != "disabled" {
		t.Fatal(c)
	}
	inspect(c)
	// A configuration import can also change enabled state; its status must agree.
	c.Enabled = true
	draft, err := json.Marshal(c)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := d.Do(ctx, Request{Action: "configuration-apply", Configuration: ConfigInput{ID: c.ID, Revision: c.Revision, Format: "json", Text: string(draft)}}); err != nil {
		t.Fatal(err)
	}
	c = d.inventory.Connections[len(d.inventory.Connections)-1]
	if !c.Enabled || c.Status != "configured" {
		t.Fatal(c)
	}
	inspect(c)
}
