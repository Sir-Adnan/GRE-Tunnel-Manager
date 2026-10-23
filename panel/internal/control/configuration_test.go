package control

import (
	"context"
	"encoding/json"
	"github.com/Sir-Adnan/GRE-Tunnel-Manager/panel/internal/model"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func demoConfig(t *testing.T, d *Demo, id string) (ConfigInput, ConfigView) {
	t.Helper()
	var inv Inventory
	raw, e := d.Do(context.Background(), Request{Action: "inventory"})
	if e != nil {
		t.Fatal(e)
	}
	json.Unmarshal(raw, &inv)
	for _, c := range inv.Connections {
		if c.ID == id {
			in := ConfigInput{ID: id, Revision: c.Revision}
			raw, e = d.Do(context.Background(), Request{Action: "configuration", Configuration: in})
			if e != nil {
				t.Fatal(e)
			}
			var v ConfigView
			if json.Unmarshal(raw, &v) != nil {
				t.Fatal(string(raw))
			}
			return in, v
		}
	}
	t.Fatal("missing fixture")
	return ConfigInput{}, ConfigView{}
}
func TestNativeEditorReviewsAppliesAndRejectsStaleOrUnsupportedText(t *testing.T) {
	ctx := context.Background()
	d := NewDemo()
	in, v := demoConfig(t, d, "F000001")
	in.Format = "native"
	in.Text = strings.ReplaceAll(v.Files[0].Text, "timeout client 3600s", "timeout client 7200s")
	if _, e := d.Do(ctx, Request{Action: "configuration-review", Configuration: in}); e == nil {
		t.Fatal("inconsistent client/server policy accepted")
	}
	in.Text = strings.ReplaceAll(in.Text, "timeout server 3600s", "timeout server 7200s")
	if _, e := d.Do(ctx, Request{Action: "configuration-review", Configuration: in}); e != nil {
		t.Fatal(e)
	}
	// A review is read-only and does not change the saved generation.
	_, old := demoConfig(t, d, "F000001")
	if old.Editor != v.Editor {
		t.Fatal("review mutated saved state")
	}
	if _, e := d.Do(ctx, Request{Action: "configuration-apply", Configuration: in}); e != nil {
		t.Fatal(e)
	}
	if _, e := d.Do(ctx, Request{Action: "configuration-apply", Configuration: in}); e == nil {
		t.Fatal("replayed editor revision accepted")
	}
	now, next := demoConfig(t, d, "F000001")
	if !strings.Contains(next.Editor, `"idle": "7200"`) {
		t.Fatal(next.Editor)
	}
	now.Format = "native"
	now.Text = next.Files[0].Text + "\nprogram arbitrary\n command /bin/sh\n"
	if _, e := d.Do(ctx, Request{Action: "configuration-review", Configuration: now}); e == nil {
		t.Fatal("executable native directive accepted")
	}
	// A separate connection remains untouched.
	_, other := demoConfig(t, d, "F000002")
	if strings.Contains(other.Editor, "7200") {
		t.Fatal("editor changed another connection")
	}
}
func TestManagedEditorValidatesEveryEngineAndClosedFields(t *testing.T) {
	for _, id := range []string{"F000001", "F000002", "F000003"} {
		d := NewDemo()
		in, v := demoConfig(t, d, id)
		in.Format = "json"
		var c model.Connection
		json.Unmarshal([]byte(v.Editor), &c)
		c.Name = "Updated from editor"
		b, _ := json.Marshal(c)
		in.Text = string(b)
		if _, e := d.Do(context.Background(), Request{Action: "configuration-apply", Configuration: in}); e != nil {
			t.Fatal(id, e)
		}
		in, v = demoConfig(t, d, id)
		in.Format = "json"
		in.Text = strings.TrimSuffix(v.Editor, "}") + `,"file":"/etc/shadow"}`
		if _, e := d.Do(context.Background(), Request{Action: "configuration-review", Configuration: in}); e == nil {
			t.Fatal("unknown path field accepted")
		}
		in.Text = v.Editor + "{}"
		if _, e := d.Do(context.Background(), Request{Action: "configuration-review", Configuration: in}); e == nil {
			t.Fatal("multiple objects accepted")
		}
	}
}
func TestReverseProjectionRedactsSecretsAndRejectsUnknownSyntax(t *testing.T) {
	raw := `[server]
bind_addr = "0.0.0.0:2333"
[server.transport.noise]
local_private_key = "private-value"
remote_public_key = "abc+/="
[server.services."example_tcp"]
token = "secret-value"
bind_addr = "0.0.0.0:443"
`
	text, e := redactReverse(raw)
	if e != nil {
		t.Fatal(e)
	}
	if strings.Contains(text, "private-value") || strings.Contains(text, "secret-value") || !strings.Contains(text, "REDACTED") {
		t.Fatal(text)
	}
	for _, suffix := range []string{"extra_secret = \"dont-leak\"\n", "token = \"\"\"\nprivate-multiline\n\"\"\"\n"} {
		if text, e := redactReverse(raw + suffix); e == nil || text != "" {
			t.Fatal("unsupported sensitive syntax returned", text)
		}
	}
}
func TestConfigFilesAreBoundedAndDoNotFollowLinks(t *testing.T) {
	root := t.TempDir()
	if e := os.WriteFile(filepath.Join(root, "ok.conf"), []byte("known"), 0600); e != nil {
		t.Fatal(e)
	}
	if text, e := boundedConfig(root, "ok.conf"); e != nil || text != "known" {
		t.Fatal(text, e)
	}
	os.WriteFile(filepath.Join(root, "large.conf"), []byte(strings.Repeat("x", maxConfigText+1)), 0600)
	if _, e := boundedConfig(root, "large.conf"); e == nil {
		t.Fatal("oversized file accepted")
	}
	if os.Symlink(filepath.Join(root, "ok.conf"), filepath.Join(root, "link.conf")) == nil {
		if _, e := boundedConfig(root, "link.conf"); e == nil {
			t.Fatal("file symlink followed")
		}
	}
	if os.Symlink(root, filepath.Join(root, "generated")) == nil {
		if _, e := boundedConfig(root, "generated/ok.conf"); e == nil {
			t.Fatal("directory symlink followed")
		}
	}
	if _, e := boundedConfig(root, "../outside"); e == nil {
		t.Fatal("root escape accepted")
	}
}
