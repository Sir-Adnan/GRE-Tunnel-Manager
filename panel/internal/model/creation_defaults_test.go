package model

import (
	"strings"
	"testing"
)

func TestCreationDefaultsAreExplicitAndDoNotMigrateSavedRecords(t *testing.T) {
	c := Connection{ID: "F000001", Name: "test", Engine: "haproxy", Protocol: "tcp", Bind: "0.0.0.0", Ports: "443", Strategy: "single", SNAT: "preserve", Interface: "any", Enabled: true, Targets: []Target{{IP: "198.51.100.20", Port: 443, Weight: 1}}}
	old, err := c.Rows(c.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasSuffix(old[0], "\t1") {
		t.Fatal("legacy absent options must stay v1")
	}
	created := c.WithCreationDefaults()
	if c.Options != nil || created.Options["maxconn"] != "100000" || created.Options["log"] != "off" || len(created.Options) != 3 {
		t.Fatalf("unexpected creation defaults: %#v", created.Options)
	}
	rows, err := created.Rows(c.ID)
	if err != nil {
		t.Fatal(err)
	}
	parsed, _, err := ParseState(rows[0])
	if err != nil || parsed[0].Options["maxconn"] != "100000" || parsed[0].Options["log"] != "off" {
		t.Fatalf("creation defaults lost: %v", err)
	}
	// An operator's cap, log and protocol choices take precedence; maps never alias.
	c.Options = map[string]string{"maxconn": "2048", "log": "errors", "proxy": "v2"}
	created = c.WithCreationDefaults()
	if created.Options["maxconn"] != "2048" || created.Options["log"] != "errors" || created.Options["proxy"] != "v2" {
		t.Fatal(created.Options)
	}
	created.Options["maxconn"] = "1"
	if c.Options["maxconn"] != "2048" {
		t.Fatal("mutated input options")
	}
	c.Engine = "realm"
	c.Options = nil
	if got := c.WithCreationDefaults().Options; len(got) != 1 || got["log"] != "off" {
		t.Fatal(got)
	}
	for _, engine := range []string{"nftables", "iptables"} {
		c.Engine = engine
		if len(c.WithCreationDefaults().Options) > 0 {
			t.Fatal("kernel engine got relay defaults")
		}
	}
}
