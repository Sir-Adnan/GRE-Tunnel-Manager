package tui

import (
	"bytes"
	"fmt"
	"strings"
	"testing"
)

func TestDarkTerminalNeverQueries(t *testing.T) {
	env := func(m map[string]string) func(string) string { return func(k string) string { return m[k] } }
	for _, c := range []struct {
		vars map[string]string
		dark bool
	}{
		{map[string]string{}, true},
		{map[string]string{"GTM_THEME": "light"}, false},
		{map[string]string{"GTM_THEME": "dark", "COLORFGBG": "0;15"}, true},
		{map[string]string{"COLORFGBG": "0;15"}, false},
		{map[string]string{"COLORFGBG": "15;default;0"}, true},
		{map[string]string{"COLORFGBG": "15;8"}, true},
		{map[string]string{"COLORFGBG": "junk"}, true},
	} {
		if got := darkTerminal(env(c.vars)); got != c.dark {
			t.Errorf("%v: dark=%v, want %v", c.vars, got, c.dark)
		}
	}
}

func TestCleanKeepsTheVisibleLine(t *testing.T) {
	for in, want := range map[string]string{
		"\x1b[32mGet:1 http://archive\x1b[0m": "Get:1 http://archive",
		"Reading 50%\rReading 100%\r":         "Reading 100%",
		"  done\t ":                           "done",
		"\x07bell":                            "bell",
	} {
		if got := clean(in); got != want {
			t.Errorf("clean(%q) = %q, want %q", in, got, want)
		}
	}
}

// live builds a UI that animates into a buffer. Plain strips escape
// sequences, so the buffer holds the text a terminal would have shown.
func live() (*UI, *bytes.Buffer) {
	out := &bytes.Buffer{}
	u := Plain(strings.NewReader(""), out)
	u.Interactive = true
	return u, out
}

func TestLiveStepHidesOutputUntilAFailure(t *testing.T) {
	u, out := live()
	u.Plan(3)
	u.Step("Installing engines")
	if u.Log().(logWriter).File() != nil {
		t.Fatal("a live step must not hand the terminal to a command")
	}
	fmt.Fprint(u.Log(), "Get:1 one\nGet:2 two\npartial")
	u.Warn("Engine installation failed")
	text := out.String()
	for _, want := range []string{"Installing engines", "1/3", "! Engine installation failed", "│ Get:1 one", "│ Get:2 two", "│ partial"} {
		if !strings.Contains(text, want) {
			t.Errorf("missing %q in:\n%s", want, text)
		}
	}
	u.Step("Starting the panel")
	fmt.Fprint(u.Log(), "quiet output\n")
	u.Done("Panel is running")
	text = out.String()
	if !strings.Contains(text, "✓ Panel is running") || strings.Contains(text, "│ quiet output") {
		t.Errorf("a successful step keeps its output hidden:\n%s", text)
	}
	if !strings.Contains(text, "2/3") {
		t.Errorf("the bar counts finished steps:\n%s", text)
	}
	before := out.Len()
	fmt.Fprint(u.Log(), "after\n")
	if !strings.Contains(out.String()[before:], "after") {
		t.Error("output between steps passes through")
	}
}

func TestStepSettlesBeforeTheNextOne(t *testing.T) {
	u, out := live()
	u.Step("Detecting")
	u.Settle()
	u.Settle()
	if n := strings.Count(out.String(), "✓ Detecting"); n != 1 {
		t.Fatalf("settled %d times:\n%s", n, out.String())
	}
	u.Step("Requesting a certificate")
	u.Fail(fmt.Errorf("no certificate"))
	if !strings.Contains(out.String(), "✗ Requesting a certificate") || !strings.Contains(out.String(), "✗ No certificate") {
		t.Errorf("a failure ends the live step:\n%s", out.String())
	}
}

func TestPlainOutputIsUnchanged(t *testing.T) {
	out := &bytes.Buffer{}
	u := Plain(strings.NewReader(""), out)
	u.Step("Starting")
	fmt.Fprint(u.Log(), "raw\n")
	u.Done("Running")
	if got := out.String(); got != "  › Starting\nraw\n  ✓ Running\n" {
		t.Errorf("plain output = %q", got)
	}
}
