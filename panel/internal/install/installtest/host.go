// Package installtest provides a fake install.Host that records commands
// and answers like a healthy Debian host. For tests only.
package installtest

import (
	"context"
	"errors"
	"io"
	"strings"
	"testing"
)

// Host records every command; Fail and Out script the answers.
type Host struct {
	Calls  []string
	Fail   map[string]error // command-line prefix → error
	Out    map[string]string
	Absent map[string]bool
	Chowns []string
	Env    []string // environment passed to StreamEnv
	// Answer, when set, may answer a command line before the defaults.
	Answer func(line string) (out string, err error, ok bool)
}

// New returns an empty recorder.
func New() *Host {
	return &Host{Fail: map[string]error{}, Out: map[string]string{}, Absent: map[string]bool{}}
}

func (f *Host) record(name string, args []string) (string, error) {
	line := strings.TrimSpace(name + " " + strings.Join(args, " "))
	f.Calls = append(f.Calls, line)
	for prefix, e := range f.Fail {
		if strings.HasPrefix(line, prefix) {
			return "", e
		}
	}
	if f.Answer != nil {
		if o, e, ok := f.Answer(line); ok {
			return o, e
		}
	}
	if o, ok := f.Out[line]; ok {
		return o, nil
	}
	switch line {
	case "getent group grepanel":
		return "grepanel:x:123:", nil
	case "getent passwd grepanel":
		return "grepanel:x:123:123::/nonexistent:/usr/sbin/nologin", nil
	case "getent group greagent":
		return "greagent:x:124:", nil
	case "getent passwd greagent":
		return "greagent:x:124:124::/nonexistent:/usr/sbin/nologin", nil
	}
	if strings.HasPrefix(line, "systemctl is-active") {
		return "active", nil
	}
	if strings.HasPrefix(line, "systemctl cat") {
		return "", errors.New("not found")
	}
	if strings.HasSuffix(line, "-version") || strings.HasSuffix(line, "nodes protocol") {
		return "1", nil
	}
	return "", nil
}

func (f *Host) Run(_ context.Context, name string, args ...string) (string, error) {
	return f.record(name, args)
}
func (f *Host) Stream(_ context.Context, name string, args ...string) error {
	_, e := f.record(name, args)
	return e
}
func (f *Host) StreamEnv(_ context.Context, env []string, name string, args ...string) error {
	f.Env = append(f.Env, env...)
	_, e := f.record(name, args)
	return e
}
func (f *Host) LookPath(name string) error {
	if f.Absent[name] {
		return errors.New("missing")
	}
	return nil
}
func (f *Host) Chown(path string, uid, gid int) error {
	f.Chowns = append(f.Chowns, path)
	return nil
}
func (f *Host) Lock(string) (io.Closer, error) { return io.NopCloser(nil), nil }

func (f *Host) Log() string { return strings.Join(f.Calls, "\n") }

func (f *Host) Index(t *testing.T, prefix string) int {
	t.Helper()
	for i, c := range f.Calls {
		if strings.HasPrefix(c, prefix) {
			return i
		}
	}
	t.Fatalf("no call %q in:\n%s", prefix, f.Log())
	return -1
}
