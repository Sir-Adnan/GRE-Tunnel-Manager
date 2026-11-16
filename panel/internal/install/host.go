// Package install owns the server-side lifecycle of the panel and the Agent:
// accounts, files, systemd units, updates with rollback, and removal. It has
// no user interface; callers pass a Reporter and decide what to ask.
//
// Every path is resolved through Layout and every command goes through Host,
// so tests run the real logic against a temporary root and a fake system.
package install

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/Sir-Adnan/GRE-Tunnel-Manager/panel/internal/certificates"
)

// Canonical server paths. Units and shims always name these, never a test root.
const (
	Binary     = "/usr/local/bin/gtm-panel"
	Command    = "/usr/local/bin/gtm"
	Shortcut   = "/usr/local/bin/igre"
	LibDir     = "/usr/local/lib/gre-manager"
	Engine     = LibDir + "/manager.sh"
	ConfigDir  = "/etc/gre-manager-panel"
	ConfigFile = ConfigDir + "/config.json"
	// TwoFactorFile turns two-factor sign-in on (see package twofactor).
	TwoFactorFile = ConfigDir + "/two-factor.json"
	StateDir      = "/var/lib/gre-manager-panel"
	UnitDir       = "/etc/systemd/system"
	LockFile      = "/run/gre-manager-panel-install.lock"
)

// Layout maps canonical paths below an optional root (tests only).
type Layout struct{ Root string }

// Path returns where a canonical path lives on this host.
func (l Layout) Path(p string) string {
	if l.Root == "" {
		return p
	}
	return filepath.Join(l.Root, p)
}

// Unit returns the path of a systemd unit file.
func (l Layout) Unit(name string) string { return l.Path(UnitDir + "/" + name) }

func (l Layout) exists(p string) bool {
	_, e := os.Lstat(l.Path(p))
	return e == nil
}

// Host is the only way this package touches the running system besides files.
type Host interface {
	// Run executes a command and returns trimmed standard output. A failed
	// command returns its trimmed standard error inside the error.
	Run(ctx context.Context, name string, args ...string) (string, error)
	// Stream executes a command attached to the caller's terminal.
	Stream(ctx context.Context, name string, args ...string) error
	// StreamEnv is Stream with extra environment entries (never in argv).
	StreamEnv(ctx context.Context, env []string, name string, args ...string) error
	LookPath(name string) error
	Chown(path string, uid, gid int) error
	Lock(path string) (io.Closer, error)
}

// System is the real Host.
type System struct {
	Stdin          io.Reader
	Stdout, Stderr io.Writer
}

func (s System) Run(ctx context.Context, name string, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	var out, errOut bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errOut
	e := cmd.Run()
	if e != nil {
		detail := strings.TrimSpace(errOut.String())
		if len(detail) > 600 {
			detail = detail[len(detail)-600:]
		}
		if detail != "" {
			e = fmt.Errorf("%s: %w: %s", name, e, detail)
		} else {
			e = fmt.Errorf("%s: %w", name, e)
		}
	}
	return strings.TrimSpace(out.String()), e
}

func (s System) Stream(ctx context.Context, name string, args ...string) error {
	return s.StreamEnv(ctx, nil, name, args...)
}

func (s System) StreamEnv(ctx context.Context, env []string, name string, args ...string) error {
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = s.Stdin, s.Stdout, s.Stderr
	if env != nil {
		cmd.Env = append(os.Environ(), env...)
	}
	return cmd.Run()
}

func (System) LookPath(name string) error {
	_, e := exec.LookPath(name)
	return e
}

func (System) Chown(path string, uid, gid int) error { return os.Lchown(path, uid, gid) }

func (System) Lock(path string) (io.Closer, error) {
	f, e := certificates.Lock(path)
	if e != nil {
		return nil, errors.New("another panel or Agent installation is running; try again when it finishes")
	}
	return f, nil
}

// Reporter receives progress. Implementations decide how it looks.
type Reporter interface {
	Step(format string, args ...any) // work begins
	Done(format string, args ...any) // work succeeded
	Warn(format string, args ...any) // attention, not fatal
	Note(format string, args ...any) // secondary detail
}

// Quiet discards progress.
type Quiet struct{}

func (Quiet) Step(string, ...any) {}
func (Quiet) Done(string, ...any) {}
func (Quiet) Warn(string, ...any) {}
func (Quiet) Note(string, ...any) {}
