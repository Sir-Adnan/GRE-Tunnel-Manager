package install

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"strconv"

	"github.com/Sir-Adnan/GRE-Tunnel-Manager/panel/internal/config"
	"golang.org/x/crypto/bcrypt"
)

// ChangePort moves the panel listener and restarts only the public panel.
// If the panel does not come back, the previous port is restored.
func (in *Installer) ChangePort(ctx context.Context, port int) (config.Config, error) {
	r, l := in.report(), in.Layout
	if port < 1 || port > 65535 {
		return config.Config{}, errors.New("port must be 1–65535")
	}
	lock, e := in.Host.Lock(l.Path(LockFile))
	if e != nil {
		return config.Config{}, e
	}
	defer lock.Close()
	path := l.Path(ConfigFile)
	old, e := config.Load(path)
	if e != nil {
		return old, e
	}
	host, current, e := net.SplitHostPort(old.Listen)
	if e != nil {
		return old, e
	}
	if current == strconv.Itoa(port) {
		return old, errors.New("the panel already uses this port")
	}
	listener, e := net.Listen("tcp", net.JoinHostPort(host, strconv.Itoa(port)))
	if e != nil {
		return old, fmt.Errorf("port %d is not available: %w", port, e)
	}
	listener.Close()
	next := old
	next.Listen = net.JoinHostPort(host, strconv.Itoa(port))
	if e = in.applyConfig(ctx, path, old, next); e != nil {
		return old, e
	}
	r.Done("Panel moved to port %d", port)
	return next, nil
}

// SetCredentials replaces the password (and optionally the username) and
// restarts the panel, which signs out every session.
func (in *Installer) SetCredentials(ctx context.Context, username, password string) (config.Config, error) {
	r, l := in.report(), in.Layout
	if e := config.ValidatePassword(password); e != nil {
		return config.Config{}, e
	}
	if username != "" && !config.UserPattern.MatchString(username) {
		return config.Config{}, errors.New("username must be 3–40 ASCII letters, digits, dots, dashes or underscores")
	}
	lock, e := in.Host.Lock(l.Path(LockFile))
	if e != nil {
		return config.Config{}, e
	}
	defer lock.Close()
	path := l.Path(ConfigFile)
	old, e := config.Load(path)
	if e != nil {
		return old, e
	}
	hash, e := bcrypt.GenerateFromPassword([]byte(password), 12)
	if e != nil {
		return old, e
	}
	next := old
	next.PasswordHash = string(hash)
	if username != "" {
		next.Username = username
	}
	if e = in.applyConfig(ctx, path, old, next); e != nil {
		return old, e
	}
	r.Done("Login updated; existing sessions were signed out")
	return next, nil
}

// applyConfig saves next, restarts the panel and returns to old on failure.
func (in *Installer) applyConfig(ctx context.Context, path string, old, next config.Config) error {
	if e := next.Validate(); e != nil {
		return e
	}
	if e := config.Save(path, next, 0640); e != nil {
		return e
	}
	if !regular(in.Layout.Unit(PanelUnit)) {
		return nil
	}
	_, e := in.Host.Run(ctx, "systemctl", "restart", PanelUnit)
	if e == nil {
		e = in.waitHealthy(ctx, next)
	}
	if e == nil {
		return nil
	}
	in.report().Warn("The panel did not start with the change; restoring the previous settings")
	if se := config.Save(path, old, 0640); se != nil {
		return fmt.Errorf("%w; restoring the configuration also failed: %v", e, se)
	}
	_, _ = in.Host.Run(ctx, "systemctl", "restart", PanelUnit)
	return fmt.Errorf("change reverted: %w", e)
}

// DisableTwoFactor removes the two-factor settings and restarts the panel,
// which signs out every session. It is the recovery path when the phone and
// the recovery codes are lost.
func (in *Installer) DisableTwoFactor(ctx context.Context) (bool, error) {
	l := in.Layout
	lock, e := in.Host.Lock(l.Path(LockFile))
	if e != nil {
		return false, e
	}
	defer lock.Close()
	path := l.Path(TwoFactorFile)
	if _, e := os.Lstat(path); errors.Is(e, os.ErrNotExist) {
		return false, nil
	}
	if e := os.Remove(path); e != nil {
		return false, e
	}
	if regular(l.Unit(PanelUnit)) {
		if _, e := in.Host.Run(ctx, "systemctl", "try-restart", PanelUnit); e != nil {
			return true, fmt.Errorf("two-factor sign-in is off, but the panel did not restart: %w", e)
		}
	}
	in.report().Done("Two-factor sign-in is off; every session was signed out")
	return true, nil
}
