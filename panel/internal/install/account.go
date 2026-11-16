package install

import (
	"context"
	"errors"
	"strconv"
	"strings"
)

// Account is a restricted system account owned by the installer.
type Account struct {
	Name     string
	UID, GID int
}

// ensureAccount creates or validates a system account that cannot log in.
// An existing account that looks like a person's is never taken over.
func ensureAccount(ctx context.Context, h Host, name string) (Account, error) {
	group, e := h.Run(ctx, "getent", "group", name)
	if e != nil || group == "" {
		if _, e = h.Run(ctx, "groupadd", "--system", name); e != nil {
			return Account{}, e
		}
		if group, e = h.Run(ctx, "getent", "group", name); e != nil {
			return Account{}, e
		}
	}
	fields := strings.Split(group, ":")
	if len(fields) != 4 {
		return Account{}, errors.New("unexpected group entry for " + name)
	}
	if members := fields[3]; members != "" && members != name {
		return Account{}, errors.New("the " + name + " group has other members; inspect it before installing")
	}
	passwd, e := h.Run(ctx, "getent", "passwd", name)
	if e != nil || passwd == "" {
		if _, e = h.Run(ctx, "useradd", "--system", "--gid", name, "--home-dir", "/nonexistent", "--shell", "/usr/sbin/nologin", name); e != nil {
			return Account{}, e
		}
		if passwd, e = h.Run(ctx, "getent", "passwd", name); e != nil {
			return Account{}, e
		}
	}
	return parseAccount(name, passwd)
}

// lookupAccount validates an existing account without creating it.
func lookupAccount(ctx context.Context, h Host, name string) (Account, error) {
	passwd, e := h.Run(ctx, "getent", "passwd", name)
	if e != nil || passwd == "" {
		return Account{}, errors.New("the " + name + " account does not exist")
	}
	return parseAccount(name, passwd)
}

func parseAccount(name, passwd string) (Account, error) {
	fields := strings.Split(passwd, ":")
	if len(fields) != 7 {
		return Account{}, errors.New("unexpected account entry for " + name)
	}
	uid, e1 := strconv.Atoi(fields[2])
	gid, e2 := strconv.Atoi(fields[3])
	shell := fields[6]
	if e1 != nil || e2 != nil || uid <= 0 || uid >= 1000 || (shell != "/usr/sbin/nologin" && shell != "/bin/false") {
		return Account{}, errors.New(name + " already belongs to an unrelated account; installation stopped")
	}
	return Account{Name: name, UID: uid, GID: gid}, nil
}
