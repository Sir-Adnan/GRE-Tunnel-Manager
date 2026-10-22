package control

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"time"
)

const ManagerPath = "/usr/local/lib/gre-manager/manager.sh"

type Runner interface {
	Run(context.Context, string, []string, string) (string, error)
}
type Executor struct{}
type cappedBuffer struct{ bytes.Buffer }

func (b *cappedBuffer) Write(p []byte) (int, error) {
	n := len(p)
	left := 262144 - b.Len()
	if left > 0 {
		if left > n {
			left = n
		}
		b.Buffer.Write(p[:left])
	}
	return n, nil
}
func (Executor) Run(ctx context.Context, name string, args []string, input string) (string, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	commandGroup(cmd)
	cmd.Env = []string{"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin", "LANG=C.UTF-8", "LC_ALL=C.UTF-8", "GTM_SERVER_LOOKUP=0", "DEBIAN_FRONTEND=noninteractive", "TERM=dumb", "NO_COLOR=1"}
	cmd.Stdin = bytes.NewBufferString(input)
	out := &cappedBuffer{}
	cmd.Stdout = out
	cmd.Stderr = out
	cmd.WaitDelay = 2 * time.Second
	e := cmd.Run()
	if e != nil {
		return out.String(), fmt.Errorf("operation failed: %w", e)
	}
	return out.String(), nil
}
func invoke(ctx context.Context, r Runner, action, input string, args ...string) (string, error) {
	return r.Run(ctx, "/bin/bash", append([]string{ManagerPath, "--api", action}, args...), input)
}
