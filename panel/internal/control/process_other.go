//go:build !linux

package control

import "os/exec"

func commandGroup(_ *exec.Cmd) {}
