package control

import "os/exec"

func lookupBinary(name string) (string, error) { return exec.LookPath(name) }
