//go:build !linux

package config

import "os"

func preserveOwner(_ *os.File, _ string) error { return nil }
