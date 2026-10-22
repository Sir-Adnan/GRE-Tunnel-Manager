package config

import (
	"os"
	"syscall"
)

func preserveOwner(file *os.File, path string) error {
	info, e := os.Stat(path)
	if os.IsNotExist(e) {
		return nil
	}
	if e != nil {
		return e
	}
	if stat, ok := info.Sys().(*syscall.Stat_t); ok && os.Geteuid() == 0 {
		return file.Chown(int(stat.Uid), int(stat.Gid))
	}
	return nil
}
