package config

import (
	"errors"
	"os"
	"path/filepath"
)

// SaveMaterial publishes one complete PEM bundle with the configuration's
// ownership. The grepanel group can read it without accessing the ACME account.
func SaveMaterial(path, ownerPath string, data []byte) error {
	if info, e := os.Lstat(path); e == nil && !info.Mode().IsRegular() {
		return errors.New("managed TLS bundle must be a regular file")
	} else if e != nil && !os.IsNotExist(e) {
		return e
	}
	f, e := os.CreateTemp(filepath.Dir(path), ".tls-*")
	if e != nil {
		return e
	}
	defer os.Remove(f.Name())
	if e = preserveOwner(f, ownerPath); e == nil {
		e = f.Chmod(0640)
	}
	if e == nil {
		_, e = f.Write(data)
	}
	if e == nil {
		e = f.Sync()
	}
	closeError := f.Close()
	if e == nil {
		e = closeError
	}
	if e == nil {
		e = os.Rename(f.Name(), path)
	}
	return e
}
