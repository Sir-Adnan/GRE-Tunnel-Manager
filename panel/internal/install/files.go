package install

import (
	"bytes"
	"errors"
	"io"
	"os"
	"path/filepath"
)

// writeFileAtomic replaces path with data through a temporary file in the
// same directory, so readers see either the old or the new content.
func writeFileAtomic(path string, data []byte, mode os.FileMode) error {
	return replaceFile(path, mode, func(w io.Writer) error {
		_, e := w.Write(data)
		return e
	})
}

// copyFileAtomic installs src at dst with mode. A running executable at dst
// keeps working because the old inode is only unlinked by the rename.
func copyFileAtomic(src, dst string, mode os.FileMode) error {
	in, e := os.Open(src)
	if e != nil {
		return e
	}
	defer in.Close()
	return replaceFile(dst, mode, func(w io.Writer) error {
		_, e := io.Copy(w, in)
		return e
	})
}

func replaceFile(path string, mode os.FileMode, fill func(io.Writer) error) error {
	if info, e := os.Lstat(path); e == nil && !info.Mode().IsRegular() {
		return errors.New("refusing to replace a non-regular file: " + path)
	}
	f, e := os.CreateTemp(filepath.Dir(path), ".gtm-*")
	if e != nil {
		return e
	}
	name := f.Name()
	defer os.Remove(name)
	if e = fill(f); e == nil {
		e = f.Chmod(mode)
	}
	if e == nil {
		e = f.Sync()
	}
	if ce := f.Close(); e == nil {
		e = ce
	}
	if e != nil {
		return e
	}
	return os.Rename(name, path)
}

// sameFile reports whether two paths hold identical bytes (or are one file).
func sameFile(a, b string) bool {
	ia, ea := os.Stat(a)
	ib, eb := os.Stat(b)
	if ea != nil || eb != nil {
		return false
	}
	if os.SameFile(ia, ib) {
		return true
	}
	if ia.Size() != ib.Size() {
		return false
	}
	da, ea := os.ReadFile(a)
	db, eb := os.ReadFile(b)
	return ea == nil && eb == nil && bytes.Equal(da, db)
}

// regular reports an existing regular file that is not a symbolic link.
func regular(path string) bool {
	info, e := os.Lstat(path)
	return e == nil && info.Mode().IsRegular()
}

// ensureDir creates path (and parents) and applies mode and ownership.
func ensureDir(h Host, path string, mode os.FileMode, uid, gid int) error {
	if info, e := os.Lstat(path); e == nil && !info.IsDir() {
		return errors.New("expected a directory: " + path)
	}
	if e := os.MkdirAll(path, mode); e != nil {
		return e
	}
	if e := os.Chmod(path, mode); e != nil {
		return e
	}
	return h.Chown(path, uid, gid)
}
