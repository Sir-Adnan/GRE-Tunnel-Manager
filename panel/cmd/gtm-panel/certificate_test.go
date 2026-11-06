package main

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/Sir-Adnan/GRE-Tunnel-Manager/panel/internal/config"
)

func TestCertificatePublicationAndActivationFailureRestoreTheExactPreviousPair(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	c, _, e := config.New(path, "127.0.0.1", 0, "admin", "test-password-12345", nil)
	if e != nil {
		t.Fatal(e)
	}
	oldConfig, e := os.ReadFile(path)
	if e != nil {
		t.Fatal(e)
	}
	newConfig := c
	newConfig.PublicHost = "panel.example"
	attempts := 0
	e = publishCertificate(path, c, newConfig, []byte("first bundle"), func() error {
		attempts++
		if attempts == 1 {
			return errors.New("simulated service failure")
		}
		return nil
	})
	if e == nil || attempts != 2 {
		t.Fatal(e, attempts)
	}
	after, e := os.ReadFile(path)
	if e != nil || string(after) != string(oldConfig) {
		t.Fatal("config not restored", e)
	}
	bundle := filepath.Join(filepath.Dir(path), "https.pem")
	if _, e = os.Stat(bundle); !os.IsNotExist(e) {
		t.Fatal("new bundle retained after failed first install", e)
	}
	if e = publishCertificate(path, c, newConfig, []byte("first bundle"), nil); e != nil {
		t.Fatal(e)
	}
	installed, e := config.Load(path)
	if e != nil || installed.Certificate != bundle || installed.PrivateKey != bundle {
		t.Fatal(installed, e)
	}
	info, e := os.Stat(bundle)
	if e != nil || (runtime.GOOS != "windows" && info.Mode().Perm() != 0640) {
		t.Fatal(info, e)
	}
	attempts = 0
	e = publishCertificate(path, installed, installed, []byte("second bundle"), func() error {
		attempts++
		if attempts == 1 {
			return errors.New("simulated reload failure")
		}
		return nil
	})
	if e == nil {
		t.Fatal("reload failure hidden")
	}
	data, e := os.ReadFile(bundle)
	if e != nil || string(data) != "first bundle" {
		t.Fatal("previous bundle not restored", string(data), e)
	}
}
