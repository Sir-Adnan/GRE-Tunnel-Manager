package control

import (
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"

	"github.com/Sir-Adnan/GRE-Tunnel-Manager/panel/internal/model"
)

type ResourceName struct {
	ID       string `json:"id"`
	Revision string `json:"revision"`
	Name     string `json:"name"`
}

func resourceNameValid(s string) bool { // Match the shared Bash data contract.
	if len(s) < 1 || len(s) > 40 {
		return false
	}
	for i, c := range s {
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') {
			continue
		}
		if i == 0 || !strings.ContainsRune("_. -", c) {
			return false
		}
	}
	return true
}
func (m *Manager) resourceNames() (map[string]string, error) {
	p := filepath.Join(m.ConfigDir, "resource-names.tsv")
	result := map[string]string{}
	stat, e := os.Lstat(p)
	if os.IsNotExist(e) {
		return result, nil
	}
	if e != nil {
		return nil, e
	}
	if !stat.Mode().IsRegular() || stat.Size() > 131072 {
		return nil, errors.New("invalid resource metadata file")
	}
	data, e := os.ReadFile(p)
	if e != nil {
		return nil, e
	}
	for _, line := range strings.Split(strings.TrimSuffix(string(data), "\n"), "\n") {
		if line == "" {
			continue
		}
		f := strings.Split(line, "\t")
		if len(f) != 3 || !ServiceOK(f[0]) || (!greID.MatchString(f[0]) && !reverseID.MatchString(f[0])) || !digestValid(f[1]) || !resourceNameValid(f[2]) || result[f[0]] != "" {
			return nil, errors.New("invalid resource metadata")
		}
		result[f[0]] = line
		if len(result) > 512 {
			return nil, errors.New("too many resource names")
		}
	}
	return result, nil
}
func digestValid(s string) bool {
	if len(s) != 64 {
		return false
	}
	_, e := hex.DecodeString(s)
	return e == nil && s == strings.ToLower(s)
}
func applyResourceName(resource *Resource, unit []byte, row string) {
	unitHash := model.Revision(string(unit))
	rowHash := "-"
	if row != "" {
		rowHash = model.Revision(row)
		f := strings.Split(row, "\t")
		if len(f) == 3 && f[1] == unitHash {
			resource.Name = f[2]
		}
	}
	resource.Revision = unitHash + ":" + rowHash
}
