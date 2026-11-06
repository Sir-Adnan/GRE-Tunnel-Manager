package control

import (
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/Sir-Adnan/GRE-Tunnel-Manager/panel/internal/model"
)

func backupDomainNames(connections []model.Connection) map[string]bool {
	used := map[string]bool{}
	for _, c := range connections {
		for _, t := range c.Targets {
			if t.IsHost() {
				used[t.IP] = true
			}
		}
	}
	return used
}

func validateBackupPolicies(policies []DNSPolicy, connections []model.Connection) error {
	used, seen := backupDomainNames(connections), map[string]bool{}
	for _, p := range policies {
		if !p.valid() || !used[p.Name] || seen[p.Name] {
			return errors.New("invalid, duplicate or unrelated DNS policy in backup")
		}
		seen[p.Name] = true
	}
	return nil
}

func (m *Manager) backupDNSPolicies(connections []model.Connection) ([]DNSPolicy, error) {
	used := backupDomainNames(connections)
	if len(used) == 0 {
		return nil, nil
	}
	path := filepath.Join(m.ConfigDir, "dns-policy.tsv")
	info, e := os.Lstat(path)
	if os.IsNotExist(e) {
		return nil, nil
	}
	if e != nil {
		return nil, e
	}
	if !info.Mode().IsRegular() {
		return nil, errors.New("DNS policy must be a regular file")
	}
	raw, e := boundedConfig(m.ConfigDir, "dns-policy.tsv")
	if e != nil {
		return nil, e
	}
	policies := []DNSPolicy{}
	seen := map[string]bool{}
	for _, line := range strings.Split(strings.TrimSpace(raw), "\n") {
		if line == "" {
			continue
		}
		fields := strings.Split(line, "\t")
		if len(fields) != 3 {
			return nil, errors.New("invalid saved DNS policy")
		}
		every, e := strconv.Atoi(fields[1])
		p := DNSPolicy{Name: fields[0], Every: every, Mode: fields[2]}
		if e != nil || !p.valid() || seen[p.Name] {
			return nil, errors.New("invalid or duplicate saved DNS policy")
		}
		seen[p.Name] = true
		if used[p.Name] {
			policies = append(policies, p)
		}
	}
	if len(policies) > 128 {
		return nil, errors.New("backup supports at most 128 DNS policies")
	}
	return policies, nil
}
