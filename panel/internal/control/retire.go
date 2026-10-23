package control

// Root-installer helpers, deliberately absent from the broker action vocabulary.
import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

func (x *NodeExecutor) CheckRetirement() error {
	entries, e := os.ReadDir(x.Directory)
	if os.IsNotExist(e) {
		return nil
	}
	if e != nil {
		return e
	}
	lease, e := nodeLease(filepath.Join(x.Directory, "broker.lock"))
	if e != nil {
		return errors.New("operation broker is still running")
	}
	defer lease.Close()
	for _, entry := range entries {
		if entry.Name() == "broker.lock" {
			continue
		}
		id := strings.TrimSuffix(entry.Name(), ".json")
		if entry.Type() != 0 || !strings.HasSuffix(entry.Name(), ".json") || !taskID.MatchString(id) {
			return errors.New("unrecognized operation journal entry; inspect before removal")
		}
		r, e := x.load(id)
		if e != nil {
			return errors.New("operation receipt is invalid; inspect before removal")
		}
		if !oneOf(r.Result.State, "prepared", "committed", "rolled_back", "failed") {
			return fmt.Errorf("operation %s requires confirmation or recovery before removal", id)
		}
	}
	return nil
}

// RetireMetrics removes only the panel's counter table. Failed inventory is not
// treated as an absent table. No host rules or conntrack entries are flushed.
func RetireMetrics(ctx context.Context, runner Runner) error {
	out, e := runner.Run(ctx, "nft", []string{"-j", "list", "tables"}, "")
	if e != nil {
		return errors.New("cannot inspect nftables accounting; retain panel data and inspect locally")
	}
	var data struct {
		NFTables []struct {
			Table *struct {
				Family string `json:"family"`
				Name   string `json:"name"`
			} `json:"table"`
		} `json:"nftables"`
	}
	if json.Unmarshal([]byte(out), &data) != nil || data.NFTables == nil {
		return errors.New("invalid nftables table inventory")
	}
	for _, item := range data.NFTables {
		if item.Table == nil || item.Table.Family != "inet" || item.Table.Name != metricsTable {
			continue
		}
		batch := "delete table inet " + metricsTable + "\n"
		if _, e = runner.Run(ctx, "nft", []string{"--check", "-f", "-"}, batch); e != nil {
			return errors.New("accounting removal validation failed")
		}
		if _, e = runner.Run(ctx, "nft", []string{"-f", "-"}, batch); e != nil {
			return errors.New("accounting removal failed")
		}
		return nil
	}
	return nil
}
