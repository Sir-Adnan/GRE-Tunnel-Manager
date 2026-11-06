package control

import (
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
)

// CheckPanelRetirement runs only after the broker has stopped. Removal must not
// discard a pending forwarding rollback or optimization recovery watch.
func CheckPanelRetirement(directory string) error {
	for _, name := range []string{"safe-change.json", "optimize-watch.json"} {
		path := filepath.Join(directory, name)
		info, e := os.Lstat(path)
		if os.IsNotExist(e) {
			continue
		}
		if e != nil {
			return e
		}
		if !info.Mode().IsRegular() || info.Size() > 1048576 {
			return errors.New("unsafe panel recovery record; inspect before removal")
		}
		f, e := os.Open(path)
		if e != nil {
			return e
		}
		data, e := io.ReadAll(io.LimitReader(f, 1048577))
		_ = f.Close()
		if e != nil || len(data) > 1048576 {
			return errors.New("panel recovery record cannot be read safely")
		}
		if name == "safe-change.json" {
			var s SafeChange
			if json.Unmarshal(data, &s) != nil || !pointName.MatchString(s.Point) || !digestValid(s.Revision) {
				return errors.New("invalid safe-apply record; inspect before removal")
			}
			return errors.New("finish, keep or recover the pending safe-apply change before removing the panel")
		}
		var w OptimizeWatch
		if json.Unmarshal(data, &w) != nil || w.Started.IsZero() {
			return errors.New("invalid optimization recovery record; inspect before removal")
		}
		if w.Result == WatchActive {
			return errors.New("finish the active optimization recovery watch before removing the panel")
		}
	}
	return nil
}
