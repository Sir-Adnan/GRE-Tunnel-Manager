//go:build !linux && !windows

package nodes

import (
	"errors"
	"os"
)

func lockFile(*os.File) error {
	return errors.New("Node Controller requires Linux (or Windows development)")
}
