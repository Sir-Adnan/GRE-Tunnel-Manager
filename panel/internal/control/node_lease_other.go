//go:build !linux

package control

import (
	"errors"
	"os"
)

func nodeLease(string) (*os.File, error) {
	return nil, errors.New("privileged node broker requires Linux")
}
