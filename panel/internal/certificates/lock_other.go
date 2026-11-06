//go:build !linux

package certificates

import (
	"errors"
	"os"
)

func Lock(string) (*os.File, error) { return nil, errors.New("certificate publication requires Linux") }
