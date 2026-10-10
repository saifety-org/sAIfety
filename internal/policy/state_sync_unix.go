//go:build !windows

package policy

import (
	"errors"
	"os"
)

func syncBlocklistDirectory(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	return errors.Join(f.Sync(), f.Close())
}
