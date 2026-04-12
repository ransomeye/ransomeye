//go:build !windows

package crypto

import (
	"fmt"
	"os"
	"syscall"
)

func validateRootOwner(fi os.FileInfo) error {
	stat, ok := fi.Sys().(*syscall.Stat_t)
	if !ok || stat == nil {
		return fmt.Errorf("WORM signing key ownership unavailable")
	}
	if stat.Uid != 0 {
		return fmt.Errorf("WORM signing key must be owned by root")
	}
	return nil
}
