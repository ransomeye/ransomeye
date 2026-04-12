//go:build windows

package crypto

import "os"

func validateRootOwner(os.FileInfo) error {
	return nil
}
