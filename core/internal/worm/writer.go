package worm

import (
	"os"
)

// AppendOnlyWrite performs an append-only write for WORM-sealed evidence logs.
// Overwrite operations will fail per PRD-10.
func AppendOnlyWrite(path string, data []byte) error {
	fd, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0400)
	if err != nil {
		return err
	}
	defer fd.Close()

	_, err = fd.Write(data)
	return err
}
