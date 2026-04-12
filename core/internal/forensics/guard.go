package forensics

import "fmt"

type Event struct {
	WormSignature []byte
	Hash          string
}

func MustBeSealed(event *Event) error {
	if event == nil || len(event.WormSignature) == 0 || event.Hash == "" {
		return fmt.Errorf("UNSEALED_DATA_REJECTED")
	}
	return nil
}
