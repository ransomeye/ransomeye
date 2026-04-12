package signature

import (
	"fmt"
	"time"

	"ransomeye/core/internal/keys"
	"ransomeye/core/internal/lifecycle"
)

func VerifyWithLifecycle(meta keys.Metadata, verify func() bool, now time.Time) error {
	engine := lifecycle.NewEngine()
	if err := engine.ValidateRuntimeOperation(meta, "verify", now); err != nil {
		return err
	}
	switch meta.Status {
	case keys.StatusActive, keys.StatusVerificationOnly:
	default:
		return fmt.Errorf("key status not allowed for verification")
	}
	if !verify() {
		return fmt.Errorf("signature verification failed")
	}
	return nil
}

func SignWithLifecycle(meta keys.Metadata, sign func() ([]byte, error), now time.Time) ([]byte, error) {
	engine := lifecycle.NewEngine()
	if err := engine.ValidateRuntimeOperation(meta, "sign", now); err != nil {
		return nil, err
	}
	return sign()
}
