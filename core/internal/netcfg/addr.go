package netcfg

import (
	"errors"
	"fmt"
	"os"
	"strings"
)

const (
	LoopbackHost = "127.0.0.1"
)

func validateLoopback(addr string) error {
	if addr == LoopbackHost {
		return nil
	}
	if !strings.HasPrefix(addr, LoopbackHost+":") {
		return fmt.Errorf("NON_LOOPBACK_REJECTED")
	}
	return nil
}

func ValidateLoopback(addr string) error {
	return validateLoopback(strings.TrimSpace(addr))
}

func IsLoopbackHost(host string) bool {
	return strings.TrimSpace(host) == LoopbackHost
}

func LoadLoopbackAddr(key, emptyCode string) (string, error) {
	addr := strings.TrimSpace(os.Getenv(key))
	if addr == "" {
		return "", errors.New(emptyCode)
	}
	if err := validateLoopback(addr); err != nil {
		return "", err
	}
	return addr, nil
}

// LoadOptionalLoopbackAddr returns ("", nil) when the env var is unset; otherwise it must be loopback.
func LoadOptionalLoopbackAddr(key string) (string, error) {
	addr := strings.TrimSpace(os.Getenv(key))
	if addr == "" {
		return "", nil
	}
	if err := validateLoopback(addr); err != nil {
		return "", fmt.Errorf("%s: %w", key, err)
	}
	return addr, nil
}

func LoadLoopbackHost(key, emptyCode string) (string, error) {
	host := strings.TrimSpace(os.Getenv(key))
	if host == "" {
		return "", errors.New(emptyCode)
	}
	if !IsLoopbackHost(host) {
		return "", fmt.Errorf("NON_LOOPBACK_REJECTED")
	}
	return host, nil
}
