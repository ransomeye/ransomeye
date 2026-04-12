package pipeline

import "errors"

var (
	ErrSequenceViolation = errors.New("sequence violation")
	ErrInvalidEvent      = errors.New("invalid event")
	ErrQueueFull         = errors.New("queue full")
)

