package authority

import (
	"errors"
	"fmt"
)

// PRD-01 failure classification (mandatory):
// TYPE 1 — INPUT ERROR → REJECT OPERATION
// TYPE 2 — STATE INCONSISTENCY → HALT PARTITION
// TYPE 3 — INTEGRITY FAILURE → GLOBAL HALT
type FailureType uint8

const (
	FailureType1InputError FailureType = iota + 1
	FailureType2StateInconsistency
	FailureType3IntegrityFailure
)

func (t FailureType) String() string {
	switch t {
	case FailureType1InputError:
		return "TYPE_1_INPUT_ERROR"
	case FailureType2StateInconsistency:
		return "TYPE_2_STATE_INCONSISTENCY"
	case FailureType3IntegrityFailure:
		return "TYPE_3_INTEGRITY_FAILURE"
	default:
		return "TYPE_UNKNOWN"
	}
}

// Failure is a typed error wrapper for PRD-01 failure propagation alignment.
// It preserves the original cause via Unwrap().
type Failure struct {
	Type FailureType
	Code string
	Err  error
}

func (f Failure) Error() string {
	if f.Code == "" {
		return fmt.Sprintf("[%s] %v", f.Type.String(), f.Err)
	}
	return fmt.Sprintf("[%s:%s] %v", f.Type.String(), f.Code, f.Err)
}

func (f Failure) Unwrap() error { return f.Err }

func fail(t FailureType, code string, err error) error {
	if err == nil {
		err = errors.New("failure")
	}
	return Failure{Type: t, Code: code, Err: err}
}

func FailType1(code string, err error) error { return fail(FailureType1InputError, code, err) }
func FailType2(code string, err error) error { return fail(FailureType2StateInconsistency, code, err) }
func FailType3(code string, err error) error { return fail(FailureType3IntegrityFailure, code, err) }

// FailureAs returns the first Failure in an error chain.
func FailureAs(err error) (Failure, bool) {
	var f Failure
	if errors.As(err, &f) {
		return f, true
	}
	return Failure{}, false
}

