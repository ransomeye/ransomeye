package authority

import (
	"errors"
	"fmt"
)

// RequireSingleTrustSnapshotBindingForSignal enforces the transitional Mishka kernel rule: authoritative
// SIGNAL ingestion and commits close execution context on exactly one CONFIG/trust_snapshot binding.
// DECISION and other record types may still use wider binding sets via buildNormalizedBindSet.
func RequireSingleTrustSnapshotBindingForSignal(refs []AuthorityRef) error {
	if len(refs) != 1 {
		return FailType1("INPUT_ERROR", errors.New("SIGNAL path requires exactly one authority binding (CONFIG/trust_snapshot)"))
	}
	r := refs[0]
	if r.Type != trustAuthorityType || r.ID != trustAuthorityID {
		return FailType1("INPUT_ERROR", fmt.Errorf("SIGNAL path requires authority binding %s/%s, got %s/%s", trustAuthorityType, trustAuthorityID, r.Type, r.ID))
	}
	return nil
}
