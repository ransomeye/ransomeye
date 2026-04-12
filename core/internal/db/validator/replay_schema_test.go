package validator

import "testing"

func TestValidateReplaySchemaSnapshotRejectsMissingColumn(t *testing.T) {
	err := validateReplaySchemaSnapshot(replaySchemaSnapshot{
		Columns: map[string]bool{
			"sequence_id":     true,
			"message_id":      true,
			"content_sha256":  false,
			"boot_session_id": true,
		},
		Constraints: []string{
			`UNIQUE (message_id, content_sha256, boot_session_id)`,
		},
	})
	if err == nil {
		t.Fatal("expected missing column rejection")
	}
}

func TestValidateReplaySchemaSnapshotRejectsMissingConstraint(t *testing.T) {
	err := validateReplaySchemaSnapshot(replaySchemaSnapshot{
		Columns: map[string]bool{
			"sequence_id":     true,
			"message_id":      true,
			"content_sha256":  true,
			"boot_session_id": true,
		},
		Constraints: []string{
			`PRIMARY KEY (event_id, event_time)`,
		},
	})
	if err == nil {
		t.Fatal("expected missing constraint rejection")
	}
}

func TestValidateReplaySchemaSnapshotAcceptsExpectedConstraint(t *testing.T) {
	err := validateReplaySchemaSnapshot(replaySchemaSnapshot{
		Columns: map[string]bool{
			"sequence_id":     true,
			"message_id":      true,
			"content_sha256":  true,
			"boot_session_id": true,
		},
		Constraints: []string{
			`UNIQUE ("message_id", "content_sha256", "boot_session_id")`,
		},
	})
	if err != nil {
		t.Fatalf("validateReplaySchemaSnapshot: %v", err)
	}
}
