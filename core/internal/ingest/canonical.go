package ingest

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"time"

	"github.com/google/uuid"
)

// Canonical payload v1.1: leading version byte for forward-compatible forensic replay (PRD-10).
//
// Layout (153 bytes total, little-endian where applicable):
//
//	[0]        version (must be PayloadVersionV1)
//	[1:9]      logical_clock uint64 LE
//	[9:25]     agent_id [16]
//	[25:41]    event_id [16]
//	[41:45]    event_type uint32 LE
//	[45:49]    aux_pid uint32 LE
//	[49:81]    process_hash [32]
//	[81:113]   file_hash [32]
//	[113:129]  network_tuple [16]
//	[129:137]  timestamp_unix_nano uint64 LE
//	[137:153]  boot_session_id [16]
const CanonicalTelemetryV1Size = 153

// PayloadVersionV1 is the only supported canonical data-plane version (PRD-02 / PRD-10).
const PayloadVersionV1 = byte(0x01)

const (
	EventTypeCodeProcess = uint32(1)
	EventTypeCodeFile    = uint32(2)
	EventTypeCodeNetwork = uint32(3)
	EventTypeCodeUser    = uint32(4)
	EventTypeCodeDecept  = uint32(5)
)

var errCanonicalSize = errors.New("canonical telemetry v1: invalid length")

// TelemetryV1View is a read-only view after cryptographic verification.
type TelemetryV1View struct {
	Raw               []byte
	Version           byte
	LogicalClock      uint64
	AgentID           uuid.UUID
	EventID           uuid.UUID
	EventTypeCode     uint32
	AuxPID            uint32
	ProcessHash       [32]byte
	FileHash          [32]byte
	NetworkTuple      [16]byte
	TimestampUnixNano uint64
	BootSessionID     [16]byte
}

// ParseTelemetryV1 parses payload after signature verification (fail-closed).
// BuildCanonicalV1 materializes the v1 wire layout (mirrors agents/linux `build_canonical_v1` and Windows agent).
// Used for deterministic replay vectors and cross-platform parity tests (PRD-02 / PRD-10).
func BuildCanonicalV1(
	logicalClock uint64,
	agentID uuid.UUID,
	eventID uuid.UUID,
	eventTypeCode uint32,
	auxPID uint32,
	processHash, fileHash [32]byte,
	networkTuple [16]byte,
	timestampUnixNano uint64,
	bootSessionID [16]byte,
) ([CanonicalTelemetryV1Size]byte, error) {
	var out [CanonicalTelemetryV1Size]byte
	aid, err := agentID.MarshalBinary()
	if err != nil {
		return out, fmt.Errorf("canonical telemetry v1: agent_id: %w", err)
	}
	eid, err := eventID.MarshalBinary()
	if err != nil {
		return out, fmt.Errorf("canonical telemetry v1: event_id: %w", err)
	}
	if len(aid) != 16 || len(eid) != 16 {
		return out, errors.New("canonical telemetry v1: uuid wire length")
	}
	out[0] = PayloadVersionV1
	binary.LittleEndian.PutUint64(out[1:9], logicalClock)
	copy(out[9:25], aid)
	copy(out[25:41], eid)
	binary.LittleEndian.PutUint32(out[41:45], eventTypeCode)
	binary.LittleEndian.PutUint32(out[45:49], auxPID)
	copy(out[49:81], processHash[:])
	copy(out[81:113], fileHash[:])
	copy(out[113:129], networkTuple[:])
	binary.LittleEndian.PutUint64(out[129:137], timestampUnixNano)
	copy(out[137:153], bootSessionID[:])
	return out, nil
}

func ParseTelemetryV1(payload []byte) (TelemetryV1View, error) {
	var z TelemetryV1View
	if len(payload) != CanonicalTelemetryV1Size {
		return z, errCanonicalSize
	}
	z.Raw = payload
	z.Version = payload[0]
	if z.Version != PayloadVersionV1 {
		return z, fmt.Errorf("canonical telemetry v1: unsupported version %d", z.Version)
	}
	z.LogicalClock = binary.LittleEndian.Uint64(payload[1:9])

	var err error
	z.AgentID, err = uuidFromBytes(payload[9:25])
	if err != nil {
		return z, fmt.Errorf("canonical telemetry v1: agent_id: %w", err)
	}
	z.EventID, err = uuidFromBytes(payload[25:41])
	if err != nil {
		return z, fmt.Errorf("canonical telemetry v1: event_id: %w", err)
	}
	z.EventTypeCode = binary.LittleEndian.Uint32(payload[41:45])
	z.AuxPID = binary.LittleEndian.Uint32(payload[45:49])
	copy(z.ProcessHash[:], payload[49:81])
	copy(z.FileHash[:], payload[81:113])
	copy(z.NetworkTuple[:], payload[113:129])
	z.TimestampUnixNano = binary.LittleEndian.Uint64(payload[129:137])
	copy(z.BootSessionID[:], payload[137:153])
	return z, nil
}

// DBEventType maps wire code to telemetry_events.event_type CHECK values.
func DBEventType(code uint32) (string, error) {
	switch code {
	case EventTypeCodeProcess:
		return "PROCESS_EVENT", nil
	case EventTypeCodeFile:
		return "FILE_EVENT", nil
	case EventTypeCodeNetwork:
		return "NETWORK_EVENT", nil
	case EventTypeCodeUser:
		return "USER_EVENT", nil
	case EventTypeCodeDecept:
		return "DECEPTION_EVENT", nil
	default:
		return "", fmt.Errorf("canonical telemetry v1: unknown event_type code %d", code)
	}
}

// TimestampUTC converts unix nano to time for DB / hub (UTC).
func TimestampUTC(nano uint64) time.Time {
	return time.Unix(0, int64(nano)).UTC()
}

func uuidFromBytes(b []byte) (uuid.UUID, error) {
	if len(b) != 16 {
		return uuid.Nil, errors.New("uuid length")
	}
	u, err := uuid.FromBytes(b)
	if err != nil {
		return uuid.Nil, err
	}
	return u, nil
}

// AgentIDBytes parses UUID string to 16-byte wire form.
func AgentIDBytes(agentIDStr string) ([16]byte, error) {
	var out [16]byte
	u, err := uuid.Parse(agentIDStr)
	if err != nil {
		return out, err
	}
	b, err := u.MarshalBinary()
	if err != nil {
		return out, err
	}
	copy(out[:], b)
	return out, nil
}

// CanonicalizePayloadBytes enforces deterministic canonical payload bytes.
// It supports canonical telemetry v1 binary payloads and strict canonical JSON.
func CanonicalizePayloadBytes(payload []byte) ([]byte, TelemetryV1View, bool, error) {
	if len(payload) == 0 {
		return nil, TelemetryV1View{}, false, errors.New("canonical payload missing")
	}
	trimmed := bytes.TrimSpace(payload)
	if len(trimmed) > 0 && (trimmed[0] == '{' || trimmed[0] == '[') {
		canonicalJSON, err := canonicalizeStrictJSON(trimmed)
		if err != nil {
			return nil, TelemetryV1View{}, false, err
		}
		if !bytes.Equal(trimmed, canonicalJSON) {
			return nil, TelemetryV1View{}, false, errors.New("non-canonical JSON payload")
		}
		return append([]byte(nil), canonicalJSON...), TelemetryV1View{}, true, nil
	}
	view, err := ParseTelemetryV1(payload)
	if err != nil {
		return nil, TelemetryV1View{}, false, err
	}
	canonical, err := BuildCanonicalV1(
		view.LogicalClock,
		view.AgentID,
		view.EventID,
		view.EventTypeCode,
		view.AuxPID,
		view.ProcessHash,
		view.FileHash,
		view.NetworkTuple,
		view.TimestampUnixNano,
		view.BootSessionID,
	)
	if err != nil {
		return nil, TelemetryV1View{}, false, err
	}
	if !bytes.Equal(payload, canonical[:]) {
		return nil, TelemetryV1View{}, false, errors.New("non-canonical payload")
	}
	return append([]byte(nil), canonical[:]...), view, false, nil
}

func canonicalizeStrictJSON(input []byte) ([]byte, error) {
	var v any
	dec := json.NewDecoder(bytes.NewReader(input))
	dec.UseNumber()
	if err := dec.Decode(&v); err != nil {
		return nil, errors.New("invalid JSON payload")
	}
	if dec.More() {
		return nil, errors.New("invalid JSON payload")
	}
	return encodeCanonicalJSON(v)
}

func encodeCanonicalJSON(v any) ([]byte, error) {
	switch t := v.(type) {
	case map[string]any:
		keys := make([]string, 0, len(t))
		for k := range t {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		out := []byte{'{'}
		for i, k := range keys {
			if i > 0 {
				out = append(out, ',')
			}
			kb, err := json.Marshal(k)
			if err != nil {
				return nil, errors.New("invalid JSON payload")
			}
			out = append(out, kb...)
			out = append(out, ':')
			vb, err := encodeCanonicalJSON(t[k])
			if err != nil {
				return nil, err
			}
			out = append(out, vb...)
		}
		out = append(out, '}')
		return out, nil
	case []any:
		out := []byte{'['}
		for i := range t {
			if i > 0 {
				out = append(out, ',')
			}
			vb, err := encodeCanonicalJSON(t[i])
			if err != nil {
				return nil, err
			}
			out = append(out, vb...)
		}
		out = append(out, ']')
		return out, nil
	case json.Number, string, bool, nil, float64:
		b, err := json.Marshal(t)
		if err != nil {
			return nil, errors.New("invalid JSON payload")
		}
		return b, nil
	default:
		b, err := json.Marshal(t)
		if err != nil {
			return nil, errors.New("invalid JSON payload")
		}
		return b, nil
	}
}
