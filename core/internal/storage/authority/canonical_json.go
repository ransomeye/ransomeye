package authority

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"sort"
)

// canonicalizeStrictJSONRFC8785 canonicalizes JSON with a deterministic encoding suitable for
// verifying RFC 8785 "canonical JSON" invariants for committed authority snapshots.
//
// It fails closed on malformed JSON or trailing data.
func canonicalizeStrictJSONRFC8785(input []byte) ([]byte, error) {
	var v any
	dec := json.NewDecoder(bytes.NewReader(input))
	dec.UseNumber()
	if err := dec.Decode(&v); err != nil {
		return nil, errors.New("invalid JSON payload")
	}
	// Ensure there are no additional JSON values after the first.
	var extra any
	if err := dec.Decode(&extra); err != io.EOF {
		return nil, errors.New("invalid JSON payload")
	}
	return encodeCanonicalJSONRFC8785(v)
}

func encodeCanonicalJSONRFC8785(v any) ([]byte, error) {
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
			vb, err := encodeCanonicalJSONRFC8785(t[k])
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
			vb, err := encodeCanonicalJSONRFC8785(t[i])
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

