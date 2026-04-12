package authority

import (
	"encoding/json"
	"errors"
	"sort"
	"strconv"
)

// JCSCanonicalJSONBytes produces RFC 8785 JSON Canonicalization Scheme (JCS) bytes
// for deterministic payloads required by PRD-01 / PRD-04 / PRD-13 (SHA-256 over these bytes where specified).
//
// Supported types:
// - map[string]any (keys sorted lexicographically)
// - []any (order preserved)
// - string, bool, int64
//
// Forbidden:
// - nil values
// - float types
func JCSCanonicalJSONBytes(v any) ([]byte, error) {
	var b []byte
	return appendJCS(b, v)
}

func appendJCS(dst []byte, v any) ([]byte, error) {
	switch t := v.(type) {
	case map[string]any:
		keys := make([]string, 0, len(t))
		for k := range t {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		dst = append(dst, '{')
		for i, k := range keys {
			if i > 0 {
				dst = append(dst, ',')
			}
			kb, _ := json.Marshal(k)
			dst = append(dst, kb...)
			dst = append(dst, ':')
			val, ok := t[k]
			if !ok {
				return nil, errors.New("jcs missing key")
			}
			if val == nil {
				return nil, errors.New("jcs nil forbidden")
			}
			var err error
			dst, err = appendJCS(dst, val)
			if err != nil {
				return nil, err
			}
		}
		dst = append(dst, '}')
		return dst, nil
	case []any:
		dst = append(dst, '[')
		for i := range t {
			if i > 0 {
				dst = append(dst, ',')
			}
			if t[i] == nil {
				return nil, errors.New("jcs nil forbidden")
			}
			var err error
			dst, err = appendJCS(dst, t[i])
			if err != nil {
				return nil, err
			}
		}
		dst = append(dst, ']')
		return dst, nil
	case string:
		sb, _ := json.Marshal(t)
		dst = append(dst, sb...)
		return dst, nil
	case bool:
		if t {
			dst = append(dst, "true"...)
		} else {
			dst = append(dst, "false"...)
		}
		return dst, nil
	case int64:
		dst = append(dst, strconv.FormatInt(t, 10)...)
		return dst, nil
	default:
		return nil, errors.New("jcs unsupported type")
	}
}

