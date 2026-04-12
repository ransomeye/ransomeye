package forensics

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"unicode/utf8"
)

func TestMarshalCanonicalKeyOrder(t *testing.T) {
	a, err := MarshalCanonical(map[string]any{
		"z": 1,
		"a": "x",
		"m": true,
	})
	if err != nil {
		t.Fatal(err)
	}
	b, err := MarshalCanonical(map[string]any{
		"m": true,
		"z": 1,
		"a": "x",
	})
	if err != nil {
		t.Fatal(err)
	}
	if string(a) != string(b) {
		t.Fatalf("non-deterministic: %q vs %q", a, b)
	}
	if string(a) != `{"a":"x","m":true,"z":1}` {
		t.Fatalf("unexpected encoding: %s", a)
	}
}

func TestCanonicalizationSpecRulesMatchImplementationRules(t *testing.T) {
	spec := loadCanonicalizationSpec(t)
	requiredSpecMarkers := []string{
		"UTF-8 encoding",
		"Object keys sorted lexicographically at every depth",
		"No insignificant whitespace",
		"Arrays preserve declared element order",
	}
	for _, marker := range requiredSpecMarkers {
		if !strings.Contains(spec, marker) {
			t.Fatalf("BUILD_FAIL: spec marker missing: %q", marker)
		}
	}

	left := map[string]any{
		"z": map[string]any{"b": 2, "a": 1},
		"a": []any{map[string]any{"y": 2, "x": 1}, "v"},
	}
	right := map[string]any{
		"a": []any{map[string]any{"x": 1, "y": 2}, "v"},
		"z": map[string]any{"a": 1, "b": 2},
	}
	leftCanonical, err := MarshalCanonical(left)
	if err != nil {
		t.Fatalf("BUILD_FAIL: MarshalCanonical(left): %v", err)
	}
	rightCanonical, err := MarshalCanonical(right)
	if err != nil {
		t.Fatalf("BUILD_FAIL: MarshalCanonical(right): %v", err)
	}

	if !utf8.Valid(leftCanonical) {
		t.Fatal("BUILD_FAIL: canonical output is not UTF-8")
	}
	if string(leftCanonical) != string(rightCanonical) {
		t.Fatalf("BUILD_FAIL: field-order canonicalization mismatch left=%q right=%q", leftCanonical, rightCanonical)
	}
	if strings.ContainsRune(string(leftCanonical), ' ') || strings.ContainsRune(string(leftCanonical), '\n') || strings.ContainsRune(string(leftCanonical), '\t') {
		t.Fatalf("BUILD_FAIL: whitespace normalization mismatch: %q", leftCanonical)
	}
	if string(leftCanonical) != `{"a":[{"x":1,"y":2},"v"],"z":{"a":1,"b":2}}` {
		t.Fatalf("BUILD_FAIL: canonical encoding mismatch got=%q", leftCanonical)
	}

	var decoded map[string]any
	if err := json.Unmarshal(leftCanonical, &decoded); err != nil {
		t.Fatalf("BUILD_FAIL: canonical output invalid JSON: %v", err)
	}
}

func loadCanonicalizationSpec(t *testing.T) string {
	t.Helper()
	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("BUILD_FAIL: os.Getwd: %v", err)
	}
	dir := wd
	for i := 0; i < 12; i++ {
		candidate := filepath.Join(dir, "docs", "CanonicalizationSpecification.md")
		raw, readErr := os.ReadFile(candidate)
		if readErr == nil {
			return string(raw)
		}
		next := filepath.Dir(dir)
		if next == dir {
			break
		}
		dir = next
	}
	t.Fatalf("BUILD_FAIL: docs/CanonicalizationSpecification.md not found from %s", wd)
	return ""
}
