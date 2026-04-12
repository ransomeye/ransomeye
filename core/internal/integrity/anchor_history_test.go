package integrity

import "testing"

func TestAnchorHistoryContains(t *testing.T) {
	var a, b [32]byte
	a[0] = 1
	b[0] = 2
	entries := [][32]byte{a, b}
	if !anchorHistoryContains(entries, a) {
		t.Fatal("expected contains a")
	}
	if anchorHistoryContains(entries, [32]byte{9}) {
		t.Fatal("unexpected")
	}
}
