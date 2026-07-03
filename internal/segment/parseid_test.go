package segment

import (
	"crypto/rand"
	"testing"
	"time"
)

func TestParseIDRoundTrip(t *testing.T) {
	t.Parallel()
	id, err := NewID(time.UnixMilli(0x0123456789A), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	got, err := ParseID(id.String())
	if err != nil {
		t.Fatalf("ParseID(%q): %v", id.String(), err)
	}
	if got != id {
		t.Fatalf("round trip mismatch: got %x, want %x", got, id)
	}
}

func TestParseIDRejects(t *testing.T) {
	t.Parallel()
	// A canonical id whose version/variant nibbles are patched to invalid values.
	valid := "01890000-0000-7000-8000-000000000001"
	cases := []struct {
		name string
		in   string
	}{
		{"traversal", "../../x"},
		{"dotdot", ".."},
		{"slash path", "a/b"},
		{"empty", ""},
		{"too short", "01890000-0000-7000-8000-00000000000"},
		{"too long", valid + "0"},
		{"non-hex", "0189000g-0000-7000-8000-000000000001"},
		{"bad dash position", "018900000-000-7000-8000-000000000001"},
		{"wrong version", "01890000-0000-4000-8000-000000000001"},
		{"wrong variant", "01890000-0000-7000-c000-000000000001"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if _, err := ParseID(tc.in); err == nil {
				t.Fatalf("ParseID(%q) = nil error, want rejection", tc.in)
			}
		})
	}
}
