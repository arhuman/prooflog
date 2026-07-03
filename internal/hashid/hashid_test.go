package hashid

import (
	"bytes"
	"strings"
	"testing"
)

func TestParseDigestRoundTrip(t *testing.T) {
	var raw [Size]byte
	for i := range raw {
		raw[i] = byte(i)
	}
	d, err := ParseDigest(raw[:])
	if err != nil {
		t.Fatalf("ParseDigest: %v", err)
	}
	if d != Digest(raw) {
		t.Fatalf("round trip mismatch: got %v want %v", d, raw)
	}
	if !bytes.Equal(d.Bytes(), raw[:]) {
		t.Fatalf("Bytes() = %x, want %x", d.Bytes(), raw[:])
	}
	back, err := ParseHexDigest(d.Hex())
	if err != nil {
		t.Fatalf("ParseHexDigest: %v", err)
	}
	if back != d {
		t.Fatalf("hex round trip mismatch: got %v want %v", back, d)
	}
	if d.String() != d.Hex() {
		t.Fatalf("String() = %q, want %q", d.String(), d.Hex())
	}
}

func TestParseDigestRejectsWrongLength(t *testing.T) {
	for _, n := range []int{0, 1, Size - 1, Size + 1, 64} {
		if _, err := ParseDigest(make([]byte, n)); err == nil {
			t.Fatalf("ParseDigest(len %d) should fail", n)
		}
	}
}

func TestParseHexDigestRejectsBadInput(t *testing.T) {
	cases := map[string]string{
		"too short":  strings.Repeat("a", 2*Size-2),
		"too long":   strings.Repeat("a", 2*Size+2),
		"non hex":    strings.Repeat("zz", Size),
		"empty":      "",
		"odd length": strings.Repeat("a", 2*Size-1),
	}
	for name, s := range cases {
		if _, err := ParseHexDigest(s); err == nil {
			t.Fatalf("%s: ParseHexDigest(%q) should fail", name, s)
		}
	}
}

// TestBytesIsCopy proves Bytes returns an independent slice: mutating it must
// not corrupt the digest.
func TestBytesIsCopy(t *testing.T) {
	var d Digest
	b := d.Bytes()
	b[0] = 0xff
	if d[0] != 0 {
		t.Fatal("Bytes() aliases the digest backing array")
	}
}
