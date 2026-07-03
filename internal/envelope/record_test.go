package envelope

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"
)

func TestFormatTimePinned(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		in   time.Time
		want string
	}{
		{"utc", time.Date(2026, 7, 3, 12, 0, 0, 104329000, time.UTC), "2026-07-03T12:00:00.104329000Z"},
		{"zero nanos", time.Date(2026, 7, 3, 12, 0, 0, 0, time.UTC), "2026-07-03T12:00:00.000000000Z"},
		{"non-utc converted", time.Date(2026, 7, 3, 14, 0, 0, 0, time.FixedZone("CEST", 2*3600)), "2026-07-03T12:00:00.000000000Z"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := FormatTime(tt.in); got != tt.want {
				t.Fatalf("FormatTime = %q, want %q", got, tt.want)
			}
		})
	}
}

// pseudo is a valid 64-lowercase-hex actor pseudonym for tests.
const pseudo = "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8091a2b3c4d5e6f708192a3b4c5d6"

func businessRecord() Record {
	return Record{
		Version:     Version,
		SourceID:    "vps-01/api",
		Seq:         1842,
		EventType:   "access.revoked",
		EventTime:   "2026-07-03T12:00:00.000000000Z",
		IngestTime:  "2026-07-03T12:00:00.104329000Z",
		Actor:       pseudo,
		Outcome:     "success",
		PayloadCT:   "Y2lwaGVy",
		PayloadHash: hex.EncodeToString(mustSum([]byte("plain"))),
		KeyID:       "org-acme-2026-1",
		PrevHash:    ZeroHash,
	}
}

func mustSum(b []byte) []byte {
	s := sha256.Sum256(b)
	return s[:]
}

func TestSerializeFieldOrderSingleLine(t *testing.T) {
	t.Parallel()
	r := businessRecord()
	if err := r.Serialize(); err != nil {
		t.Fatal(err)
	}
	got := string(r.Bytes())
	want := `{"v":2,"source_id":"vps-01/api","seq":1842,"event_type":"access.revoked","event_time":"2026-07-03T12:00:00.000000000Z","ingest_time":"2026-07-03T12:00:00.104329000Z","actor":"` + pseudo + `","outcome":"success","payload_ct":"Y2lwaGVy","payload_hash":"` + r.PayloadHash + `","key_id":"org-acme-2026-1","prev_hash":"` + ZeroHash + `"}`
	if got != want {
		t.Fatalf("serialized bytes mismatch:\n got: %s\nwant: %s", got, want)
	}
}

func TestHashCoversStoredBytes(t *testing.T) {
	t.Parallel()
	r := businessRecord()
	if err := r.Serialize(); err != nil {
		t.Fatal(err)
	}
	want := sha256.Sum256(r.Bytes())
	if r.Hash() != want {
		t.Fatal("Hash does not cover stored bytes")
	}
	if r.HashHex() != hex.EncodeToString(want[:]) {
		t.Fatal("HashHex mismatch")
	}
}

func TestParseRoundTripPreservesBytes(t *testing.T) {
	t.Parallel()
	r := businessRecord()
	if err := r.Serialize(); err != nil {
		t.Fatal(err)
	}
	parsed, err := Parse(r.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	if string(parsed.Bytes()) != string(r.Bytes()) {
		t.Fatal("Parse changed canonical bytes")
	}
	if parsed.Hash() != r.Hash() {
		t.Fatal("Parse changed hash")
	}
}

func TestSerializeNoHTMLEscape(t *testing.T) {
	t.Parallel()
	r := businessRecord()
	r.Actor = "a<b>&c"
	if err := r.Serialize(); err != nil {
		t.Fatal(err)
	}
	if !json.Valid(r.Bytes()) {
		t.Fatal("invalid json")
	}
	if got := string(r.Bytes()); !contains(got, `"actor":"a<b>&c"`) {
		t.Fatalf("HTML characters were escaped: %s", got)
	}
}

func TestSerializeHasNoLabelsField(t *testing.T) {
	t.Parallel()
	r := businessRecord()
	if err := r.Serialize(); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(r.Bytes()), "labels") {
		t.Fatalf("v2 record must not carry a labels field: %s", r.Bytes())
	}
}

func TestValidate(t *testing.T) {
	t.Parallel()
	sysClear := json.RawMessage(`{"k":1}`)
	tests := []struct {
		name    string
		mutate  func(*Record)
		wantErr error
	}{
		{"valid business", func(_ *Record) {}, nil},
		{"valid empty actor", func(r *Record) { r.Actor = "" }, nil},
		{"bad version v1", func(r *Record) { r.Version = 1 }, ErrMissingField},
		{"no source", func(r *Record) { r.SourceID = "" }, ErrMissingField},
		{"zero seq", func(r *Record) { r.Seq = 0 }, ErrMissingField},
		{"no event type", func(r *Record) { r.EventType = "" }, ErrMissingField},
		{"bad prev hash", func(r *Record) { r.PrevHash = "xyz" }, ErrBadHash},
		{"actor too short", func(r *Record) { r.Actor = "abcd" }, ErrBadActor},
		{"actor uppercase hex", func(r *Record) { r.Actor = strings.ToUpper(pseudo) }, ErrBadActor},
		{"actor non-hex", func(r *Record) { r.Actor = strings.Repeat("g", 64) }, ErrBadActor},
		{"invalid outcome", func(r *Record) { r.Outcome = "maybe" }, ErrBadOutcome},
		{"business missing ct", func(r *Record) { r.PayloadCT = "" }, ErrMissingField},
		{"business bad payload hash", func(r *Record) { r.PayloadHash = "short" }, ErrBadHash},
		{"business missing key id", func(r *Record) { r.KeyID = "" }, ErrMissingField},
		{"business with clear", func(r *Record) { r.PayloadClear = sysClear }, ErrPayloadShape},
		{
			name: "valid system",
			mutate: func(r *Record) {
				r.EventType = "system.heartbeat"
				r.PayloadClear = sysClear
				r.PayloadCT, r.PayloadHash, r.KeyID = "", "", ""
			},
			wantErr: nil,
		},
		{
			name: "system missing clear",
			mutate: func(r *Record) {
				r.EventType = "system.heartbeat"
				r.PayloadCT, r.PayloadHash, r.KeyID = "", "", ""
			},
			wantErr: ErrPayloadShape,
		},
		{
			name: "system with ct",
			mutate: func(r *Record) {
				r.EventType = "system.heartbeat"
				r.PayloadClear = sysClear
			},
			wantErr: ErrPayloadShape,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := businessRecord()
			tt.mutate(&r)
			err := r.Validate()
			if tt.wantErr == nil {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				return
			}
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("got %v, want %v", err, tt.wantErr)
			}
		})
	}
}

func TestIsSystem(t *testing.T) {
	t.Parallel()
	if !(Record{EventType: "system.heartbeat"}).IsSystem() {
		t.Fatal("system.heartbeat should be system")
	}
	if (Record{EventType: "access.revoked"}).IsSystem() {
		t.Fatal("access.revoked should not be system")
	}
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
