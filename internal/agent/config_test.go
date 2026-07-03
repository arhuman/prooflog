package agent

import (
	"encoding/json"
	"strings"
	"testing"
)

// TestConfigLocalityRoundTrip verifies the operator-declared locality fields
// survive a JSON marshal/unmarshal cycle and are omitted when empty.
func TestConfigLocalityRoundTrip(t *testing.T) {
	tests := []struct {
		name             string
		storeLocality    string
		verifierLocality string
		wantOmitted      bool
	}{
		{"both set", "CH", "EU/DE", false},
		{"store only", "CH", "", false},
		{"both empty", "", "", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			in := DefaultConfig()
			in.StoreLocality = tt.storeLocality
			in.VerifierLocality = tt.verifierLocality

			b, err := json.Marshal(in)
			if err != nil {
				t.Fatalf("marshal: %v", err)
			}

			var out Config
			if err := json.Unmarshal(b, &out); err != nil {
				t.Fatalf("unmarshal: %v", err)
			}
			if out.StoreLocality != tt.storeLocality {
				t.Fatalf("store_locality = %q, want %q", out.StoreLocality, tt.storeLocality)
			}
			if out.VerifierLocality != tt.verifierLocality {
				t.Fatalf("verifier_locality = %q, want %q", out.VerifierLocality, tt.verifierLocality)
			}

			s := string(b)
			hasKey := strings.Contains(s, "store_locality") || strings.Contains(s, "verifier_locality")
			if tt.wantOmitted && hasKey {
				t.Fatalf("empty localities should be omitted, got %s", s)
			}
			if !tt.wantOmitted && !hasKey {
				t.Fatalf("set localities should be present, got %s", s)
			}
		})
	}
}
