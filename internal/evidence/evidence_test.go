package evidence

import (
	"testing"
	"time"
)

func TestAutoField(t *testing.T) {
	t.Parallel()
	f := AutoField("acme")
	if !f.Present || f.Provenance != Auto || f.Value != "acme" {
		t.Fatalf("AutoField = %+v", f)
	}
}

func TestManualSlot(t *testing.T) {
	t.Parallel()
	f := ManualSlot[time.Time]()
	if f.Present || f.Provenance != Manual {
		t.Fatalf("ManualSlot = %+v", f)
	}
	if !f.Value.IsZero() {
		t.Fatal("manual slot should hold the zero value")
	}
}

func TestIncidentMixedProvenance(t *testing.T) {
	t.Parallel()
	inc := Incident{
		Discovery:  AutoField(time.Date(2026, 7, 3, 0, 0, 0, 0, time.UTC)),
		AttackType: ManualSlot[string](),
		Impact:     AutoField(CIAImpact{Confidentiality: true}),
	}
	if inc.Discovery.Provenance != Auto {
		t.Fatal("discovery should be auto (evidenced)")
	}
	if inc.AttackType.Present {
		t.Fatal("attack type should be an empty manual slot")
	}
	if !inc.Impact.Value.Confidentiality {
		t.Fatal("impact value not carried")
	}
}
