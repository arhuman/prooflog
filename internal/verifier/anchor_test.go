package verifier

import (
	"context"
	"math/big"
	"testing"
	"time"

	"github.com/arhuman/prooflog/internal/anchor"
	"github.com/arhuman/prooflog/internal/anchor/tsatest"
)

// anchorFor mints a matching receipt for the source's latest checkpoint note.
func anchorFor(t *testing.T, signedNote string, genTime time.Time) anchor.Receipt {
	t.Helper()
	fake := &tsatest.FakeAnchor{TSA: "https://tsa.test/tsr", GenTime: genTime, Nonce: big.NewInt(7)}
	rec, err := fake.Anchor(context.Background(), []byte(signedNote))
	if err != nil {
		t.Fatal(err)
	}
	return rec
}

func TestVerifyAnchorMatching(t *testing.T) {
	_, priv, keys := testKeyring(t)
	b := newBuilder(t, priv)
	b.heartbeat(10)
	b.tick(60 * time.Second)
	b.heartbeat(10)
	b.seal()

	gen := time.Date(2026, 7, 4, 2, 0, 0, 0, time.UTC)
	src := b.source()
	src.Anchors = []anchor.Receipt{anchorFor(t, b.checkpts[0], gen)}

	res := Verify(src, keys, DefaultPolicy())
	if res.Anchors.Total != 1 || res.Anchors.Matching != 1 {
		t.Fatalf("anchor check = %+v, want total=1 matching=1", res.Anchors)
	}
	if !res.Anchors.Configured || res.Anchors.TSA != "https://tsa.test/tsr" {
		t.Fatalf("anchor metadata not surfaced: %+v", res.Anchors)
	}
	if !res.Anchors.LatestGenTime.Equal(gen) {
		t.Fatalf("latest genTime = %s, want %s", res.Anchors.LatestGenTime, gen)
	}
	if hasFinding(res.Findings, "F-ANCHOR") {
		t.Fatalf("matching anchor must not raise F-ANCHOR: %+v", res.Findings)
	}
}

func TestVerifyAnchorSizeMismatchRaisesFinding(t *testing.T) {
	_, priv, keys := testKeyring(t)
	b := newBuilder(t, priv)
	b.heartbeat(10)
	b.seal()

	rec := anchorFor(t, b.checkpts[0], time.Date(2026, 7, 4, 2, 0, 0, 0, time.UTC))
	rec.Size = 999 // imprint still matches, but (origin,size,root) no longer does
	src := b.source()
	src.Anchors = []anchor.Receipt{rec}

	res := Verify(src, keys, DefaultPolicy())
	if res.Anchors.Total != 1 || res.Anchors.Matching != 0 {
		t.Fatalf("anchor check = %+v, want total=1 matching=0", res.Anchors)
	}
	if !hasFinding(res.Findings, "F-ANCHOR") {
		t.Fatalf("size mismatch must raise F-ANCHOR: %+v", res.Findings)
	}
}

func TestVerifyAnchorImprintMismatchRaisesFinding(t *testing.T) {
	_, priv, keys := testKeyring(t)
	b := newBuilder(t, priv)
	b.heartbeat(10)
	b.seal()

	// A receipt minted over unrelated bytes: its token imprint matches no
	// accepted checkpoint note.
	unrelated := "prooflog/test/anchor\n100\nAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\n\n— x y\n"
	rec := anchorFor(t, unrelated, time.Date(2026, 7, 4, 2, 0, 0, 0, time.UTC))
	src := b.source()
	src.Anchors = []anchor.Receipt{rec}

	res := Verify(src, keys, DefaultPolicy())
	if res.Anchors.Matching != 0 {
		t.Fatalf("unrelated receipt must not match: %+v", res.Anchors)
	}
	if !hasFinding(res.Findings, "F-ANCHOR") {
		t.Fatalf("imprint mismatch must raise F-ANCHOR: %+v", res.Findings)
	}
}
