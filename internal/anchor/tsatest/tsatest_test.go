package tsatest

import (
	"bytes"
	"context"
	"crypto/sha256"
	"math/big"
	"testing"
	"time"

	"github.com/arhuman/prooflog/internal/anchor"
)

const signedNote = "prooflog/test/anchor\n100\nAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\n\n— prooflog/test/anchor dGVzdA==\n"

func TestMintTokenParsesViaAnchor(t *testing.T) {
	imprint := sha256.Sum256([]byte(signedNote))
	gen := time.Date(2026, 7, 4, 2, 0, 0, 0, time.UTC)
	token, err := MintToken(imprint[:], big.NewInt(42), gen)
	if err != nil {
		t.Fatal(err)
	}
	got, alg, gt, err := anchor.ParseTokenImprint(token)
	if err != nil {
		t.Fatalf("minted token does not parse: %v", err)
	}
	if !bytes.Equal(got, imprint[:]) {
		t.Fatal("imprint mismatch")
	}
	if alg != "2.16.840.1.101.3.4.2.1" {
		t.Fatalf("alg = %q", alg)
	}
	if !gt.Equal(gen) {
		t.Fatalf("genTime = %s, want %s", gt, gen)
	}
}

func TestFakeAnchorReceipt(t *testing.T) {
	gen := time.Date(2026, 7, 4, 2, 0, 0, 0, time.UTC)
	fake := &FakeAnchor{TSA: "https://tsa.test/tsr", Qualified: true, GenTime: gen, Nonce: big.NewInt(7)}
	rec, err := fake.Anchor(context.Background(), []byte(signedNote))
	if err != nil {
		t.Fatal(err)
	}
	if rec.Origin != "prooflog/test/anchor" || rec.Size != 100 {
		t.Fatalf("checkpoint identity not parsed: %+v", rec)
	}
	if rec.TSA != "https://tsa.test/tsr" || !rec.Qualified || !rec.GenTime.Equal(gen) {
		t.Fatalf("receipt metadata: %+v", rec)
	}
	imprint, _, _, err := anchor.ParseTokenImprint(rec.Token)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256([]byte(signedNote))
	if !bytes.Equal(imprint, sum[:]) {
		t.Fatal("token imprint does not cover the note")
	}
}
