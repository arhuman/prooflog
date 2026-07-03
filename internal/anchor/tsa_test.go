package anchor

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/asn1"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// goldenNonce is a fixed nonce so the request encoding is deterministic.
var goldenNonce = big.NewInt(0x1122334455667788)

func readFixture(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatalf("read fixture %s: %v", name, err)
	}
	return b
}

// fixtureToken parses the committed response.der and returns its token bytes,
// nonce, and genTime, so the round-trip test stays robust to regeneration.
func fixtureToken(t *testing.T, respDER []byte) (token []byte, nonce *big.Int, genTime time.Time) {
	t.Helper()
	var resp timeStampResp
	if _, err := asn1.Unmarshal(respDER, &resp); err != nil {
		t.Fatalf("unmarshal response: %v", err)
	}
	tst, err := parseTimeStampToken(resp.Token.FullBytes)
	if err != nil {
		t.Fatalf("parse token: %v", err)
	}
	return resp.Token.FullBytes, tst.Nonce, tst.GenTime.UTC()
}

func TestBuildTimeStampReqGolden(t *testing.T) {
	note := readFixture(t, "note.bin")
	imprint := sha256.Sum256(note)
	got, err := buildTimeStampReq(imprint[:], goldenNonce)
	if err != nil {
		t.Fatal(err)
	}

	goldenPath := filepath.Join("testdata", "request-golden.der")
	if os.Getenv("UPDATE_GOLDEN") == "1" {
		if err := os.WriteFile(goldenPath, got, 0o644); err != nil {
			t.Fatal(err)
		}
		t.Log("updated", goldenPath)
	}
	want := readFixture(t, "request-golden.der")
	if !bytes.Equal(got, want) {
		t.Fatalf("request DER mismatch:\n got %x\nwant %x", got, want)
	}

	// The encoding must round-trip and carry exactly what we set.
	var req tsRequest
	if _, err := asn1.Unmarshal(got, &req); err != nil {
		t.Fatalf("golden request does not parse: %v", err)
	}
	if req.Version != 1 || !req.CertReq || req.Nonce.Cmp(goldenNonce) != 0 {
		t.Fatalf("unexpected request fields: %+v", req)
	}
	if !req.MessageImprint.HashAlgorithm.Algorithm.Equal(oidSHA256) ||
		!bytes.Equal(req.MessageImprint.HashedMessage, imprint[:]) {
		t.Fatal("request imprint does not match the note")
	}
}

// tsaServer serves a fixed reply body with the RFC 3161 content type and
// captures the last request body for assertions.
func tsaServer(t *testing.T, reply []byte) (*httptest.Server, *[]byte) {
	t.Helper()
	var lastReq []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body := make([]byte, r.ContentLength)
		_, _ = r.Body.Read(body)
		lastReq = body
		w.Header().Set("Content-Type", contentTypeReply)
		_, _ = w.Write(reply)
	}))
	t.Cleanup(srv.Close)
	return srv, &lastReq
}

func TestAnchorRoundTrip(t *testing.T) {
	note := readFixture(t, "note.bin")
	respDER := readFixture(t, "response.der")
	token, nonce, genTime := fixtureToken(t, respDER)

	srv, _ := tsaServer(t, respDER)
	client := &TSAClient{
		URL:       srv.URL,
		Qualified: false,
		nonce:     func() (*big.Int, error) { return nonce, nil },
	}

	rec, err := client.Anchor(context.Background(), note)
	if err != nil {
		t.Fatalf("Anchor: %v", err)
	}
	if rec.Origin != "prooflog/test/anchor" || rec.Size != 100 {
		t.Fatalf("checkpoint identity not parsed: %+v", rec)
	}
	if !rec.GenTime.Equal(genTime) {
		t.Fatalf("genTime = %s, want %s", rec.GenTime, genTime)
	}
	if !bytes.Equal(rec.Token, token) {
		t.Fatal("stored token does not match the DER TimeStampToken")
	}
	if rec.TSA != srv.URL {
		t.Fatalf("TSA = %q, want %q", rec.TSA, srv.URL)
	}

	// The stored token verifies offline against the note it should cover.
	imprint, alg, gt, err := ParseTokenImprint(rec.Token)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(note)
	if !bytes.Equal(imprint, sum[:]) {
		t.Fatal("stored token imprint does not match the note")
	}
	if alg != oidSHA256.String() || !gt.Equal(genTime) {
		t.Fatalf("token imprint alg/genTime mismatch: %s / %s", alg, gt)
	}
}

func TestAnchorRejectsWrongNonce(t *testing.T) {
	note := readFixture(t, "note.bin")
	respDER := readFixture(t, "response.der")
	srv, _ := tsaServer(t, respDER)
	// Client sends a nonce that will not match the fixture's echoed nonce.
	client := &TSAClient{URL: srv.URL, nonce: func() (*big.Int, error) { return big.NewInt(1), nil }}
	if _, err := client.Anchor(context.Background(), note); err == nil {
		t.Fatal("expected nonce round-trip failure")
	}
}

func TestAnchorRejectsWrongImprint(t *testing.T) {
	respDER := readFixture(t, "response.der")
	_, nonce, _ := fixtureToken(t, respDER)
	srv, _ := tsaServer(t, respDER)
	client := &TSAClient{URL: srv.URL, nonce: func() (*big.Int, error) { return nonce, nil }}
	// Feed bytes whose imprint differs from the fixture's imprint.
	if _, err := client.Anchor(context.Background(), []byte("different-bytes\n\n— x y\n")); err == nil {
		t.Fatal("expected imprint mismatch failure")
	}
}

func TestAnchorRejectsRejectedStatus(t *testing.T) {
	note := readFixture(t, "note.bin")
	// A minimal rejected TimeStampResp: PKIStatusInfo{status=2, "policy not
	// supported"}, no token.
	type rejStatus struct {
		Status       int
		StatusString []string
	}
	type rejResp struct {
		Status rejStatus
	}
	der, err := asn1.Marshal(rejResp{Status: rejStatus{Status: 2, StatusString: []string{"policy not supported"}}})
	if err != nil {
		t.Fatal(err)
	}
	srv, _ := tsaServer(t, der)
	client := &TSAClient{URL: srv.URL, nonce: func() (*big.Int, error) { return goldenNonce, nil }}
	_, err = client.Anchor(context.Background(), note)
	if err == nil {
		t.Fatal("expected rejection error")
	}
	if !bytes.Contains([]byte(err.Error()), []byte("policy not supported")) {
		t.Fatalf("error should carry the status string: %v", err)
	}
}
