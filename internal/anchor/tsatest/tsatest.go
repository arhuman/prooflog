// Package tsatest provides in-process RFC 3161 fakes for tests: MintToken
// assembles a minimal DER TimeStampToken (no CMS signature — chain validation
// is out of scope for the anchor client) and FakeAnchor implements anchor.Anchor
// without a network TSA. It is test support only, kept out of the anchor
// package's production surface (cf. net/http/httptest).
package tsatest

import (
	"context"
	"crypto/sha256"
	"encoding/asn1"
	"encoding/base64"
	"fmt"
	"math/big"
	"strings"
	"time"

	"github.com/arhuman/prooflog/internal/anchor"
	"github.com/arhuman/prooflog/internal/note"
)

var (
	oidSHA256    = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}
	oidTSTInfo   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 16, 1, 4}
	oidSignedDt  = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 2}
	oidTestPolcy = asn1.ObjectIdentifier{1, 2, 3, 4, 1}
)

type algorithmIdentifier struct {
	Algorithm  asn1.ObjectIdentifier
	Parameters asn1.RawValue `asn1:"optional"`
}

type messageImprint struct {
	HashAlgorithm algorithmIdentifier
	HashedMessage []byte
}

type tstInfo struct {
	Version        int
	Policy         asn1.ObjectIdentifier
	MessageImprint messageImprint
	SerialNumber   *big.Int
	GenTime        time.Time `asn1:"generalized"`
	Nonce          *big.Int  `asn1:"optional"`
}

type encapContentInfo struct {
	EContentType asn1.ObjectIdentifier
	EContent     []byte `asn1:"explicit,optional,tag:0"`
}

type signedData struct {
	Version          int
	DigestAlgorithms []algorithmIdentifier `asn1:"set"`
	EncapContentInfo encapContentInfo
	SignerInfos      []asn1.RawValue `asn1:"set"`
}

type contentInfo struct {
	ContentType asn1.ObjectIdentifier
	Content     signedData `asn1:"explicit,tag:0"`
}

// MintToken assembles a minimal, structurally valid DER TimeStampToken carrying
// the given imprint, nonce, and genTime. The CMS SignerInfos set is empty: the
// anchor client stores and parses tokens but does not validate their signature.
func MintToken(imprint []byte, nonce *big.Int, genTime time.Time) ([]byte, error) {
	sha := algorithmIdentifier{Algorithm: oidSHA256, Parameters: asn1.NullRawValue}
	tst := tstInfo{
		Version:        1,
		Policy:         oidTestPolcy,
		MessageImprint: messageImprint{HashAlgorithm: sha, HashedMessage: imprint},
		SerialNumber:   big.NewInt(1),
		GenTime:        genTime.UTC(),
		Nonce:          nonce,
	}
	eContent, err := asn1.Marshal(tst)
	if err != nil {
		return nil, err
	}
	sd := signedData{
		Version:          3,
		DigestAlgorithms: []algorithmIdentifier{sha},
		EncapContentInfo: encapContentInfo{EContentType: oidTSTInfo, EContent: eContent},
		SignerInfos:      []asn1.RawValue{},
	}
	ci := contentInfo{ContentType: oidSignedDt, Content: sd}
	return asn1.Marshal(ci)
}

// FakeAnchor implements anchor.Anchor by minting a token over the signed-note
// bytes and returning a receipt with the checkpoint identity parsed back out.
type FakeAnchor struct {
	TSA       string
	Qualified bool
	GenTime   time.Time // fixed attested time; zero uses time.Now
	Nonce     *big.Int  // fixed nonce; nil uses a constant
	Fail      error     // when set, Anchor returns this error
}

// Name identifies the fake anchor.
func (f *FakeAnchor) Name() string { return "fake:" + f.TSA }

// Anchor mints a receipt for signedNote.
func (f *FakeAnchor) Anchor(_ context.Context, signedNote []byte) (anchor.Receipt, error) {
	if f.Fail != nil {
		return anchor.Receipt{}, f.Fail
	}
	imprint := sha256.Sum256(signedNote)
	nonce := f.Nonce
	if nonce == nil {
		nonce = big.NewInt(0x0BADC0DE)
	}
	gen := f.GenTime
	if gen.IsZero() {
		gen = time.Now().UTC()
	}
	token, err := MintToken(imprint[:], nonce, gen)
	if err != nil {
		return anchor.Receipt{}, err
	}
	cp, err := parseCheckpoint(signedNote)
	if err != nil {
		return anchor.Receipt{}, err
	}
	tsa := f.TSA
	if tsa == "" {
		tsa = "https://tsa.test/tsr"
	}
	return anchor.Receipt{
		Origin:     cp.Origin,
		Size:       cp.Size,
		RootB64:    base64.StdEncoding.EncodeToString(cp.Hash[:]),
		TSA:        tsa,
		Token:      token,
		GenTime:    gen.UTC(),
		AnchoredAt: time.Now().UTC(),
		Qualified:  f.Qualified,
	}, nil
}

func parseCheckpoint(signedNote []byte) (note.Checkpoint, error) {
	s := string(signedNote)
	split := strings.LastIndex(s, "\n\n")
	if split < 0 {
		return note.Checkpoint{}, fmt.Errorf("tsatest: malformed signed note")
	}
	return note.ParseCheckpoint(s[:split+1])
}
