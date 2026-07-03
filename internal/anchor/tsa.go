package anchor

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/asn1"
	"encoding/base64"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"strings"
	"time"

	"github.com/arhuman/prooflog/internal/note"
)

// RFC 3161 wire constants.
const (
	contentTypeQuery = "application/timestamp-query"
	contentTypeReply = "application/timestamp-reply"
	maxReplyBytes    = 1 << 20 // 1 MiB is far above any real TimeStampResp
)

// Object identifiers used on the RFC 3161 / RFC 5652 wire.
var (
	oidSHA256   = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1} // id-sha256
	oidTSTInfo  = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 16, 1, 4}
	oidSignedDt = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 2} // id-signedData
)

// TSAClient anchors signed checkpoints against an RFC 3161 Time-Stamp
// Authority. It sends a SHA-256 message imprint of the exact signed-note bytes,
// verifies the returned token's imprint and nonce, and stores the whole DER
// token for offline verification (REQ-C-15).
//
// Full CMS signature-chain validation is intentionally out of scope here; the
// DER token is stored whole and verifiable offline (openssl ts -verify).
// github.com/digitorus/timestamp is a possible future option for in-process
// CMS validation.
type TSAClient struct {
	URL       string
	HTTP      *http.Client
	Qualified bool // operator declares this TSA eIDAS-qualified (Art. 41)

	// nonce generates the per-request nonce; nil uses crypto/rand. Overridable
	// in tests for deterministic request encoding.
	nonce func() (*big.Int, error)
}

// Name identifies the TSA for logs and reports.
func (c *TSAClient) Name() string { return "rfc3161:" + c.URL }

// Anchor timestamps signedNote against the TSA and returns a Receipt binding the
// note's checkpoint identity to the authority-attested genTime (REQ-C-15).
func (c *TSAClient) Anchor(ctx context.Context, signedNote []byte) (Receipt, error) {
	imprint := sha256.Sum256(signedNote)
	nonce, err := c.newNonce()
	if err != nil {
		return Receipt{}, fmt.Errorf("anchor: nonce: %w", err)
	}
	reqDER, err := buildTimeStampReq(imprint[:], nonce)
	if err != nil {
		return Receipt{}, fmt.Errorf("anchor: build request: %w", err)
	}

	respDER, err := c.post(ctx, reqDER)
	if err != nil {
		return Receipt{}, err
	}

	tst, token, err := parseTimeStampResp(respDER, imprint[:], nonce)
	if err != nil {
		return Receipt{}, err
	}

	cp, err := parseCheckpointNote(signedNote)
	if err != nil {
		return Receipt{}, fmt.Errorf("anchor: checkpoint: %w", err)
	}
	return Receipt{
		Origin:     cp.Origin,
		Size:       cp.Size,
		RootB64:    base64.StdEncoding.EncodeToString(cp.Hash[:]),
		TSA:        c.URL,
		Token:      token,
		GenTime:    tst.GenTime.UTC(),
		AnchoredAt: time.Now().UTC(),
		Qualified:  c.Qualified,
	}, nil
}

func (c *TSAClient) newNonce() (*big.Int, error) {
	if c.nonce != nil {
		return c.nonce()
	}
	// 64-bit unpredictable nonce; RFC 3161 leaves the size to the requester.
	return rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 64))
}

func (c *TSAClient) post(ctx context.Context, reqDER []byte) ([]byte, error) {
	client := c.HTTP
	if client == nil {
		client = &http.Client{Timeout: 30 * time.Second}
	}
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, c.URL, bytes.NewReader(reqDER))
	if err != nil {
		return nil, fmt.Errorf("anchor: request: %w", err)
	}
	httpReq.Header.Set("Content-Type", contentTypeQuery)
	resp, err := client.Do(httpReq)
	if err != nil {
		if resp != nil {
			resp.Body.Close()
		}
		return nil, fmt.Errorf("anchor: post %s: %w", c.URL, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("anchor: TSA returned HTTP %d", resp.StatusCode)
	}
	if ct := resp.Header.Get("Content-Type"); !strings.HasPrefix(ct, contentTypeReply) {
		return nil, fmt.Errorf("anchor: unexpected content-type %q", ct)
	}
	limited := &io.LimitedReader{R: resp.Body, N: maxReplyBytes + 1}
	body, err := io.ReadAll(limited)
	if err != nil {
		return nil, fmt.Errorf("anchor: read reply: %w", err)
	}
	if limited.N == 0 {
		return nil, fmt.Errorf("anchor: reply exceeds %d bytes", maxReplyBytes)
	}
	return body, nil
}

// --- RFC 3161 / RFC 5652 ASN.1 structures ---

type algorithmIdentifier struct {
	Algorithm  asn1.ObjectIdentifier
	Parameters asn1.RawValue `asn1:"optional"`
}

type messageImprint struct {
	HashAlgorithm algorithmIdentifier
	HashedMessage []byte
}

// tsRequest is a TimeStampReq (RFC 3161 §2.4.1). reqPolicy and extensions are
// omitted; certReq requests the TSA certificate in the token.
type tsRequest struct {
	Version        int
	MessageImprint messageImprint
	Nonce          *big.Int `asn1:"optional"`
	CertReq        bool     `asn1:"optional,default:false"`
}

type pkiStatusInfo struct {
	Status       int
	StatusString asn1.RawValue  `asn1:"optional"` // PKIFreeText: SEQUENCE OF UTF8String
	FailInfo     asn1.BitString `asn1:"optional"`
}

// timeStampResp is a TimeStampResp (RFC 3161 §2.4.2). Token is the CMS
// ContentInfo (the whole DER TimeStampToken).
type timeStampResp struct {
	Status pkiStatusInfo
	Token  asn1.RawValue `asn1:"optional"`
}

// contentInfo is an RFC 5652 ContentInfo carrying a SignedData.
type contentInfo struct {
	ContentType asn1.ObjectIdentifier
	Content     asn1.RawValue `asn1:"explicit,tag:0"`
}

type encapContentInfo struct {
	EContentType asn1.ObjectIdentifier
	EContent     []byte `asn1:"explicit,optional,tag:0"`
}

// signedData is an RFC 5652 SignedData. Certificates, CRLs, and signerInfos are
// captured but not validated (chain validation is out of scope; see the
// TSAClient doc comment).
type signedData struct {
	Version          int
	DigestAlgorithms asn1.RawValue
	EncapContentInfo encapContentInfo
	Certificates     asn1.RawValue `asn1:"optional,tag:0"`
	CRLs             asn1.RawValue `asn1:"optional,tag:1"`
	SignerInfos      asn1.RawValue
}

// accuracy is TSTInfo's optional Accuracy SEQUENCE; declared as a struct so
// optional detection matches the SEQUENCE tag when present and skips cleanly
// when absent.
type accuracy struct {
	Seconds int `asn1:"optional"`
	Millis  int `asn1:"optional,tag:0"`
	Micros  int `asn1:"optional,tag:1"`
}

// tstInfo is the TSTInfo eContent (RFC 3161 §2.4.2).
type tstInfo struct {
	Version        int
	Policy         asn1.ObjectIdentifier
	MessageImprint messageImprint
	SerialNumber   *big.Int
	GenTime        time.Time     `asn1:"generalized"`
	Accuracy       accuracy      `asn1:"optional"`
	Ordering       bool          `asn1:"optional,default:false"`
	Nonce          *big.Int      `asn1:"optional"`
	TSA            asn1.RawValue `asn1:"optional,tag:0"`
	Extensions     asn1.RawValue `asn1:"optional,tag:1"`
}

// buildTimeStampReq encodes a TimeStampReq for a SHA-256 imprint with a nonce
// and certReq set (REQ-C-15).
func buildTimeStampReq(imprint []byte, nonce *big.Int) ([]byte, error) {
	req := tsRequest{
		Version: 1,
		MessageImprint: messageImprint{
			HashAlgorithm: algorithmIdentifier{Algorithm: oidSHA256, Parameters: asn1.NullRawValue},
			HashedMessage: imprint,
		},
		Nonce:   nonce,
		CertReq: true,
	}
	return asn1.Marshal(req)
}

// parseTimeStampResp checks the PKI status, extracts the TSTInfo and the whole
// DER token, and verifies the imprint algorithm/value and nonce round-trip
// against what was sent (REQ-C-15).
func parseTimeStampResp(der, wantImprint []byte, wantNonce *big.Int) (tstInfo, []byte, error) {
	var resp timeStampResp
	if _, err := asn1.Unmarshal(der, &resp); err != nil {
		return tstInfo{}, nil, fmt.Errorf("anchor: parse response: %w", err)
	}
	switch resp.Status.Status {
	case 0, 1: // granted, grantedWithMods
	default:
		return tstInfo{}, nil, fmt.Errorf("anchor: TSA rejected request (status %d%s)",
			resp.Status.Status, statusString(resp.Status.StatusString))
	}
	if len(resp.Token.FullBytes) == 0 {
		return tstInfo{}, nil, fmt.Errorf("anchor: response carries no token")
	}
	token := resp.Token.FullBytes

	tst, err := parseTimeStampToken(token)
	if err != nil {
		return tstInfo{}, nil, err
	}
	if !tst.MessageImprint.HashAlgorithm.Algorithm.Equal(oidSHA256) {
		return tstInfo{}, nil, fmt.Errorf("anchor: token imprint algorithm %v is not SHA-256",
			tst.MessageImprint.HashAlgorithm.Algorithm)
	}
	if !bytes.Equal(tst.MessageImprint.HashedMessage, wantImprint) {
		return tstInfo{}, nil, fmt.Errorf("anchor: token imprint does not match the request")
	}
	if tst.Nonce == nil || wantNonce == nil || tst.Nonce.Cmp(wantNonce) != 0 {
		return tstInfo{}, nil, fmt.Errorf("anchor: token nonce does not round-trip")
	}
	return tst, token, nil
}

// parseTimeStampToken unwraps a CMS ContentInfo → SignedData → TSTInfo.
func parseTimeStampToken(token []byte) (tstInfo, error) {
	var ci contentInfo
	if _, err := asn1.Unmarshal(token, &ci); err != nil {
		return tstInfo{}, fmt.Errorf("anchor: parse token: %w", err)
	}
	if !ci.ContentType.Equal(oidSignedDt) {
		return tstInfo{}, fmt.Errorf("anchor: token content type %v is not signedData", ci.ContentType)
	}
	var sd signedData
	if _, err := asn1.Unmarshal(ci.Content.Bytes, &sd); err != nil {
		return tstInfo{}, fmt.Errorf("anchor: parse signedData: %w", err)
	}
	if !sd.EncapContentInfo.EContentType.Equal(oidTSTInfo) {
		return tstInfo{}, fmt.Errorf("anchor: eContent type %v is not TSTInfo", sd.EncapContentInfo.EContentType)
	}
	var tst tstInfo
	if _, err := asn1.Unmarshal(sd.EncapContentInfo.EContent, &tst); err != nil {
		return tstInfo{}, fmt.Errorf("anchor: parse TSTInfo: %w", err)
	}
	return tst, nil
}

// ParseTokenImprint extracts the message imprint, hash-algorithm OID, and
// genTime from a stored DER TimeStampToken, for offline cross-checking of a
// receipt against the checkpoint note it should cover (REQ-C-15).
func ParseTokenImprint(token []byte) (imprint []byte, hashAlg string, genTime time.Time, err error) {
	tst, err := parseTimeStampToken(token)
	if err != nil {
		return nil, "", time.Time{}, err
	}
	return tst.MessageImprint.HashedMessage,
		tst.MessageImprint.HashAlgorithm.Algorithm.String(),
		tst.GenTime.UTC(), nil
}

// statusString renders a PKIFreeText (SEQUENCE OF UTF8String) for error detail.
func statusString(raw asn1.RawValue) string {
	if len(raw.FullBytes) == 0 {
		return ""
	}
	var msgs []string
	if _, err := asn1.Unmarshal(raw.FullBytes, &msgs); err != nil || len(msgs) == 0 {
		return ""
	}
	return ": " + strings.Join(msgs, "; ")
}

// parseCheckpointNote extracts the checkpoint body (origin/size/root) from a
// signed note, without verifying its signature — the receipt metadata only; the
// imprint over the exact bytes is what binds the anchor (REQ-C-15).
func parseCheckpointNote(signedNote []byte) (note.Checkpoint, error) {
	s := string(signedNote)
	split := strings.LastIndex(s, "\n\n")
	if split < 0 {
		return note.Checkpoint{}, fmt.Errorf("malformed signed note")
	}
	return note.ParseCheckpoint(s[:split+1])
}
