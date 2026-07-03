package assess

import (
	"bytes"
	"compress/gzip"
	"io"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/arhuman/prooflog/internal/hashid"
)

func gzipString(t *testing.T, s string) io.Reader {
	t.Helper()
	var buf bytes.Buffer
	w := gzip.NewWriter(&buf)
	if _, err := w.Write([]byte(s)); err != nil {
		t.Fatalf("gzip write: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("gzip close: %v", err)
	}
	return &buf
}

func mustProfile(t *testing.T, name string) *Profile {
	t.Helper()
	p, err := LoadProfile(name)
	if err != nil {
		t.Fatalf("LoadProfile(%q): %v", name, err)
	}
	return p
}

func readOne(t *testing.T, profile *Profile, jsonl string) *Input {
	t.Helper()
	in, err := Read(profile, strings.NewReader(jsonl))
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	return in
}

func findingIDs(res SourceResult) []string {
	ids := make([]string, 0, len(res.Findings))
	for _, f := range res.Findings {
		ids = append(ids, f.ID)
	}
	return ids
}

func hasID(res SourceResult, id string) bool {
	for _, f := range res.Findings {
		if f.ID == id {
			return true
		}
	}
	return false
}

func TestEmbeddedProfilesValid(t *testing.T) {
	for _, name := range []string{"generic", "idp-signin", "cloudtrail", "immudb-export"} {
		p := mustProfile(t, name)
		if err := p.Validate(); err != nil {
			t.Errorf("profile %s invalid: %v", name, err)
		}
	}
}

func TestCapabilityDrivesAnalyzers(t *testing.T) {
	// idp-signin declares no sequence and no heartbeat: those analyses must not run.
	p := mustProfile(t, "idp-signin")
	caps := p.Capabilities()
	if caps.Sequenced || caps.Heartbeats {
		t.Fatalf("idp-signin should not be sequenced/heartbeat-capable: %+v", caps)
	}
	jsonl := `{"createdDateTime":"2026-01-02T00:00:00Z","userPrincipalName":"a@x","activityDisplayName":"signin"}
{"createdDateTime":"2026-01-02T01:00:00Z","userPrincipalName":"b@x","activityDisplayName":"signin"}`
	in := readOne(t, p, jsonl)
	if len(in.Sources) != 1 {
		t.Fatalf("want 1 source, got %d", len(in.Sources))
	}
	res := Assess(in.Sources[0], caps, DefaultPolicy(), Window{}, in.Malformed)
	if hasID(res, "A-SEQGAP") || hasID(res, "A-DUP") || hasID(res, "A-HBGAP") {
		t.Errorf("sequence/heartbeat findings must not appear without capability: %v", findingIDs(res))
	}
	if caps.Missing() == nil {
		t.Error("expected Missing() to disclose absent analyses")
	}
}

func TestSequenceGapAndDup(t *testing.T) {
	p := mustProfile(t, "generic")
	jsonl := `{"source":"s","time":"2026-01-01T00:00:00Z","seq":1,"type":"deploy"}
{"source":"s","time":"2026-01-01T00:01:00Z","seq":2,"type":"deploy"}
{"source":"s","time":"2026-01-01T00:05:00Z","seq":5,"type":"deploy"}
{"source":"s","time":"2026-01-01T00:05:01Z","seq":5,"type":"deploy"}`
	in := readOne(t, p, jsonl)
	res := Assess(in.Sources[0], p.Capabilities(), DefaultPolicy(), Window{}, in.Malformed)
	if !hasID(res, "A-SEQGAP") {
		t.Errorf("expected A-SEQGAP, got %v", findingIDs(res))
	}
	if !hasID(res, "A-DUP") {
		t.Errorf("expected A-DUP, got %v", findingIDs(res))
	}
	if res.SeqFirst != 1 || res.SeqLast != 5 {
		t.Errorf("seq range: got %d..%d", res.SeqFirst, res.SeqLast)
	}
	for _, f := range res.Findings {
		if f.ID == "A-SEQGAP" && !strings.Contains(f.Detail, "3-4") {
			t.Errorf("gap range should mention 3-4: %q", f.Detail)
		}
	}
}

func TestNoFindingsCleanSequence(t *testing.T) {
	p := mustProfile(t, "generic")
	jsonl := `{"source":"s","time":"2026-01-01T00:00:00Z","seq":1,"type":"deploy"}
{"source":"s","time":"2026-01-01T00:01:00Z","seq":2,"type":"deploy"}
{"source":"s","time":"2026-01-01T00:02:00Z","seq":3,"type":"deploy"}`
	in := readOne(t, p, jsonl)
	res := Assess(in.Sources[0], p.Capabilities(), DefaultPolicy(), Window{}, in.Malformed)
	if len(res.Findings) != 0 {
		t.Errorf("expected no findings, got %v", findingIDs(res))
	}
}

func TestHeartbeatGap(t *testing.T) {
	p := mustProfile(t, "generic")
	policy := Policy{HeartbeatInterval: 60 * time.Second, MaxSilence: 3 * time.Minute}
	jsonl := `{"source":"s","time":"2026-01-01T00:00:00Z","seq":1,"type":"heartbeat"}
{"source":"s","time":"2026-01-01T00:01:00Z","seq":2,"type":"heartbeat"}
{"source":"s","time":"2026-01-01T00:20:00Z","seq":3,"type":"heartbeat"}`
	in := readOne(t, p, jsonl)
	res := Assess(in.Sources[0], p.Capabilities(), policy, Window{}, in.Malformed)
	if !hasID(res, "A-HBGAP") {
		t.Errorf("expected A-HBGAP, got %v", findingIDs(res))
	}
	if len(res.Windows) != 1 || res.Windows[0].Bounded {
		t.Errorf("expected 1 unbounded window, got %+v", res.Windows)
	}
}

func TestCoverageHole(t *testing.T) {
	p := mustProfile(t, "generic")
	jsonl := `{"source":"s","time":"2026-03-01T00:00:00Z","seq":1,"type":"deploy"}
{"source":"s","time":"2026-03-02T00:00:00Z","seq":2,"type":"deploy"}`
	period := Window{
		Start: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		End:   time.Date(2026, 6, 30, 0, 0, 0, 0, time.UTC),
	}
	in := readOne(t, p, jsonl)
	res := Assess(in.Sources[0], p.Capabilities(), DefaultPolicy(), period, in.Malformed)
	if !hasID(res, "A-COVERAGE") {
		t.Errorf("expected A-COVERAGE, got %v", findingIDs(res))
	}
}

func TestTimeNonMonotonicWithSequence(t *testing.T) {
	// A timestamp stepping back by more than monotonicTolerance (1s) as the
	// sequence increases must raise A-TIME on its non-monotonic branch.
	p := mustProfile(t, "generic")
	jsonl := `{"source":"s","time":"2026-01-01T00:10:00Z","seq":1,"type":"a"}
{"source":"s","time":"2026-01-01T00:00:00Z","seq":2,"type":"a"}`
	in := readOne(t, p, jsonl)
	res := Assess(in.Sources[0], p.Capabilities(), DefaultPolicy(), Window{}, in.Malformed)
	if !hasID(res, "A-TIME") {
		t.Fatalf("expected A-TIME for a backwards timestamp beyond tolerance, got %v", findingIDs(res))
	}
	for _, f := range res.Findings {
		if f.ID == "A-TIME" && !strings.Contains(f.Detail, "time decreases as sequence increases") {
			t.Errorf("A-TIME should report the non-monotonic count: %q", f.Detail)
		}
	}

	// A backwards step within the tolerance must not raise it.
	within := `{"source":"s","time":"2026-01-01T00:00:01Z","seq":1,"type":"a"}
{"source":"s","time":"2026-01-01T00:00:00Z","seq":2,"type":"a"}`
	inW := readOne(t, p, within)
	resW := Assess(inW.Sources[0], p.Capabilities(), DefaultPolicy(), Window{}, inW.Malformed)
	if hasID(resW, "A-TIME") {
		t.Errorf("a 1s backwards step is within tolerance and must not raise A-TIME: %v", findingIDs(resW))
	}
}

func TestMalformedInputDigestDeterministic(t *testing.T) {
	p := mustProfile(t, "generic")
	jsonl := `{"source":"s","time":"2026-01-01T00:00:00Z","seq":1,"type":"deploy"}
not json at all
{"source":"s","time":"2026-01-01T00:01:00Z","seq":2,"type":"deploy"}`
	in1 := readOne(t, p, jsonl)
	in2 := readOne(t, p, jsonl)
	if in1.Digest != in2.Digest {
		t.Errorf("global digest not deterministic: %s vs %s", in1.Digest, in2.Digest)
	}
	if in1.Malformed != 1 {
		t.Errorf("expected 1 malformed, got %d", in1.Malformed)
	}
	if in1.Sources[0].Digest != in2.Sources[0].Digest {
		t.Error("per-source digest not deterministic")
	}
	// Heavy corruption should raise A-INPUT.
	heavy := "bad\nbad\n" + `{"source":"s","time":"2026-01-01T00:00:00Z","seq":1}`
	inH := readOne(t, p, heavy)
	resH := Assess(inH.Sources[0], p.Capabilities(), DefaultPolicy(), Window{}, inH.Malformed)
	if !hasID(resH, "A-INPUT") {
		t.Errorf("expected A-INPUT under heavy corruption, got %v", findingIDs(resH))
	}
}

func TestGzipTransparent(t *testing.T) {
	p := mustProfile(t, "generic")
	line := `{"source":"s","time":"2026-01-01T00:00:00Z","seq":1,"type":"deploy"}`
	plain := readOne(t, p, line)
	gz := gzipString(t, line)
	in, err := Read(p, gz)
	if err != nil {
		t.Fatalf("Read gzip: %v", err)
	}
	if in.Sources[0].Digest != plain.Sources[0].Digest {
		t.Error("gzip and plain should yield identical per-source digest")
	}
}

func TestCloudTrailNestedPath(t *testing.T) {
	p := mustProfile(t, "cloudtrail")
	jsonl := `{"eventSource":"iam.amazonaws.com","eventTime":"2026-01-01T00:00:00Z","eventName":"CreateUser","userIdentity":{"arn":"arn:aws:iam::1:user/root"}}`
	in := readOne(t, p, jsonl)
	if len(in.Sources) != 1 {
		t.Fatalf("want 1 source, got %d", len(in.Sources))
	}
	r := in.Sources[0].Records[0]
	if r.Actor != "arn:aws:iam::1:user/root" {
		t.Errorf("nested userIdentity.arn not extracted: %q", r.Actor)
	}
	if r.Type != "CreateUser" {
		t.Errorf("eventName not mapped: %q", r.Type)
	}
}

func TestLargeSequenceNumberPrecision(t *testing.T) {
	// Two consecutive sequence ids just above 2^53. As float64 both round to
	// 9007199254740992, which would fabricate a duplicate and hide the true
	// values. With json.Number they stay exact: no gap, no dup.
	p := mustProfile(t, "generic")
	jsonl := `{"source":"s","time":"2026-01-01T00:00:00Z","seq":9007199254740993,"type":"tx"}
{"source":"s","time":"2026-01-01T00:01:00Z","seq":9007199254740994,"type":"tx"}`
	in := readOne(t, p, jsonl)
	res := Assess(in.Sources[0], p.Capabilities(), DefaultPolicy(), Window{}, in.Malformed)
	if hasID(res, "A-DUP") {
		t.Errorf("distinct large seqs must not be seen as duplicates: %v", findingIDs(res))
	}
	if hasID(res, "A-SEQGAP") {
		t.Errorf("consecutive large seqs must not report a gap: %v", findingIDs(res))
	}
	if res.SeqFirst != 9007199254740993 || res.SeqLast != 9007199254740994 {
		t.Errorf("large seq precision lost: got %d..%d", res.SeqFirst, res.SeqLast)
	}
}

func TestOverLongLineCountedMalformedNotFatal(t *testing.T) {
	// Shrink the cap so the test line is cheap to build.
	orig := maxLineBytes
	maxLineBytes = 128
	defer func() { maxLineBytes = orig }()

	p := mustProfile(t, "generic")
	long := `{"source":"s","time":"2026-01-01T00:00:00Z","seq":2,"filler":"` + strings.Repeat("x", 400) + `"}`
	jsonl := strings.Join([]string{
		`{"source":"s","time":"2026-01-01T00:00:00Z","seq":1,"type":"ok"}`,
		long,
		`{"source":"s","time":"2026-01-01T00:02:00Z","seq":3,"type":"ok"}`,
	}, "\n")
	in, err := Read(p, strings.NewReader(jsonl))
	if err != nil {
		t.Fatalf("an over-long line must not abort the read: %v", err)
	}
	if in.Malformed != 1 {
		t.Errorf("over-long line should count as 1 malformed, got %d", in.Malformed)
	}
	if len(in.Sources) != 1 || in.Sources[0].RawCount != 2 {
		t.Fatalf("the two good records around the long line should survive: %+v", in.Sources)
	}
}

func TestOverLongLineTailBoundInDigest(t *testing.T) {
	// REQ-E-15: a changed export changes the digest — even when the change sits
	// past the retention cap of an over-long (malformed) line. Two inputs that
	// differ only in that drained tail must not share a digest.
	orig := maxLineBytes
	maxLineBytes = 128
	defer func() { maxLineBytes = orig }()

	p := mustProfile(t, "generic")
	good := `{"source":"s","time":"2026-01-01T00:00:00Z","seq":1,"type":"ok"}`
	prefix := `{"source":"s","filler":"` + strings.Repeat("x", 300) + `"`
	a := good + "\n" + prefix + `AAAA"}`
	b := good + "\n" + prefix + `BBBB"}`

	inA := readOne(t, p, a)
	inA2 := readOne(t, p, a)
	inB := readOne(t, p, b)
	if inA.Digest != inA2.Digest {
		t.Error("digest must be deterministic for identical input")
	}
	if inA.Digest == inB.Digest {
		t.Error("inputs differing only past the over-long-line cap must not share a digest")
	}
	// The drained tail also counts toward the bytes consumed.
	want := int64(len(good) + 1 + len(prefix) + len(`AAAA"}`) + 1)
	if inA.BytesRead != want {
		t.Errorf("BytesRead should include the drained tail: got %d, want %d", inA.BytesRead, want)
	}
}

func TestUnixTimestampLayout(t *testing.T) {
	p := mustProfile(t, "immudb-export")
	// tx as a large integer, ts as a unix epoch.
	jsonl := `{"tx":1024,"ts":1767225600,"source":"payments","type":"charge"}`
	in := readOne(t, p, jsonl)
	r := in.Sources[0].Records[0]
	if r.Time.IsZero() {
		t.Error("unix timestamp layout failed to parse")
	}
	if r.Seq == nil || *r.Seq != 1024 {
		t.Errorf("tx sequence not mapped: %+v", r.Seq)
	}
}

func TestReadLimitedTruncatesAndDiscloses(t *testing.T) {
	p := mustProfile(t, "generic")
	var lines []string
	for i := 1; i <= 10; i++ {
		lines = append(lines, `{"source":"s","time":"2026-01-01T00:00:00Z","seq":`+strconv.Itoa(i)+`,"type":"ok"}`)
	}
	in, err := ReadLimited(p, Limits{MaxRecords: 4}, strings.NewReader(strings.Join(lines, "\n")))
	if err != nil {
		t.Fatalf("ReadLimited: %v", err)
	}
	if !in.Truncated || in.TruncReason == "" {
		t.Errorf("expected truncation to be flagged and explained, got %+v", in)
	}
	if in.Sources[0].RawCount != 4 {
		t.Errorf("expected exactly 4 records kept, got %d", in.Sources[0].RawCount)
	}
	// Unlimited read of the same input must NOT be flagged truncated.
	full := readOne(t, p, strings.Join(lines, "\n"))
	if full.Truncated {
		t.Error("unlimited read must not be marked truncated")
	}
	if full.Sources[0].RawCount != 10 {
		t.Errorf("unlimited read should keep all 10, got %d", full.Sources[0].RawCount)
	}
}

func TestDigestUnaffectedByRawDrop(t *testing.T) {
	// Dropping the retained raw copy must not change the digest: it is still
	// computed over the same line bytes in order.
	p := mustProfile(t, "generic")
	jsonl := `{"source":"s","time":"2026-01-01T00:00:00Z","seq":1,"type":"a"}
{"source":"s","time":"2026-01-01T00:01:00Z","seq":2,"type":"b"}`
	a := readOne(t, p, jsonl)
	b := readOne(t, p, jsonl)
	if a.Digest != b.Digest || a.Sources[0].Digest != b.Sources[0].Digest {
		t.Error("digests must remain deterministic after dropping Raw")
	}
	if a.Digest == (hashid.Digest{}) || a.Sources[0].Digest == (hashid.Digest{}) {
		t.Error("digests must be populated")
	}
}

func TestProfileValidationErrors(t *testing.T) {
	_, err := parseProfile([]byte(`{"description":"no name"}`))
	if err == nil {
		t.Error("expected error for missing name")
	}
	_, err = parseProfile([]byte(`{"name":"x","timestamp":{"field":"t","layout":"bogus"}}`))
	if err == nil {
		t.Error("expected error for unknown layout")
	}
	_, err = parseProfile([]byte(`{"name":"x","unknown_key":1,"timestamp":{"field":"t"}}`))
	if err == nil {
		t.Error("expected error for unknown profile key")
	}
}
