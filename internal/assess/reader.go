package assess

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"hash"
	"io"
	"slices"
	"strconv"
	"strings"

	"github.com/arhuman/prooflog/internal/hashid"
)

// maxLineBytes bounds a single JSONL record so a pathological file cannot
// exhaust memory; a line longer than this is drained and counted malformed
// rather than aborting the read. It is a var only so tests can shrink it.
var maxLineBytes = 16 << 20

// SourceInput is the demuxed, normalized input for one source, with the digest
// binding the assessment to exactly these bytes.
type SourceInput struct {
	SourceID string
	Records  []Record
	Digest   hashid.Digest // SHA-256 over this source's raw record lines, in order
	RawCount int
}

// Input is the full result of reading one or more JSONL streams under a profile.
type Input struct {
	Sources   []SourceInput
	Malformed int
	Total     int           // non-empty lines read
	Digest    hashid.Digest // SHA-256 over every raw byte read, malformed and over-long lines included
	BytesRead int64         // approximate input bytes consumed (line content + newline)

	// Truncated is set when a Limits cap stopped the read before end of input;
	// TruncReason states which cap and its value. The assessment discloses this
	// loudly — there is no silent truncation.
	Truncated   bool
	TruncReason string
}

// Limits bounds how much of the input is retained in memory. A zero field means
// unlimited. When a cap is hit the read stops and Input.Truncated is set; the
// caller must surface it (the report and stderr both do).
type Limits struct {
	MaxRecords int   // max successfully-mapped records retained
	MaxBytes   int64 // max input bytes consumed
}

// defaultSourceID is used when a profile maps no source id.
const defaultSourceID = "assessed-source"

// Read consumes JSONL streams under the profile with no size limit. It is a thin
// wrapper over ReadLimited for callers (and tests) that do not bound input.
func Read(profile *Profile, streams ...io.Reader) (*Input, error) {
	return ReadLimited(profile, Limits{}, streams...)
}

// ReadLimited consumes JSONL streams (transparently gzip-decoded) under the
// profile, normalizes each line to a Record, demultiplexes by source preserving
// input order, and binds each source and the whole input to a SHA-256 digest.
// Each raw line is hashed into the digests at read time and then dropped, so
// memory tracks the retained normalized records, not the raw input size. When a
// Limits cap is reached the read stops and Input.Truncated is set. The result is
// deterministic for identical input bytes and limits.
func ReadLimited(profile *Profile, limits Limits, streams ...io.Reader) (*Input, error) {
	caps := profile.Capabilities()
	global := sha256.New()
	order := []string{}
	byID := map[string]*SourceInput{}
	perDigest := map[string]hash.Hash{}
	in := &Input{}
	kept := 0

	get := func(id string) *SourceInput {
		si, ok := byID[id]
		if !ok {
			si = &SourceInput{SourceID: id}
			byID[id] = si
			perDigest[id] = sha256.New()
			order = append(order, id)
		}
		return si
	}

	for _, s := range streams {
		if in.Truncated {
			break
		}
		r, err := maybeGunzip(s)
		if err != nil {
			return nil, err
		}
		br := bufio.NewReaderSize(r, 64<<10)
		for {
			// The drained tail of an over-long line goes into the global digest
			// too (ahead of its retained prefix — the serialization order is an
			// implementation detail; what matters is that identical inputs agree
			// and any changed byte, even past the cap, changes the digest).
			raw, tooLong, drained, e := readBoundedLine(br, maxLineBytes, global)
			line := bytes.TrimSpace(raw)
			if len(line) > 0 || tooLong {
				in.Total++
				in.BytesRead += int64(len(line)) + 1 + drained
				global.Write(line)
				global.Write([]byte{'\n'})

				if tooLong {
					// One over-long line is malformed and skipped, never fatal.
					in.Malformed++
				} else if rec, mErr := mapLine(profile, caps, line); mErr != nil {
					in.Malformed++
				} else {
					si := get(rec.SourceID)
					si.Records = append(si.Records, rec)
					si.RawCount++
					perDigest[rec.SourceID].Write(line)
					perDigest[rec.SourceID].Write([]byte{'\n'})
					kept++
				}
			}
			if e == io.EOF {
				break
			}
			if e != nil {
				return nil, fmt.Errorf("assess: read: %w", e)
			}
			if limits.MaxRecords > 0 && kept >= limits.MaxRecords {
				in.Truncated = true
				in.TruncReason = fmt.Sprintf("--max-records %d reached; remaining input not read", limits.MaxRecords)
				break
			}
			if limits.MaxBytes > 0 && in.BytesRead >= limits.MaxBytes {
				in.Truncated = true
				in.TruncReason = fmt.Sprintf("--max-bytes %d reached; remaining input not read", limits.MaxBytes)
				break
			}
		}
	}

	for _, id := range order {
		si := byID[id]
		d, err := hashid.ParseDigest(perDigest[id].Sum(nil))
		if err != nil {
			return nil, fmt.Errorf("assess: source digest: %w", err)
		}
		si.Digest = d
		in.Sources = append(in.Sources, *si)
	}
	d, err := hashid.ParseDigest(global.Sum(nil))
	if err != nil {
		return nil, fmt.Errorf("assess: input digest: %w", err)
	}
	in.Digest = d
	return in, nil
}

// readBoundedLine reads one newline-terminated line using at most max bytes of
// memory. A line longer than max is drained to its terminator and returned with
// tooLong=true (its prefix truncated at max), so a single pathological line
// neither exhausts memory nor aborts the read. Drained bytes beyond the cap are
// streamed into overflow and counted in drained, so the caller can still bind
// them into the input digest (REQ-E-15: a changed export changes the digest,
// even past the cap of an over-long line). The returned err is io.EOF on the
// final line and nil otherwise.
func readBoundedLine(br *bufio.Reader, limit int, overflow io.Writer) (line []byte, tooLong bool, drained int64, err error) {
	for {
		frag, e := br.ReadSlice('\n')
		if tooLong {
			overflow.Write(frag)
			drained += int64(len(frag))
		} else if len(line)+len(frag) > limit {
			tooLong = true
			room := limit - len(line)
			line = append(line, frag[:room]...)
			overflow.Write(frag[room:])
			drained += int64(len(frag) - room)
		} else {
			line = append(line, frag...)
		}
		switch e {
		case bufio.ErrBufferFull:
			continue // keep draining the rest of this (long) line
		case nil:
			return line, tooLong, drained, nil
		default: // io.EOF or a real read error
			return line, tooLong, drained, e
		}
	}
}

// mapLine parses one JSONL line and maps it to a normalized Record. Numbers are
// decoded as json.Number so large integer sequence ids keep full precision
// (float64 would silently round values above 2^53).
func mapLine(p *Profile, caps Capabilities, line []byte) (Record, error) {
	dec := json.NewDecoder(bytes.NewReader(line))
	dec.UseNumber()
	var obj map[string]any
	if err := dec.Decode(&obj); err != nil {
		return Record{}, err
	}
	var rec Record

	rec.SourceID = mapString(p.SourceID, obj, defaultSourceID)

	if p.Timestamp != nil {
		if v, ok := extract(obj, p.Timestamp.Field); ok {
			if t, err := p.Timestamp.parseTime(v); err == nil {
				rec.Time = t
			}
		}
	}
	if caps.Sequenced {
		if v, ok := extract(obj, p.Sequence.Field); ok {
			if n, ok := toUint64(v); ok {
				rec.Seq = &n
			}
		}
	}
	if caps.Typed {
		rec.Type = mapString(p.EventType, obj, "")
	}
	if caps.Actors {
		rec.Actor = mapString(p.Actor, obj, "")
	}
	if caps.Heartbeats {
		rec.Heartbeat = matchHeartbeat(p.Heartbeat, obj)
	}
	return rec, nil
}

func mapString(fm *FieldMap, obj map[string]any, fallback string) string {
	if fm == nil {
		return fallback
	}
	if fm.Const != "" {
		return fm.Const
	}
	if v, ok := extract(obj, fm.Field); ok {
		if s := stringify(v); s != "" {
			return s
		}
	}
	if fm.Default != "" {
		return fm.Default
	}
	return fallback
}

func matchHeartbeat(hm *HeartbeatMatch, obj map[string]any) bool {
	if hm == nil {
		return false
	}
	if hm.Field != "" {
		if v, ok := extract(obj, hm.Field); ok && stringify(v) == hm.Equals {
			return true
		}
	}
	if len(hm.Types) > 0 {
		if v, ok := extract(obj, hm.Field); ok && slices.Contains(hm.Types, stringify(v)) {
			return true
		}
	}
	return false
}

// extract walks a dotted path (with numeric segments indexing arrays) into a
// decoded JSON object: "a.b", "records.0.id".
func extract(obj map[string]any, path string) (any, bool) {
	if path == "" {
		return nil, false
	}
	var cur any = obj
	for seg := range strings.SplitSeq(path, ".") {
		switch node := cur.(type) {
		case map[string]any:
			v, ok := node[seg]
			if !ok {
				return nil, false
			}
			cur = v
		case []any:
			i, err := strconv.Atoi(seg)
			if err != nil || i < 0 || i >= len(node) {
				return nil, false
			}
			cur = node[i]
		default:
			return nil, false
		}
	}
	return cur, cur != nil
}

func stringify(v any) string {
	switch n := v.(type) {
	case string:
		return n
	case json.Number:
		return n.String()
	case bool:
		return strconv.FormatBool(n)
	default:
		return ""
	}
}

func toUint64(v any) (uint64, bool) {
	switch n := v.(type) {
	case json.Number:
		u, err := strconv.ParseUint(n.String(), 10, 64)
		return u, err == nil
	case string:
		u, err := strconv.ParseUint(n, 10, 64)
		return u, err == nil
	default:
		return 0, false
	}
}

// maybeGunzip wraps the reader in a gzip decoder when the stream starts with the
// gzip magic bytes, transparently handling gzipped archives.
func maybeGunzip(r io.Reader) (io.Reader, error) {
	br := bufio.NewReader(r)
	magic, err := br.Peek(2)
	if err != nil {
		if err == io.EOF {
			return br, nil
		}
		return nil, err
	}
	if magic[0] == 0x1f && magic[1] == 0x8b {
		return gzip.NewReader(br)
	}
	return br, nil
}

// jsonUnmarshalStrict decodes JSON rejecting unknown fields, so a mistyped
// profile key is a clear error instead of a silent no-op.
func jsonUnmarshalStrict(data []byte, v any) error {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	return dec.Decode(v)
}
