package spool

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/arhuman/prooflog/internal/envelope"
)

// Iter streams stored records with seq >= fromSeq, in sequence order, for
// replay from the last ACKed offset (REQ-E-04).
type Iter struct {
	files   []string
	idx     int
	fromSeq uint64
	f       *os.File
	r       *bufio.Reader
}

// Iter returns an iterator over records with seq >= fromSeq.
func (s *Spool) Iter(fromSeq uint64) (*Iter, error) {
	s.mu.Lock()
	files, err := s.segmentFiles()
	// Skip leading sealed segments whose highest seq is below fromSeq: replay only
	// needs records past the ACK watermark, and those sealed segments were already
	// integrity-checked at write time, so re-parsing and re-hashing them here would
	// be wasted work. An unknown max seq means the active/unsealed tail file, which
	// is never skipped. This bounds Iter's cost by one boundary segment instead of
	// the whole spool history under the never-pruned Block policy (REQ-E-04).
	start := 0
	for start < len(files) {
		maxSeq, ok := s.maxSeqByFile[files[start]]
		if !ok || maxSeq >= fromSeq {
			break
		}
		start++
	}
	s.mu.Unlock()
	if err != nil {
		return nil, err
	}
	return &Iter{files: files[start:], fromSeq: fromSeq}, nil
}

// Next returns the next record with seq >= fromSeq. ok is false at the end.
func (it *Iter) Next() (rec envelope.Record, ok bool, err error) {
	for {
		if it.r == nil {
			if it.idx >= len(it.files) {
				return envelope.Record{}, false, nil
			}
			f, err := os.Open(it.files[it.idx])
			if err != nil {
				return envelope.Record{}, false, fmt.Errorf("spool: iter open: %w", err)
			}
			it.f = f
			it.r = bufio.NewReader(f)
			it.idx++
		}
		body, hash, _, err := readFrame(it.r)
		if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
			_ = it.f.Close()
			it.f, it.r = nil, nil
			continue
		}
		if err != nil {
			return envelope.Record{}, false, err
		}
		parsed, err := envelope.Parse(body)
		if err != nil {
			return envelope.Record{}, false, fmt.Errorf("spool: iter parse: %w", err)
		}
		if parsed.Hash() != hash {
			return envelope.Record{}, false, &CorruptionError{File: it.files[it.idx-1], LastGoodSeq: parsed.Seq, Reason: "hash mismatch"}
		}
		if parsed.Seq < it.fromSeq {
			continue
		}
		return parsed, true, nil
	}
}

// Close releases the iterator's open file, if any.
func (it *Iter) Close() error {
	if it.f != nil {
		err := it.f.Close()
		it.f, it.r = nil, nil
		if err != nil {
			return fmt.Errorf("spool: iter close: %w", err)
		}
	}
	return nil
}
