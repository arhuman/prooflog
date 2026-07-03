// Package spool is the per-source append-only durable spool. Records are stored
// as binary frames in segment files; appends are fsynced before returning so
// acceptance is durable, and disk pressure triggers a defined, configurable
// policy (REQ-C-04, REQ-E-03, REQ-E-04, REQ-E-09).
package spool

import (
	"bufio"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"

	"github.com/arhuman/prooflog/internal/envelope"
)

const (
	segExt      = ".plogseg"
	stateFile   = "state.json"
	hashSize    = 32
	segNameFmt  = "%020d" + segExt
	maxFrameLen = 16 << 20
	// freeSpaceTTL bounds how long one statfs probe is reused across a burst of
	// appends, so an ingest burst does not statfs on every record (REQ-E-09). A
	// slightly stale reading within the window is acceptable; block/drop
	// thresholds still trigger once the cache refreshes.
	freeSpaceTTL = time.Second
)

// defaultFreeSpace is set by a platform build file; nil on unsupported systems.
var defaultFreeSpace func(dir string) (uint64, error)

// Policy selects the action taken when the spool crosses its disk-pressure
// threshold (REQ-E-09).
type Policy int

const (
	// Block refuses new events when under disk pressure (default, FAU_STG.4).
	Block Policy = iota
	// DropOldest deletes the oldest fully-sealed and acked segment to make room.
	DropOldest
)

// ErrSpoolFull is returned by Append under the Block policy when disk is low.
var ErrSpoolFull = errors.New("spool: disk pressure, append blocked")

// CorruptionError reports a damaged frame found while scanning, identifying the
// last sequence number that verified cleanly.
type CorruptionError struct {
	File        string
	LastGoodSeq uint64
	Reason      string
}

func (e *CorruptionError) Error() string {
	return fmt.Sprintf("spool: corruption in %s after seq %d: %s", e.File, e.LastGoodSeq, e.Reason)
}

// Config configures a Spool.
type Config struct {
	Dir            string
	ThresholdBytes uint64
	Policy         Policy
	// OnPressure is invoked with the observed free bytes when the threshold is
	// crossed, so the agent can record system.local_spool_pressure (REQ-E-09).
	OnPressure func(freeBytes uint64)
	// FreeSpace probes available bytes; defaults to a syscall-backed probe.
	FreeSpace func(dir string) (uint64, error)
}

// Spool is an append-only per-source record store (REQ-E-04).
type Spool struct {
	cfg            Config
	mu             sync.Mutex
	active         *os.File
	activeFirstSeq uint64
	lastSeq        uint64
	ackedSeq       uint64
	// maxSeqByFile caches each sealed segment's highest seq (guarded by mu), so
	// dropOldestAcked need not rescan sealed segments on every pressure event.
	maxSeqByFile map[string]uint64
	// frameBuf is reused across appends to assemble each frame in one buffer and
	// issue a single Write before the fsync, cutting the per-record syscall count
	// (guarded by mu).
	frameBuf []byte
	// cacheFreeSpace enables the short-TTL free-space cache below. It is disabled
	// when the caller injects Config.FreeSpace so pressure tests observe every
	// fresh reading; the real statfs-backed probe is always cached.
	cacheFreeSpace  bool
	freeSpaceValid  bool
	freeSpaceCached uint64
	freeSpaceAt     time.Time
}

type stateData struct {
	AckedSeq uint64 `json:"acked_seq"`
}

// Open opens or creates the spool at cfg.Dir, recovering LastSeq by scanning
// segment files and self-healing a truncated trailing frame. Corruption inside
// a completed segment returns a *CorruptionError (REQ-C-04).
func Open(cfg Config) (*Spool, error) {
	injected := cfg.FreeSpace != nil
	if cfg.FreeSpace == nil {
		cfg.FreeSpace = defaultFreeSpace
	}
	if err := os.MkdirAll(cfg.Dir, 0o700); err != nil {
		return nil, fmt.Errorf("spool: mkdir: %w", err)
	}
	s := &Spool{cfg: cfg, cacheFreeSpace: !injected}
	if err := s.loadState(); err != nil {
		return nil, err
	}
	files, err := s.segmentFiles()
	if err != nil {
		return nil, err
	}
	s.maxSeqByFile = make(map[string]uint64, len(files))
	for i, f := range files {
		last := i == len(files)-1
		maxSeq, err := scanSegment(f, last)
		if err != nil {
			return nil, err
		}
		// The mandatory recovery scan already computes maxSeq per file, so the
		// cache is free at startup (REQ-C-04); no state.json change needed.
		s.maxSeqByFile[f] = maxSeq
		if maxSeq > s.lastSeq {
			s.lastSeq = maxSeq
		}
	}
	return s, nil
}

// LastSeq returns the highest sequence number durably stored.
func (s *Spool) LastSeq() uint64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.lastSeq
}

// AckedSeq returns the highest sequence number acked by the store.
func (s *Spool) AckedSeq() uint64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.ackedSeq
}

// Append durably stores rec, fsyncing before returning (REQ-E-04). It enforces
// the disk-pressure policy before writing (REQ-E-09).
func (s *Spool) Append(rec envelope.Record) error {
	if len(rec.Bytes()) == 0 {
		return fmt.Errorf("spool: record not serialized")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.enforcePressure(); err != nil {
		return err
	}
	if s.active == nil {
		if err := s.openActive(rec.Seq); err != nil {
			return err
		}
	}
	if err := s.writeFrame(rec.Bytes(), rec.Hash()); err != nil {
		return err
	}
	if err := s.active.Sync(); err != nil {
		return fmt.Errorf("spool: fsync: %w", err)
	}
	s.lastSeq = rec.Seq
	return nil
}

// Roll closes the active segment so the next Append starts a new segment file.
// Sealed files are never reopened for writing (REQ-C-04, §4.4).
func (s *Spool) Roll() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.closeActive()
}

// MarkAcked persists that the store has durably accepted records up to uptoSeq.
func (s *Spool) MarkAcked(uptoSeq uint64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if uptoSeq < s.ackedSeq {
		return nil
	}
	s.ackedSeq = uptoSeq
	return s.saveState()
}

// Close flushes and closes the active segment.
func (s *Spool) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.closeActive()
}

func (s *Spool) openActive(firstSeq uint64) error {
	name := filepath.Join(s.cfg.Dir, fmt.Sprintf(segNameFmt, firstSeq))
	f, err := os.OpenFile(name, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return fmt.Errorf("spool: open segment: %w", err)
	}
	s.active = f
	s.activeFirstSeq = firstSeq
	return nil
}

func (s *Spool) closeActive() error {
	if s.active == nil {
		return nil
	}
	name := s.active.Name()
	first := s.activeFirstSeq
	err := s.active.Close()
	s.active = nil
	if err != nil {
		return fmt.Errorf("spool: close segment: %w", err)
	}
	// Record the sealed segment's max seq for dropOldestAcked. Only cache when a
	// record actually reached this file: a write failure after openActive leaves
	// lastSeq below the file's firstSeq, so guard against caching a stale max.
	if s.lastSeq >= first {
		s.maxSeqByFile[name] = s.lastSeq
	}
	return nil
}

func (s *Spool) enforcePressure() error {
	if s.cfg.ThresholdBytes == 0 || s.cfg.FreeSpace == nil {
		return nil
	}
	free, err := s.probeFreeSpace()
	if err != nil {
		return fmt.Errorf("spool: free space: %w", err)
	}
	if free >= s.cfg.ThresholdBytes {
		return nil
	}
	if s.cfg.OnPressure != nil {
		s.cfg.OnPressure(free)
	}
	if s.cfg.Policy == DropOldest {
		if dropped, err := s.dropOldestAcked(); err != nil {
			return err
		} else if dropped {
			return nil
		}
	}
	return ErrSpoolFull
}

// probeFreeSpace returns available bytes, reusing the last statfs reading within
// freeSpaceTTL so a burst of appends does not statfs per record. The cache is
// bypassed when Config.FreeSpace was injected, so pressure tests that mutate an
// injected probe observe each fresh value immediately. Called under s.mu.
func (s *Spool) probeFreeSpace() (uint64, error) {
	if !s.cacheFreeSpace {
		return s.cfg.FreeSpace(s.cfg.Dir)
	}
	now := time.Now()
	if s.freeSpaceValid && now.Sub(s.freeSpaceAt) < freeSpaceTTL {
		return s.freeSpaceCached, nil
	}
	free, err := s.cfg.FreeSpace(s.cfg.Dir)
	if err != nil {
		return 0, err
	}
	s.freeSpaceCached = free
	s.freeSpaceAt = now
	s.freeSpaceValid = true
	return free, nil
}

// dropOldestAcked deletes the oldest non-active segment fully acked by the
// store, returning whether one was dropped.
func (s *Spool) dropOldestAcked() (bool, error) {
	files, err := s.segmentFiles()
	if err != nil {
		return false, err
	}
	activeName := ""
	if s.active != nil {
		activeName = s.active.Name()
	}
	for _, f := range files {
		if f == activeName {
			continue
		}
		// Seqs are strictly monotonic across segments (file names encode firstSeq
		// and are sorted), so the oldest non-active segment holds the lowest seqs:
		// if it is not fully acked no later segment can be either. Checking only
		// the oldest is therefore sufficient — hence the unconditional return.
		maxSeq, ok := s.maxSeqByFile[f]
		if !ok {
			// Cache miss should not happen (Open and closeActive populate it), but
			// fall back to a scan for robustness and repopulate the cache.
			scanned, err := scanSegment(f, false)
			if err != nil {
				return false, err
			}
			maxSeq = scanned
			s.maxSeqByFile[f] = scanned
		}
		if maxSeq <= s.ackedSeq {
			if err := os.Remove(f); err != nil {
				return false, fmt.Errorf("spool: drop segment: %w", err)
			}
			delete(s.maxSeqByFile, f)
			return true, nil
		}
		return false, nil
	}
	return false, nil
}

func (s *Spool) segmentFiles() ([]string, error) {
	matches, err := filepath.Glob(filepath.Join(s.cfg.Dir, "*"+segExt))
	if err != nil {
		return nil, fmt.Errorf("spool: list segments: %w", err)
	}
	sort.Strings(matches)
	return matches, nil
}

func (s *Spool) loadState() error {
	b, err := os.ReadFile(filepath.Join(s.cfg.Dir, stateFile))
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("spool: read state: %w", err)
	}
	var st stateData
	if err := json.Unmarshal(b, &st); err != nil {
		return fmt.Errorf("spool: parse state: %w", err)
	}
	s.ackedSeq = st.AckedSeq
	return nil
}

func (s *Spool) saveState() error {
	b, err := json.Marshal(stateData{AckedSeq: s.ackedSeq})
	if err != nil {
		return fmt.Errorf("spool: marshal state: %w", err)
	}
	tmp := filepath.Join(s.cfg.Dir, stateFile+".tmp")
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return fmt.Errorf("spool: write state: %w", err)
	}
	if err := os.Rename(tmp, filepath.Join(s.cfg.Dir, stateFile)); err != nil {
		return fmt.Errorf("spool: commit state: %w", err)
	}
	return nil
}

// writeFrame assembles one frame — the same on-disk layout readFrame parses:
// [uvarint body length][body][32-byte hash] — into the reusable s.frameBuf and
// issues a single Write, so the fsync in Append remains the sole durability
// boundary (REQ-E-04). Called under s.mu.
func (s *Spool) writeFrame(recordBytes []byte, hash [32]byte) error {
	buf := s.frameBuf[:0]
	var hdr [binary.MaxVarintLen64]byte
	n := binary.PutUvarint(hdr[:], uint64(len(recordBytes)))
	buf = append(buf, hdr[:n]...)
	buf = append(buf, recordBytes...)
	buf = append(buf, hash[:]...)
	s.frameBuf = buf
	if _, err := s.active.Write(buf); err != nil {
		return fmt.Errorf("spool: write frame: %w", err)
	}
	return nil
}

// scanSegment verifies every frame in a segment file, returning the highest
// sequence number found. If allowTailHeal is set, a truncated trailing frame is
// truncated away (crash recovery); otherwise it is reported as corruption.
func scanSegment(path string, allowTailHeal bool) (uint64, error) {
	f, err := os.OpenFile(path, os.O_RDWR, 0o600)
	if err != nil {
		return 0, fmt.Errorf("spool: open for scan: %w", err)
	}
	defer f.Close()

	r := bufio.NewReader(f)
	var maxSeq, offset uint64
	for {
		recordBytes, hash, consumed, err := readFrame(r)
		if errors.Is(err, io.EOF) {
			return maxSeq, nil
		}
		if errors.Is(err, io.ErrUnexpectedEOF) {
			if allowTailHeal {
				if terr := f.Truncate(int64(offset)); terr != nil {
					return 0, fmt.Errorf("spool: heal truncate: %w", terr)
				}
				return maxSeq, nil
			}
			return 0, &CorruptionError{File: path, LastGoodSeq: maxSeq, Reason: "truncated frame"}
		}
		if err != nil {
			return 0, err
		}
		if sha256.Sum256(recordBytes) != hash {
			return 0, &CorruptionError{File: path, LastGoodSeq: maxSeq, Reason: "hash mismatch"}
		}
		rec, err := envelope.Parse(recordBytes)
		if err != nil {
			return 0, &CorruptionError{File: path, LastGoodSeq: maxSeq, Reason: err.Error()}
		}
		maxSeq = rec.Seq
		offset += consumed
	}
}

// readFrame reads one frame, returning its record bytes, hash, bytes consumed,
// and io.EOF at a clean boundary or io.ErrUnexpectedEOF on a partial frame.
func readFrame(r *bufio.Reader) ([]byte, [32]byte, uint64, error) {
	var hash [32]byte
	if _, err := r.Peek(1); err != nil {
		if errors.Is(err, io.EOF) {
			return nil, hash, 0, io.EOF
		}
		return nil, hash, 0, fmt.Errorf("spool: peek frame: %w", err)
	}
	length, hdrLen, err := readUvarintLen(r)
	if err != nil {
		return nil, hash, 0, err
	}
	if length == 0 || length > maxFrameLen {
		return nil, hash, 0, fmt.Errorf("spool: implausible frame length %d", length)
	}
	body := make([]byte, length)
	if _, err := io.ReadFull(r, body); err != nil {
		return nil, hash, 0, io.ErrUnexpectedEOF
	}
	if _, err := io.ReadFull(r, hash[:]); err != nil {
		return nil, hash, 0, io.ErrUnexpectedEOF
	}
	return body, hash, uint64(hdrLen) + length + hashSize, nil
}

func readUvarintLen(r *bufio.Reader) (uint64, int, error) {
	var x uint64
	var s uint
	for i := 0; i < binary.MaxVarintLen64; i++ {
		b, err := r.ReadByte()
		if err != nil {
			return 0, 0, io.ErrUnexpectedEOF
		}
		if b < 0x80 {
			return x | uint64(b)<<s, i + 1, nil
		}
		x |= uint64(b&0x7f) << s
		s += 7
	}
	return 0, 0, fmt.Errorf("spool: varint overflow")
}
