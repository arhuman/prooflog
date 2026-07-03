package verifier

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/arhuman/prooflog/internal/note"
)

const checkpointExt = ".notes"

// ForkError reports a checkpoint that violates the append-only commitment: a
// tree that shrank (rollback/truncation) or a different root at an already-seen
// size (equivocation). Refusing forks is the v1 trust anchor (REQ-C-07).
type ForkError struct {
	Origin   string
	PrevSize uint64
	NewSize  uint64
	Reason   string
}

func (e *ForkError) Error() string {
	return fmt.Sprintf("verifier: fork on %s (prev size %d, new size %d): %s",
		e.Origin, e.PrevSize, e.NewSize, e.Reason)
}

// CheckpointStore durably persists accepted checkpoints as append-only JSON
// lines, one file per source, and tracks the last accepted checkpoint per origin
// for submission-time fork detection (REQ-C-07). Append-only files (not SQLite)
// keep the trust anchor's own storage simple and audit-friendly: the verifier is
// content-blind and only ever appends signed notes it accepted.
type CheckpointStore struct {
	dir  string
	mu   sync.Mutex
	last map[string]note.Checkpoint // keyed by origin
}

// OpenCheckpointStore opens or creates the checkpoint store at dir, rebuilding
// the per-origin last-checkpoint index from the persisted notes.
func OpenCheckpointStore(dir string) (*CheckpointStore, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("verifier: mkdir checkpoints: %w", err)
	}
	c := &CheckpointStore{dir: dir, last: make(map[string]note.Checkpoint)}
	matches, err := filepath.Glob(filepath.Join(dir, "*"+checkpointExt))
	if err != nil {
		return nil, fmt.Errorf("verifier: list checkpoints: %w", err)
	}
	for _, path := range matches {
		notes, err := readNotesFile(path)
		if err != nil {
			return nil, err
		}
		for _, signed := range notes {
			cp, err := CheckpointOf(signed)
			if err != nil {
				return nil, err
			}
			if prev, ok := c.last[cp.Origin]; !ok || cp.Size >= prev.Size {
				c.last[cp.Origin] = cp
			}
		}
	}
	return c, nil
}

// LastFor returns the last accepted checkpoint for origin.
func (c *CheckpointStore) LastFor(origin string) (note.Checkpoint, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	cp, ok := c.last[origin]
	return cp, ok
}

// Accept applies the append-only rule to cp and, if consistent, durably appends
// the signed note for sourceID and advances the per-origin head. It returns a
// *ForkError for a rollback or equivocation (REQ-C-07).
func (c *CheckpointStore) Accept(sourceID, signed string, cp note.Checkpoint) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if prev, ok := c.last[cp.Origin]; ok {
		switch {
		case cp.Size < prev.Size:
			return &ForkError{cp.Origin, prev.Size, cp.Size, "tree size decreased"}
		case cp.Size == prev.Size && cp.Hash != prev.Hash:
			return &ForkError{cp.Origin, prev.Size, cp.Size, "different root at same tree size"}
		case cp.Size == prev.Size && cp.Hash == prev.Hash:
			return nil // idempotent re-submission; already persisted
		}
	}
	if err := appendNote(c.notesPath(sourceID), signed); err != nil {
		return err
	}
	c.last[cp.Origin] = cp
	return nil
}

// All returns every signed checkpoint persisted for sourceID, in receipt order.
func (c *CheckpointStore) All(sourceID string) ([]string, error) {
	return readNotesFile(c.notesPath(sourceID))
}

func (c *CheckpointStore) notesPath(sourceID string) string {
	return filepath.Join(c.dir, sanitizeSource(sourceID)+checkpointExt)
}

// LoadCheckpoints reads the signed checkpoints persisted for sourceID under dir,
// for offline verification (REQ-C-07). It returns nil when none exist.
func LoadCheckpoints(dir, sourceID string) ([]string, error) {
	return readNotesFile(filepath.Join(dir, sanitizeSource(sourceID)+checkpointExt))
}

func appendNote(path, signed string) error {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return fmt.Errorf("verifier: open notes: %w", err)
	}
	defer f.Close()
	line, err := json.Marshal(signed)
	if err != nil {
		return fmt.Errorf("verifier: encode note: %w", err)
	}
	if _, err := f.Write(append(line, '\n')); err != nil {
		return fmt.Errorf("verifier: append note: %w", err)
	}
	return f.Sync()
}

func readNotesFile(path string) ([]string, error) {
	f, err := os.Open(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("verifier: open notes: %w", err)
	}
	defer f.Close()
	var out []string
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 8<<20)
	for sc.Scan() {
		var signed string
		if err := json.Unmarshal(sc.Bytes(), &signed); err != nil {
			return nil, fmt.Errorf("verifier: decode note: %w", err)
		}
		out = append(out, signed)
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("verifier: scan notes: %w", err)
	}
	return out, nil
}

// CheckpointOf extracts the checkpoint body from a signed note without verifying
// its signature (used to rebuild the head index from trusted local storage). It
// delegates to note.CheckpointOf, the single implementation of the split-and-parse.
func CheckpointOf(signed string) (note.Checkpoint, error) {
	return note.CheckpointOf(signed)
}

func sanitizeSource(s string) string {
	// "." is replaced too so a crafted source ID cannot form ".." path elements.
	return strings.NewReplacer("/", "_", " ", "_", "\\", "_", ".", "_").Replace(s)
}
