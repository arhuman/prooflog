package anchor

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

const anchorExt = ".anchors"

// Log durably persists timestamp receipts as append-only JSON lines, one
// file per source, mirroring the verifier's checkpoint store: append-only files
// (not SQLite) keep the trust surface simple and audit-friendly, and every line
// is fsynced before Append returns (REQ-C-15).
type Log struct {
	dir string
	mu  sync.Mutex
}

// OpenAnchorLog opens or creates the receipt store at dir.
func OpenAnchorLog(dir string) (*Log, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("anchor: mkdir receipts: %w", err)
	}
	return &Log{dir: dir}, nil
}

// Append durably appends a receipt for sourceID.
func (l *Log) Append(sourceID string, r Receipt) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	return appendReceipt(l.path(sourceID), r)
}

// All returns every receipt persisted for sourceID, in receipt order.
func (l *Log) All(sourceID string) ([]Receipt, error) {
	return readReceipts(l.path(sourceID))
}

func (l *Log) path(sourceID string) string {
	return filepath.Join(l.dir, sanitizeSource(sourceID)+anchorExt)
}

// LoadReceipts reads the receipts persisted for sourceID under dir, for offline
// verification (REQ-C-15). It returns nil when none exist.
func LoadReceipts(dir, sourceID string) ([]Receipt, error) {
	return readReceipts(filepath.Join(dir, sanitizeSource(sourceID)+anchorExt))
}

func appendReceipt(path string, r Receipt) error {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return fmt.Errorf("anchor: open receipts: %w", err)
	}
	defer f.Close()
	line, err := json.Marshal(r)
	if err != nil {
		return fmt.Errorf("anchor: encode receipt: %w", err)
	}
	if _, err := f.Write(append(line, '\n')); err != nil {
		return fmt.Errorf("anchor: append receipt: %w", err)
	}
	return f.Sync()
}

func readReceipts(path string) ([]Receipt, error) {
	f, err := os.Open(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("anchor: open receipts: %w", err)
	}
	defer f.Close()
	var out []Receipt
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 8<<20)
	for sc.Scan() {
		var r Receipt
		if err := json.Unmarshal(sc.Bytes(), &r); err != nil {
			return nil, fmt.Errorf("anchor: decode receipt: %w", err)
		}
		out = append(out, r)
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("anchor: scan receipts: %w", err)
	}
	return out, nil
}

// sanitizeSource mirrors the verifier checkpoint store's filename sanitization
// exactly so a source's receipts and checkpoints share the same on-disk name.
func sanitizeSource(s string) string {
	// "." is replaced too so a crafted source ID cannot form ".." path elements.
	return strings.NewReplacer("/", "_", " ", "_", "\\", "_", ".", "_").Replace(s)
}
