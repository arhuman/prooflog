// Package pseudonym maps actor identities to stable HMAC-SHA256 pseudonyms
// with a per-subject erasable salt. Deleting a subject's salt severs the
// link between the person and their pseudonym in every record — the records
// themselves are never rewritten (GDPR Art. 17 via crypto-shredding of
// linkability; HMAC per REQ-C-03, never a bare hash).
package pseudonym

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"
)

// saltBytes is the per-subject salt length: 256 bits of crypto/rand entropy.
const saltBytes = 32

// ErrEmptyActor rejects an empty actor identity.
var ErrEmptyActor = errors.New("pseudonym: empty actor")

// ErrNotFound signals an actor with no salt on record.
var ErrNotFound = errors.New("pseudonym: actor not found")

// entry is the persisted record for one subject.
type entry struct {
	Salt      string `json:"salt"`      // hex-encoded per-subject salt
	Pseudonym string `json:"pseudonym"` // hex HMAC-SHA256(salt, actor)
	Created   string `json:"created"`   // RFC3339 first-seen time
}

// Store maps actor identities to stable pseudonyms backed by a JSON file. It is
// safe for concurrent use.
type Store struct {
	path  string
	mu    sync.Mutex
	salts map[string]entry
}

// Open loads the salt store at path, lazily creating an empty one. The file is
// a 0600 JSON object keyed by actor identity.
func Open(path string) (*Store, error) {
	s := &Store{path: path, salts: make(map[string]entry)}
	b, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return s, nil
		}
		return nil, fmt.Errorf("pseudonym: read %q: %w", path, err)
	}
	if len(b) == 0 {
		return s, nil
	}
	if err := json.Unmarshal(b, &s.salts); err != nil {
		return nil, fmt.Errorf("pseudonym: parse %q: %w", path, err)
	}
	return s, nil
}

// Pseudonym returns the stable 64-hex HMAC-SHA256 pseudonym for actor, creating
// a 32-byte random salt on first sight and persisting the store durably before
// returning so the mapping survives a crash.
func (s *Store) Pseudonym(actor string) (string, error) {
	if actor == "" {
		return "", ErrEmptyActor
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if e, ok := s.salts[actor]; ok {
		return e.Pseudonym, nil
	}
	salt := make([]byte, saltBytes)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("pseudonym: generate salt: %w", err)
	}
	e := entry{
		Salt:      hex.EncodeToString(salt),
		Pseudonym: compute(salt, actor),
		Created:   time.Now().UTC().Format(time.RFC3339),
	}
	s.salts[actor] = e
	if err := s.persist(); err != nil {
		delete(s.salts, actor)
		return "", err
	}
	return e.Pseudonym, nil
}

// Lookup returns the cached pseudonym for actor without ever creating a salt.
func (s *Store) Lookup(actor string) (string, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	e, ok := s.salts[actor]
	if !ok {
		return "", false
	}
	return e.Pseudonym, true
}

// Erase deletes the subject's entry and rewrites the file durably, severing the
// link between the person and their pseudonym. A missing actor is an error.
//
// The guarantee is that the salt is gone from the live store: no in-process path
// can re-derive the pseudonym afterwards. It is best-effort against forensic disk
// recovery — persist rewrites via temp+rename and does not overwrite the freed
// sectors, so on SSD/CoW/journalling filesystems the old salt bytes may linger in
// unallocated blocks. Deployments needing an erasure guarantee against physical
// media recovery must host the salt store on a full-disk-encrypted or
// secure-erase-capable volume, so freed sectors are ciphertext (REQ-C-03).
func (s *Store) Erase(actor string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.salts[actor]; !ok {
		return fmt.Errorf("%w: %q", ErrNotFound, actor)
	}
	saved := s.salts[actor]
	delete(s.salts, actor)
	if err := s.persist(); err != nil {
		s.salts[actor] = saved
		return err
	}
	return nil
}

// Subjects returns the sorted list of actor identities currently on record.
func (s *Store) Subjects() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]string, 0, len(s.salts))
	for a := range s.salts {
		out = append(out, a)
	}
	sort.Strings(out)
	return out
}

// compute derives the pseudonym as hex HMAC-SHA256 keyed by the salt over the
// actor bytes (REQ-C-03: keyed MAC, never a bare hash).
func compute(salt []byte, actor string) string {
	mac := hmac.New(sha256.New, salt)
	mac.Write([]byte(actor))
	return hex.EncodeToString(mac.Sum(nil))
}

// persist writes the store to a temp file, fsyncs it, and renames it over the
// target, fsyncing the directory so the replacement is durable. Callers hold s.mu.
func (s *Store) persist() error {
	b, err := json.MarshalIndent(s.salts, "", "  ")
	if err != nil {
		return fmt.Errorf("pseudonym: marshal: %w", err)
	}
	dir := filepath.Dir(s.path)
	tmp, err := os.CreateTemp(dir, ".salts-*.tmp")
	if err != nil {
		return fmt.Errorf("pseudonym: temp file: %w", err)
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return fmt.Errorf("pseudonym: chmod: %w", err)
	}
	if _, err := tmp.Write(b); err != nil {
		tmp.Close()
		return fmt.Errorf("pseudonym: write: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return fmt.Errorf("pseudonym: sync: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("pseudonym: close: %w", err)
	}
	if err := os.Rename(tmpName, s.path); err != nil {
		return fmt.Errorf("pseudonym: rename: %w", err)
	}
	return syncDir(dir)
}

// syncDir fsyncs a directory so a rename into it is durable.
func syncDir(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return fmt.Errorf("pseudonym: open dir: %w", err)
	}
	defer d.Close()
	if err := d.Sync(); err != nil {
		return fmt.Errorf("pseudonym: sync dir: %w", err)
	}
	return nil
}
