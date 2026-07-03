package pseudonym

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func tempStore(t *testing.T) (string, *Store) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "salts.json")
	s, err := Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	return path, s
}

func TestPseudonymDeterministicAndDistinct(t *testing.T) {
	t.Parallel()
	_, s := tempStore(t)

	p1, err := s.Pseudonym("alice@acme")
	if err != nil {
		t.Fatal(err)
	}
	if len(p1) != 64 {
		t.Fatalf("pseudonym not 64 hex: %q", p1)
	}
	// Deterministic across calls.
	p1b, err := s.Pseudonym("alice@acme")
	if err != nil {
		t.Fatal(err)
	}
	if p1 != p1b {
		t.Fatalf("pseudonym not stable: %q != %q", p1, p1b)
	}
	// Distinct actors → distinct pseudonyms and distinct salts.
	p2, err := s.Pseudonym("bob@acme")
	if err != nil {
		t.Fatal(err)
	}
	if p1 == p2 {
		t.Fatal("distinct actors produced the same pseudonym")
	}
	if s.salts["alice@acme"].Salt == s.salts["bob@acme"].Salt {
		t.Fatal("distinct actors share a salt")
	}
}

func TestOpenExistingReturnsSamePseudonyms(t *testing.T) {
	t.Parallel()
	path, s := tempStore(t)
	p, err := s.Pseudonym("alice@acme")
	if err != nil {
		t.Fatal(err)
	}
	s2, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	got, ok := s2.Lookup("alice@acme")
	if !ok {
		t.Fatal("reopened store lost the actor")
	}
	if got != p {
		t.Fatalf("reopened pseudonym changed: %q != %q", got, p)
	}
}

func TestLookupNeverCreates(t *testing.T) {
	t.Parallel()
	_, s := tempStore(t)
	if _, ok := s.Lookup("ghost"); ok {
		t.Fatal("Lookup returned a pseudonym for an unseen actor")
	}
	if len(s.Subjects()) != 0 {
		t.Fatal("Lookup created an entry")
	}
}

func TestErase(t *testing.T) {
	t.Parallel()
	path, s := tempStore(t)
	p, err := s.Pseudonym("alice@acme")
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Erase("alice@acme"); err != nil {
		t.Fatal(err)
	}
	if _, ok := s.Lookup("alice@acme"); ok {
		t.Fatal("Lookup true after Erase")
	}
	// File no longer contains the actor or its salt/pseudonym.
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	content := string(b)
	for _, forbidden := range []string{"alice@acme", p} {
		if strings.Contains(content, forbidden) {
			t.Fatalf("erased data still on disk: %q", forbidden)
		}
	}
	// Erasing a missing actor is an error.
	if err := s.Erase("alice@acme"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("re-erase error = %v, want ErrNotFound", err)
	}
}

func TestEmptyActorRejected(t *testing.T) {
	t.Parallel()
	_, s := tempStore(t)
	if _, err := s.Pseudonym(""); !errors.Is(err, ErrEmptyActor) {
		t.Fatalf("empty actor error = %v, want ErrEmptyActor", err)
	}
}

func TestFilePermissions(t *testing.T) {
	t.Parallel()
	path, s := tempStore(t)
	if _, err := s.Pseudonym("alice@acme"); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Fatalf("salt store perms = %o, want 600", perm)
	}
}

func TestSubjectsSorted(t *testing.T) {
	t.Parallel()
	_, s := tempStore(t)
	for _, a := range []string{"carol", "alice", "bob"} {
		if _, err := s.Pseudonym(a); err != nil {
			t.Fatal(err)
		}
	}
	got := s.Subjects()
	want := []string{"alice", "bob", "carol"}
	if len(got) != len(want) {
		t.Fatalf("Subjects = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("Subjects = %v, want %v", got, want)
		}
	}
}
