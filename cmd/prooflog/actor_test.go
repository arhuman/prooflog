package main

import (
	"path/filepath"
	"testing"

	"github.com/arhuman/prooflog/internal/pseudonym"
)

// TestRunActorUnknownSubcommand checks the dispatch-level error for unknown
// subcommands.
func TestRunActorUnknownSubcommand(t *testing.T) {
	err := runActor([]string{"bogus"})
	if err == nil {
		t.Fatal("expected error for unknown actor subcommand, got nil")
	}
}

// TestRunActorNoArgs checks the error when no subcommand is supplied.
func TestRunActorNoArgs(t *testing.T) {
	if err := runActor([]string{}); err == nil {
		t.Fatal("expected error with no arguments, got nil")
	}
}

// TestRunActorIDMissingSalts checks that --salts is required for actor id.
func TestRunActorIDMissingSalts(t *testing.T) {
	err := runActor([]string{"id", "alice@acme"})
	if err == nil {
		t.Fatal("expected error when --salts is missing, got nil")
	}
}

// TestRunActorEraseMissingSalts checks that --salts is required for actor erase.
func TestRunActorEraseMissingSalts(t *testing.T) {
	err := runActor([]string{"erase", "alice@acme"})
	if err == nil {
		t.Fatal("expected error when --salts is missing, got nil")
	}
}

// TestRunActorIDAndErase exercises the full actor pseudonym lifecycle: looking
// up a known pseudonym with actor id and then erasing it with actor erase.
func TestRunActorIDAndErase(t *testing.T) {
	saltsPath := filepath.Join(t.TempDir(), "salts.json")

	// Seed the store so the actor has a salt on record.
	store, err := pseudonym.Open(saltsPath)
	if err != nil {
		t.Fatalf("open salts: %v", err)
	}
	_, err = store.Pseudonym("alice@acme")
	if err != nil {
		t.Fatalf("seed pseudonym: %v", err)
	}

	// actor id should return the pseudonym.
	if err := runActor([]string{"id", "--salts", saltsPath, "alice@acme"}); err != nil {
		t.Fatalf("actor id: %v", err)
	}

	// actor erase should sever the link.
	if err := runActor([]string{"erase", "--salts", saltsPath, "alice@acme"}); err != nil {
		t.Fatalf("actor erase: %v", err)
	}

	// After erasure, actor id must fail because the salt is gone.
	if err := runActor([]string{"id", "--salts", saltsPath, "alice@acme"}); err == nil {
		t.Fatal("actor id after erasure: expected error, got nil")
	}
}

// TestRunActorIDUnknownActor ensures a clear error when the actor has never
// been recorded.
func TestRunActorIDUnknownActor(t *testing.T) {
	saltsPath := filepath.Join(t.TempDir(), "salts.json")
	// Create an empty store.
	if _, err := pseudonym.Open(saltsPath); err != nil {
		t.Fatalf("open salts: %v", err)
	}

	err := runActor([]string{"id", "--salts", saltsPath, "ghost@acme"})
	if err == nil {
		t.Fatal("expected error for unknown actor, got nil")
	}
}
