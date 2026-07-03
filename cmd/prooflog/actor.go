package main

import (
	"flag"
	"fmt"
	"time"

	"github.com/arhuman/prooflog/internal/pseudonym"
)

// runActor manages actor pseudonyms held in the salt store: print a subject's
// pseudonym, or erase the linkability between a subject and their pseudonym
// (GDPR Art. 17 crypto-shredding). Records are never rewritten.
func runActor(args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("usage: prooflog actor <id|erase> --salts <path> <actor>")
	}
	sub, rest := args[0], args[1:]
	switch sub {
	case "id":
		return runActorID(rest)
	case "erase":
		return runActorErase(rest)
	default:
		return fmt.Errorf("unknown actor subcommand %q (want id|erase)", sub)
	}
}

func runActorID(args []string) error {
	fs := flag.NewFlagSet("actor id", flag.ContinueOnError)
	saltsPath := fs.String("salts", "", "path to the salt store (required)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	actor, err := actorArg(fs, *saltsPath)
	if err != nil {
		return err
	}
	store, err := pseudonym.Open(*saltsPath)
	if err != nil {
		return err
	}
	p, ok := store.Lookup(actor)
	if !ok {
		return fmt.Errorf("actor %q has never been recorded (no salt on file)", actor)
	}
	fmt.Println(p)
	return nil
}

func runActorErase(args []string) error {
	fs := flag.NewFlagSet("actor erase", flag.ContinueOnError)
	saltsPath := fs.String("salts", "", "path to the salt store (required)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	actor, err := actorArg(fs, *saltsPath)
	if err != nil {
		return err
	}
	store, err := pseudonym.Open(*saltsPath)
	if err != nil {
		return err
	}
	p, ok := store.Lookup(actor)
	if !ok {
		return fmt.Errorf("actor %q has never been recorded (no salt on file)", actor)
	}
	if err := store.Erase(actor); err != nil {
		return err
	}
	now := time.Now().UTC().Format(time.RFC3339)
	fmt.Printf("linkability for subject %q erased at %s; pseudonym %s remains in records; "+
		"records remain intact and verifiable\n", actor, now, p)
	return nil
}

// actorArg extracts the single required positional actor argument.
func actorArg(fs *flag.FlagSet, saltsPath string) (string, error) {
	if saltsPath == "" {
		return "", fmt.Errorf("--salts is required")
	}
	if fs.NArg() != 1 {
		return "", fmt.Errorf("exactly one <actor> argument is required")
	}
	return fs.Arg(0), nil
}
