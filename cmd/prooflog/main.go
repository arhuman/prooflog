// Command prooflog is the single static binary for the tamper-evident evidence
// logging system. Each role is a subcommand; this file only dispatches, one
// file per subcommand.
package main

import (
	"fmt"
	"os"

	"github.com/arhuman/prooflog/internal/version"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	cmd, args := os.Args[1], os.Args[2:]
	run, ok := commands[cmd]
	if !ok {
		fmt.Fprintf(os.Stderr, "prooflog: unknown command %q\n\n", cmd)
		usage()
		os.Exit(2)
	}
	if err := run(args); err != nil {
		fmt.Fprintf(os.Stderr, "prooflog %s: %v\n", cmd, err)
		os.Exit(1)
	}
}

// commands maps a subcommand name to its runner.
var commands = map[string]func([]string) error{
	"init":      runInit,
	"agent":     runAgent,
	"store":     runStore,
	"verifier":  runVerifier,
	"event":     runEvent,
	"key":       runKey,
	"actor":     runActor,
	"hold":      runHold,
	"export":    runExport,
	"heartbeat": runHeartbeat,
	"verify":    runVerify,
	"report":    runReport,
	"assess":    runAssess,
	"spool":     runSpool,
	"demo":      runDemo,
	"version":   runVersion,
}

func usage() {
	fmt.Fprint(os.Stderr, `prooflog — tamper-evident evidence logging

usage: prooflog <command> [flags]

commands:
  init        generate org + agent keys and a config skeleton
  agent       run the local agent daemon (ingest, spool, upload)
  store       run the central store service
  verifier    run the verifier trust-anchor daemon (checkpoints + verification)
  event       send an event to the local agent
  key rotate  rotate the agent signing key (emits system.key_rotated)
  key revoke  revoke the agent signing key (emits system.key_revoked)
  actor       manage actor pseudonyms: print or erase linkability
  hold        place, release, or list legal holds on the store
  export      export a forensic evidence bundle with a custody manifest
  export verify re-verify a bundle offline (file hashes, signature, chain), exit 1 on failure
  heartbeat   force an immediate heartbeat via the local agent
  verify        offline-verify a spool or store pull, exit 1 on findings
  report        generate the Markdown continuity/integrity report
  report verify check a signed report's footer signature
  assess        Tier 0 assessment over foreign logs (JSONL + profile), exit 1 on findings
  spool cat     pretty-print spool frames in a directory
  demo        run the adversarial demo (healthy | outage | tamper)
  version     print the version

run "prooflog <command> -h" for command flags.
`)
}

func runVersion(_ []string) error {
	fmt.Printf("prooflog %s\n", version.Info())
	return nil
}
