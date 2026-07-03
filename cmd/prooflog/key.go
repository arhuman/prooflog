package main

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"flag"
	"fmt"
	"time"

	"github.com/arhuman/prooflog/internal/agent"
	"github.com/arhuman/prooflog/internal/verifier"
)

// resolveControlSocket locates the agent's privileged control socket: the
// explicit --socket path if given, else derived from the agent key directory in
// --config. Control lives on an owner-only unix socket, not the TCP ingest plane,
// so only a process that can open the 0600 socket may rotate or revoke keys (§6).
func resolveControlSocket(socket, configPath string) (string, error) {
	if socket != "" {
		return socket, nil
	}
	if configPath == "" {
		return "", fmt.Errorf("key: need --socket or --config to locate the agent control socket")
	}
	cfg, err := agent.LoadConfig(configPath)
	if err != nil {
		return "", err
	}
	if cfg.AgentKeyPath == "" {
		return "", fmt.Errorf("key: config %s has no agent_key to derive the control socket", configPath)
	}
	return agent.ControlSocketPath(cfg), nil
}

// runKey dispatches the signing-key lifecycle subcommands. Both talk to the
// local agent over its owner-only unix control socket (§6).
func runKey(args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("usage: prooflog key <rotate|revoke> [flags]")
	}
	sub, rest := args[0], args[1:]
	switch sub {
	case "rotate":
		return runKeyRotate(rest)
	case "revoke":
		return runKeyRevoke(rest)
	default:
		return fmt.Errorf("unknown key subcommand %q (want rotate or revoke)", sub)
	}
}

// runKeyRotate asks the agent to rotate its signing key, then prints the new key
// identity and public key. With --keys it appends the new public key to a
// co-located verifier registry file (single-host convenience); otherwise it
// prints instructions to register the key with the independent verifier operator
// (see docs/verifier-deployment-models.md, Tier 2/3).
func runKeyRotate(args []string) error {
	fs := flag.NewFlagSet("key rotate", flag.ContinueOnError)
	socket := fs.String("socket", "", "agent control socket path (default: derived from --config)")
	configPath := fs.String("config", "", "agent config to derive the control socket path")
	reason := fs.String("reason", "", "reason recorded in the system.key_rotated event")
	keysPath := fs.String("keys", "", "co-located verifier registry to append the new public key to")
	if err := fs.Parse(args); err != nil {
		return err
	}

	sockPath, err := resolveControlSocket(*socket, *configPath)
	if err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	resp, err := postJSONWith(ctx, unixClient(sockPath), "http://unix/v1/rotate-key", map[string]any{"reason": *reason})
	if err != nil {
		return err
	}

	oldKeyID, _ := resp["old_key_id"].(string)
	newKeyID, _ := resp["new_key_id"].(string)
	newKeyName, _ := resp["new_key_name"].(string)
	pubB64, _ := resp["new_public_key"].(string)
	origin, _ := resp["origin"].(string)
	sourceID, _ := resp["source_id"].(string)

	fmt.Printf("signing key rotated\n")
	fmt.Printf("  old key id:   %s\n", oldKeyID)
	fmt.Printf("  new key id:   %s\n", newKeyID)
	fmt.Printf("  new key name: %s\n", newKeyName)
	fmt.Printf("  public key:   %s\n", pubB64)

	if *keysPath == "" {
		fmt.Printf("\nregister the new public key with the verifier operator so its checkpoints\n")
		fmt.Printf("are trusted. An independent verifier's registry can only be updated by its\n")
		fmt.Printf("own operator — see docs/verifier-deployment-models.md (Tier 2/3). Add:\n")
		fmt.Printf("  { \"source_id\": %q, \"origin\": %q, \"key_name\": %q, \"public_key\": %q }\n",
			sourceID, origin, newKeyName, pubB64)
		return nil
	}

	pub, err := base64.StdEncoding.DecodeString(pubB64)
	if err != nil {
		return fmt.Errorf("decode new public key: %w", err)
	}
	if err := verifier.AppendKey(*keysPath, verifier.SourceKey{
		SourceID:  sourceID,
		Origin:    origin,
		KeyName:   newKeyName,
		PublicKey: ed25519.PublicKey(pub),
	}); err != nil {
		return err
	}
	fmt.Printf("\nappended the new public key to %s (single-host registry).\n", *keysPath)
	return nil
}

// runKeyRevoke asks the agent to record a signing-key revocation. The exposure
// window between --since and the revocation surfaces as an F-KEYREV finding in
// any report covering the period.
func runKeyRevoke(args []string) error {
	fs := flag.NewFlagSet("key revoke", flag.ContinueOnError)
	socket := fs.String("socket", "", "agent control socket path (default: derived from --config)")
	configPath := fs.String("config", "", "agent config to derive the control socket path")
	reason := fs.String("reason", "", "reason recorded in the system.key_revoked event")
	since := fs.String("since", "", "suspected exposure start (RFC3339); empty if unknown")
	if err := fs.Parse(args); err != nil {
		return err
	}

	sockPath, err := resolveControlSocket(*socket, *configPath)
	if err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	resp, err := postJSONWith(ctx, unixClient(sockPath), "http://unix/v1/revoke-key",
		map[string]any{"reason": *reason, "suspected_since": *since})
	if err != nil {
		return err
	}

	fmt.Printf("signing key revocation recorded (seq=%v hash=%v)\n", resp["seq"], resp["record_hash"])
	fmt.Printf("the exposure window will appear as an F-KEYREV finding in reports covering the period.\n")
	if *since == "" {
		fmt.Printf("no --since given: the exposure window is reported as starting at an unstated time.\n")
	}
	return nil
}
