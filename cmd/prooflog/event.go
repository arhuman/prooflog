package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"strings"
	"time"

	"github.com/arhuman/prooflog/internal/agent"
)

// labelFlag collects repeated --label k=v pairs.
type labelFlag map[string]string

func (l labelFlag) String() string { return "" }

func (l labelFlag) Set(v string) error {
	k, val, ok := strings.Cut(v, "=")
	if !ok {
		return fmt.Errorf("label must be key=value, got %q", v)
	}
	l[k] = val
	return nil
}

// runEvent sends an event to the local agent's HTTP ingest endpoint (§6).
func runEvent(args []string) error {
	fs := flag.NewFlagSet("event", flag.ContinueOnError)
	addr := fs.String("addr", "", "agent ingest address (default: from config or 127.0.0.1:9600)")
	configPath := fs.String("config", "", "agent config to resolve the ingest address")
	actor := fs.String("actor", "", "acting subject identity")
	outcome := fs.String("outcome", "", "event outcome, e.g. success/failure")
	payloadJSON := fs.String("payload-json", "", "business payload as a JSON object")
	labels := labelFlag{}
	fs.Var(labels, "label", "label key=value (repeatable)")
	// The event type is the first positional; flags follow it. Go's flag package
	// stops at the first non-flag token, so we split the type off explicitly.
	if len(args) < 1 {
		return fmt.Errorf("usage: prooflog event <type> [flags]")
	}
	eventType := args[0]
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}

	var payload json.RawMessage
	if *payloadJSON != "" {
		if !json.Valid([]byte(*payloadJSON)) {
			return fmt.Errorf("--payload-json is not valid JSON")
		}
		payload = json.RawMessage(*payloadJSON)
	}

	target, err := resolveAddr(*addr, *configPath)
	if err != nil {
		return err
	}

	req := map[string]any{"event_type": eventType}
	if *actor != "" {
		req["actor"] = *actor
	}
	if *outcome != "" {
		req["outcome"] = *outcome
	}
	if len(labels) > 0 {
		req["labels"] = map[string]string(labels)
	}
	if payload != nil {
		req["payload_json"] = payload
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	resp, err := postJSON(ctx, "http://"+target+"/v1/events", req)
	if err != nil {
		return err
	}
	fmt.Printf("accepted seq=%v hash=%v type=%v\n", resp["seq"], resp["record_hash"], resp["event_type"])
	return nil
}

// resolveAddr picks the ingest address from the flag, then the config, then the
// documented default.
func resolveAddr(addr, configPath string) (string, error) {
	if addr != "" {
		return addr, nil
	}
	if configPath != "" {
		cfg, err := agent.LoadConfig(configPath)
		if err != nil {
			return "", err
		}
		if cfg.HTTPAddr != "" {
			return cfg.HTTPAddr, nil
		}
	}
	return "127.0.0.1:9600", nil
}
