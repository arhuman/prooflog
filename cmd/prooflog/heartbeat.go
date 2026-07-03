package main

import (
	"context"
	"flag"
	"fmt"
	"time"
)

// runHeartbeat forces an immediate heartbeat via the local agent endpoint
// (REQ-E-06).
func runHeartbeat(args []string) error {
	fs := flag.NewFlagSet("heartbeat", flag.ContinueOnError)
	addr := fs.String("addr", "", "agent ingest address (default: from config or 127.0.0.1:9600)")
	configPath := fs.String("config", "", "agent config to resolve the ingest address")
	if err := fs.Parse(args); err != nil {
		return err
	}
	target, err := resolveAddr(*addr, *configPath)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	resp, err := postJSON(ctx, "http://"+target+"/v1/heartbeat", map[string]any{})
	if err != nil {
		return err
	}
	fmt.Printf("heartbeat seq=%v hash=%v\n", resp["seq"], resp["record_hash"])
	return nil
}
