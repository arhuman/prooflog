package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"time"
)

const maxRespBytes = 1 << 20

// postJSON sends body as JSON to the local agent's TCP ingest plane and decodes
// the JSON response. It uses a dedicated client with an explicit timeout and
// bounds the response body (lang-go client rules).
func postJSON(ctx context.Context, url string, body any) (map[string]any, error) {
	return postJSONWith(ctx, &http.Client{Timeout: 10 * time.Second}, url, body)
}

// unixClient dials socketPath for every request, so the caller can reach the
// agent's owner-only control plane. The URL host is ignored by the transport.
func unixClient(socketPath string) *http.Client {
	return &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				return (&net.Dialer{}).DialContext(ctx, "unix", socketPath)
			},
		},
	}
}

// postJSONWith is postJSON over a caller-supplied client (TCP ingest or the unix
// control socket).
func postJSONWith(ctx context.Context, client *http.Client, url string, body any) (map[string]any, error) {
	buf, err := json.Marshal(body)
	if err != nil {
		return nil, fmt.Errorf("marshal request: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(buf))
	if err != nil {
		return nil, fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("send request: %w", err)
	}
	defer resp.Body.Close()

	limited := &io.LimitedReader{R: resp.Body, N: maxRespBytes + 1}
	data, err := io.ReadAll(limited)
	if err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}
	if limited.N == 0 {
		return nil, fmt.Errorf("response exceeds %d bytes", maxRespBytes)
	}
	var out map[string]any
	if len(data) > 0 {
		if err := json.Unmarshal(data, &out); err != nil {
			return nil, fmt.Errorf("decode response: %w", err)
		}
	}
	if resp.StatusCode != http.StatusOK {
		return out, fmt.Errorf("agent returned %s", resp.Status)
	}
	return out, nil
}
