package main

import (
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
)

// binarySelfHash returns the SHA-256 hex of the running executable, pinning the
// exact verifier build in the report chain of custody (REQ-E-02). It returns
// "unavailable" if the executable path or bytes cannot be read.
func binarySelfHash() string {
	path, err := os.Executable()
	if err != nil {
		return "unavailable"
	}
	f, err := os.Open(path)
	if err != nil {
		return "unavailable"
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "unavailable"
	}
	return hex.EncodeToString(h.Sum(nil))
}
