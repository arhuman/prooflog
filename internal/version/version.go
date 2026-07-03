// Package version exposes build metadata stamped into the binary via
// -ldflags -X at build time (see the Makefile). A plain `go build`/`go install`
// without those flags falls back to the defaults below, so the package is always
// safe to import and never panics on a missing value.
package version

import (
	"fmt"
	"runtime"
)

var (
	// Version is the build version, e.g. a git describe like "v0.1.0-2-g1a2b3c4"
	// or a bare commit hash when no tag exists. Overridden at build time.
	Version = "dev"
	// GitCommit is the short git commit hash the binary was built from.
	GitCommit = "unknown"
	// BuildDate is the UTC build timestamp (RFC3339). Overridden at build time.
	BuildDate = "unknown"
)

// Info returns the full build metadata on one line: version, commit, build
// date, and the Go toolchain version.
func Info() string {
	return fmt.Sprintf("%s (commit %s, built %s, %s)",
		Version, GitCommit, BuildDate, runtime.Version())
}
