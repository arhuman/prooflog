package version

import (
	"runtime"
	"strings"
	"testing"
)

func TestInfoIncludesAllFields(t *testing.T) {
	info := Info()
	for _, want := range []string{Version, GitCommit, BuildDate, runtime.Version()} {
		if !strings.Contains(info, want) {
			t.Errorf("Info() = %q, missing %q", info, want)
		}
	}
	if strings.Contains(info, "\n") {
		t.Errorf("Info() = %q, want a single line", info)
	}
}
