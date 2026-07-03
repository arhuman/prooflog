// Package traceability guards the REQ-* spec<->code mapping as a checked
// invariant rather than a convention that can silently rot. The REQ-*/RFC
// traceability comments are part of this compliance product's value, so a test
// enforces that every REQ-* referenced in code or docs corresponds to a real
// requirement in the canonical register (docs/standards.md), and reports (as a
// non-fatal note) requirements that no code references yet.
package traceability

import (
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// reqRef matches a concrete requirement reference, e.g. REQ-C-07. The register
// uses single-letter families (C/E/R) today; [A-Z]+ tolerates future families.
var reqRef = regexp.MustCompile(`REQ-[A-Z]+-[0-9]+`)

// reqDecl matches a requirement DECLARATION: an ID in the first column of a
// Markdown table row in the register, e.g. "| REQ-C-07 | ... |".
var reqDecl = regexp.MustCompile(`(?m)^\|\s*(REQ-[A-Z]+-[0-9]+)\s*\|`)

// repoRoot walks up from this test file until it finds go.mod, so the scan is
// independent of the test's working directory.
func repoRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatalf("go.mod not found walking up from %s", dir)
		}
		dir = parent
	}
}

// loadDeclared parses the canonical register and returns the set of declared
// requirement IDs.
func loadDeclared(t *testing.T, root string) map[string]bool {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(root, "docs", "standards.md"))
	if err != nil {
		t.Fatalf("read register: %v", err)
	}
	declared := map[string]bool{}
	for _, m := range reqDecl.FindAllStringSubmatch(string(data), -1) {
		declared[m[1]] = true
	}
	if len(declared) == 0 {
		t.Fatal("no REQ-* declarations parsed from docs/standards.md; the register format may have changed")
	}
	return declared
}

// collectRefs walks the repo and returns, per requirement ID, the set of Go
// files and the set of doc files that reference it.
func collectRefs(t *testing.T, root string) (goRefs, docRefs map[string]map[string]bool) {
	t.Helper()
	goRefs = map[string]map[string]bool{}
	docRefs = map[string]map[string]bool{}
	add := func(refs map[string]map[string]bool, id, rel string) {
		if refs[id] == nil {
			refs[id] = map[string]bool{}
		}
		refs[id][rel] = true
	}
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			switch d.Name() {
			case ".git", ".jj", "node_modules", "vendor", "bin":
				return fs.SkipDir
			}
			return nil
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		isGo := strings.HasSuffix(path, ".go")
		isDoc := strings.HasSuffix(path, ".md") && strings.HasPrefix(rel, "docs"+string(os.PathSeparator))
		if !isGo && !isDoc {
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		for _, id := range reqRef.FindAllString(string(data), -1) {
			if isGo {
				add(goRefs, id, rel)
			} else {
				add(docRefs, id, rel)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk: %v", err)
	}
	return goRefs, docRefs
}

func filesOf(set map[string]bool) string {
	files := make([]string, 0, len(set))
	for f := range set {
		files = append(files, f)
	}
	sort.Strings(files)
	return strings.Join(files, ", ")
}

// TestREQReferencesAreDeclared fails on any REQ-* referenced in code or docs
// that is absent from the register — catching a typo'd or renamed requirement
// before it silently rots the spec<->code mapping.
func TestREQReferencesAreDeclared(t *testing.T) {
	root := repoRoot(t)
	declared := loadDeclared(t, root)
	goRefs, docRefs := collectRefs(t, root)

	check := func(kind string, refs map[string]map[string]bool) {
		ids := make([]string, 0, len(refs))
		for id := range refs {
			ids = append(ids, id)
		}
		sort.Strings(ids)
		for _, id := range ids {
			if !declared[id] {
				t.Errorf("undeclared requirement %s referenced in %s file(s): %s\n"+
					"  add it to docs/standards.md or fix the reference", id, kind, filesOf(refs[id]))
			}
		}
	}
	check("Go", goRefs)
	check("doc", docRefs)
}

// TestREQRequirementsHaveCodeReferences reports (without failing) requirements
// that no Go file references yet. Many are report-content or doc-level
// requirements with no code touchpoint, so this is a signal to review, not a
// hard failure.
func TestREQRequirementsHaveCodeReferences(t *testing.T) {
	root := repoRoot(t)
	declared := loadDeclared(t, root)
	goRefs, _ := collectRefs(t, root)

	var orphans []string
	for id := range declared {
		if len(goRefs[id]) == 0 {
			orphans = append(orphans, id)
		}
	}
	sort.Strings(orphans)
	if len(orphans) > 0 {
		t.Logf("NOTE: %d requirement(s) have no Go reference (report/doc-level requirements are expected here): %s",
			len(orphans), strings.Join(orphans, ", "))
	}
}
