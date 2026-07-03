package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"time"

	"github.com/arhuman/prooflog/internal/note"
	"github.com/arhuman/prooflog/internal/spool"
)

// runDemo runs the adversarial demo: it launches the real store, verifier, and
// agent as subprocesses of this binary, drives a healthy pipeline, then (in
// tamper mode) breaks the evidence on disk and shows the offline verifier
// catching each tampering as a finding (architecture §7, REQ-C-02..C-07).
func runDemo(args []string) error {
	mode := "tamper"
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		mode, args = args[0], args[1:]
	}
	switch mode {
	case "healthy", "outage", "tamper":
	default:
		return fmt.Errorf("unknown mode %q (want healthy | outage | tamper)", mode)
	}

	fs := flag.NewFlagSet("demo", flag.ContinueOnError)
	dir := fs.String("dir", "", "workspace directory (default: a fresh temp dir)")
	storeAddr := fs.String("store-addr", "127.0.0.1:9700", "store gRPC listen address")
	verifierAddr := fs.String("verifier-addr", "127.0.0.1:9800", "verifier gRPC listen address")
	agentAddr := fs.String("agent-addr", "127.0.0.1:9600", "agent HTTP ingest address")
	keep := fs.Bool("keep", false, "keep the workspace directory on exit")
	if err := fs.Parse(args); err != nil {
		return err
	}

	bin, err := os.Executable()
	if err != nil {
		return fmt.Errorf("locate self: %w", err)
	}

	workspace := *dir
	createdTemp := false
	if workspace == "" {
		workspace, err = os.MkdirTemp("", "prooflog-demo-")
		if err != nil {
			return fmt.Errorf("workspace: %w", err)
		}
		createdTemp = true
	}

	logf, err := os.Create(filepath.Join(workspace, "demo.log"))
	if err != nil {
		return fmt.Errorf("demo log: %w", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	d := &demo{
		bin:          bin,
		dir:          workspace,
		storeAddr:    *storeAddr,
		verifierAddr: *verifierAddr,
		agentAddr:    *agentAddr,
		source:       "vps-01/api",
		st:           newStyler(),
		log:          logf,
		ctx:          ctx,
	}

	cleanup := func() {
		cancel()
		d.killAll()
		_ = logf.Close()
		if createdTemp && !*keep {
			_ = os.RemoveAll(workspace)
		}
	}
	defer cleanup()

	sigc := make(chan os.Signal, 1)
	signal.Notify(sigc, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sigc
		cleanup()
		os.Exit(130)
	}()

	d.section("Adversarial demo — mode: " + mode)
	d.info("workspace: " + workspace)
	if *keep || !createdTemp {
		d.info("workspace kept; component logs in demo.log")
	}

	switch mode {
	case "healthy":
		return d.runHealthy()
	case "outage":
		return d.runOutage()
	default:
		return d.runTamper()
	}
}

// demo holds the launched components and shared demo state.
type demo struct {
	bin          string
	dir          string
	storeAddr    string
	verifierAddr string
	agentAddr    string
	source       string
	st           styler
	log          *os.File
	ctx          context.Context

	all   []*exec.Cmd
	store *exec.Cmd
	agent *exec.Cmd
}

// ---- orchestration ----------------------------------------------------------

func (d *demo) setup() error {
	d.section("init — keys, config, verifier registration")
	if out, err := d.exec("init",
		"--dir", d.dir, "--org", "acme", "--source-id", d.source,
		"--store-addr", d.storeAddr, "--verifier-addr", d.verifierAddr,
		"--seal-max-records", "3", "--seal-max-age", "3s", "--heartbeat-interval", "5s"); err != nil {
		return fmt.Errorf("init: %v: %s", err, out)
	}
	d.info("keys, config.json and verifier-keys.json written")

	d.section("start store, verifier, agent")
	d.store = d.start("store", "--dir", filepath.Join(d.dir, "store-data"),
		"--listen", d.storeAddr, "--insecure")
	if err := d.waitPort(d.storeAddr); err != nil {
		return err
	}
	d.info("store up on " + d.storeAddr)

	d.start("verifier", "--listen", d.verifierAddr, "--store-addr", d.storeAddr,
		"--data-dir", filepath.Join(d.dir, "verifier-data"),
		"--keys", filepath.Join(d.dir, "verifier-keys.json"), "--interval", "3s", "--insecure")
	if err := d.waitPort(d.verifierAddr); err != nil {
		return err
	}
	d.info("verifier up on " + d.verifierAddr)

	d.agent = d.start("agent", "--config", filepath.Join(d.dir, "config.json"))
	if err := d.waitPort(d.agentAddr); err != nil {
		return err
	}
	d.info("agent up on " + d.agentAddr)
	return nil
}

// baselineEvents drives a healthy stream: several business events, a heartbeat,
// and a wait for segments to seal, upload, and be checkpointed by the verifier.
func (d *demo) baselineEvents() error {
	d.section("send events while healthy")
	events := []struct{ typ, actor, payload string }{
		{"deploy.completed", "ci", `{"version":"1.4.2"}`},
		{"access.granted", "admin@acme", `{"user":"alice"}`},
		{"access.revoked", "admin@acme", `{"user":"bob"}`},
		{"access.granted", "admin@acme", `{"user":"carol"}`},
		{"config.changed", "ci", `{"key":"timeout"}`},
		{"access.revoked", "admin@acme", `{"user":"dave"}`},
	}
	for _, e := range events {
		if err := d.event(e.typ, e.actor, e.payload); err != nil {
			return err
		}
	}
	if out, err := d.exec("heartbeat", "--config", filepath.Join(d.dir, "config.json")); err != nil {
		return fmt.Errorf("heartbeat: %v: %s", err, out)
	}
	d.info("sent 6 events + 1 heartbeat; waiting for seal, upload, and checkpoints")

	notes := checkpointNotesFile(filepath.Join(d.dir, "verifier-data"), d.source)
	if err := waitCond(20*time.Second, func() bool { return fileNonEmpty(notes) }); err != nil {
		return fmt.Errorf("no signed checkpoints appeared: %w", err)
	}
	d.info("segments sealed, uploaded, and checkpointed")
	return nil
}

func (d *demo) runHealthy() error {
	if err := d.setup(); err != nil {
		return err
	}
	if err := d.baselineEvents(); err != nil {
		return err
	}
	d.stopAgent()
	d.section("verify (offline, from spool + signed checkpoints)")
	out, err := d.verify(d.dir)
	fmt.Print(d.colorizeSummary(out))
	if err != nil {
		return fmt.Errorf("healthy run unexpectedly raised findings")
	}
	fmt.Println(d.st.green("PASS — evidence is clean and continuous."))
	return nil
}

func (d *demo) runOutage() error {
	if err := d.setup(); err != nil {
		return err
	}
	if err := d.baselineEvents(); err != nil {
		return err
	}

	d.section("simulate a store outage (kill the store)")
	d.killCmd(d.store)
	d.store = nil
	d.info("store down — the agent keeps accepting events locally")

	d.section("send events during the outage (buffered to the local spool)")
	if err := d.event("access.granted", "admin@acme", `{"user":"erin"}`); err != nil {
		return err
	}
	if err := d.event("access.revoked", "admin@acme", `{"user":"erin"}`); err != nil {
		return err
	}
	if err := d.event("deploy.completed", "ci", `{"version":"1.4.3"}`); err != nil {
		return err
	}
	if err := waitCond(15*time.Second, func() bool {
		return spoolHasEvent(filepath.Join(d.dir, "spool"), "system.network_outage")
	}); err != nil {
		return fmt.Errorf("outage was not recorded: %w", err)
	}
	d.info("outage recorded (system.network_outage)")

	d.section("restart the store and wait for replay")
	d.store = d.start("store", "--dir", filepath.Join(d.dir, "store-data"),
		"--listen", d.storeAddr, "--insecure")
	if err := d.waitPort(d.storeAddr); err != nil {
		return err
	}
	if err := waitCond(30*time.Second, func() bool {
		return spoolHasEvent(filepath.Join(d.dir, "spool"), "system.replay_completed")
	}); err != nil {
		return fmt.Errorf("replay did not complete: %w", err)
	}
	d.info("replay completed — buffered events uploaded")

	d.stopAgent()
	d.section("verify (offline) — outage tolerated, evidence clean")
	out, err := d.verify(d.dir)
	fmt.Print(d.colorizeSummary(out))
	if err != nil {
		return fmt.Errorf("outage run unexpectedly raised findings")
	}
	fmt.Println(d.st.green("PASS — outage and replay tolerated, no findings."))
	return nil
}

func (d *demo) runTamper() error {
	if err := d.setup(); err != nil {
		return err
	}
	if err := d.baselineEvents(); err != nil {
		return err
	}
	d.stopAgent()

	d.section("baseline verification (pristine evidence)")
	out, err := d.verify(d.dir)
	fmt.Print(d.colorizeSummary(out))
	if err != nil {
		return fmt.Errorf("baseline unexpectedly raised findings: %s", out)
	}
	fmt.Println(d.st.green("baseline is clean — now we attack it."))
	d.info(d.st.dim("note: the agent was stopped after a clean shutdown; an *unclean* stop " +
		"would leave a bounded observation gap (system.agent_stopped absent), which the report " +
		"surfaces as an observability boundary, not a cryptographic finding."))

	attacks := []struct {
		title  string
		mutate func(scratch string) (string, error)
	}{
		{"altered one recorded event → hash chain broken",
			func(s string) (string, error) { return tamperModifyEvent(filepath.Join(s, "spool")) }},
		{"excised recorded events from the spool → sequence gap / chain break",
			func(s string) (string, error) { return tamperDeleteSegment(filepath.Join(s, "spool")) }},
		{"truncated the log to hide the latest events → caught by the independent checkpoint",
			func(s string) (string, error) {
				return tamperTruncateLog(filepath.Join(s, "spool"),
					checkpointNotesFile(filepath.Join(s, "verifier-data"), d.source))
			}},
		{"rewrote a signed checkpoint → invalid signature + fork rejected",
			func(s string) (string, error) {
				return tamperRewriteCheckpoint(checkpointNotesFile(filepath.Join(s, "verifier-data"), d.source))
			}},
	}

	detected := 0
	for i, a := range attacks {
		d.section(fmt.Sprintf("tampering #%d — %s", i+1, a.title))
		scratch, err := d.copyEvidence()
		if err != nil {
			return err
		}
		broke, err := a.mutate(scratch)
		if err != nil {
			_ = os.RemoveAll(scratch)
			return fmt.Errorf("mutation %d: %w", i+1, err)
		}
		d.info("broke: " + broke)

		out, verr := d.verify(scratch)
		_ = os.RemoveAll(scratch)
		findings := extractFindings(out)
		if verr == nil || len(findings) == 0 {
			return fmt.Errorf("tampering #%d was NOT detected:\n%s", i+1, out)
		}
		fmt.Println("  verifier findings:")
		for _, f := range findings {
			fmt.Println("    " + d.st.redBold(f))
		}
		fmt.Println("  " + d.st.green("✓ detected (verify exited non-zero)"))
		detected++
	}

	d.section("summary")
	fmt.Printf("  %s\n", d.st.green(fmt.Sprintf("%d tampering attempts, %d detected.", len(attacks), detected)))
	fmt.Printf("  for the signed Markdown version, run:\n")
	fmt.Printf("    prooflog report --spool %s --checkpoints %s --keys %s --heartbeat-interval 5s --insecure\n",
		filepath.Join(d.dir, "spool"), filepath.Join(d.dir, "verifier-data"),
		filepath.Join(d.dir, "verifier-keys.json"))
	return nil
}

// ---- process management -----------------------------------------------------

func (d *demo) start(sub string, args ...string) *exec.Cmd {
	cmd := exec.CommandContext(d.ctx, d.bin, append([]string{sub}, args...)...)
	cmd.Stdout = d.log
	cmd.Stderr = d.log
	if err := cmd.Start(); err != nil {
		// A failed Start surfaces as a port-wait timeout with a clear message.
		fmt.Fprintf(d.log, "start %s: %v\n", sub, err)
		return cmd
	}
	d.all = append(d.all, cmd)
	return cmd
}

// exec runs a subcommand to completion, returning its combined output.
func (d *demo) exec(sub string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(d.ctx, 60*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, d.bin, append([]string{sub}, args...)...).CombinedOutput()
	return string(out), err
}

func (d *demo) event(typ, actor, payload string) error {
	out, err := d.exec("event", typ, "--config", filepath.Join(d.dir, "config.json"),
		"--actor", actor, "--outcome", "success", "--payload-json", payload)
	if err != nil {
		return fmt.Errorf("event %s: %v: %s", typ, err, out)
	}
	return nil
}

// verify runs `prooflog verify` offline against a workspace, returning its
// combined output and a non-nil error when findings were raised (exit 1).
func (d *demo) verify(workspace string) (string, error) {
	return d.exec("verify",
		"--spool", filepath.Join(workspace, "spool"),
		"--checkpoints", filepath.Join(workspace, "verifier-data"),
		"--keys", filepath.Join(workspace, "verifier-keys.json"),
		"--heartbeat-interval", "5s", "--insecure")
}

func (d *demo) stopAgent() {
	if d.agent == nil {
		return
	}
	d.section("stop the agent gracefully (records system.agent_stopped)")
	_ = d.agent.Process.Signal(syscall.SIGTERM)
	_ = d.agent.Wait()
	d.agent = nil
}

func (d *demo) killCmd(cmd *exec.Cmd) {
	if cmd == nil || cmd.Process == nil {
		return
	}
	_ = cmd.Process.Kill()
	_ = cmd.Wait()
}

func (d *demo) killAll() {
	for _, cmd := range d.all {
		if cmd != nil && cmd.Process != nil {
			_ = cmd.Process.Kill()
			_ = cmd.Wait()
		}
	}
	d.all = nil
}

// copyEvidence copies the files an offline verify needs (spool, checkpoints, and
// registered keys) into a fresh scratch dir so each attack runs against a
// pristine baseline in isolation.
func (d *demo) copyEvidence() (string, error) {
	scratch, err := os.MkdirTemp("", "prooflog-demo-scratch-")
	if err != nil {
		return "", fmt.Errorf("scratch: %w", err)
	}
	for _, item := range []string{"spool", "verifier-data", "verifier-keys.json"} {
		if err := copyTree(filepath.Join(d.dir, item), filepath.Join(scratch, item)); err != nil {
			_ = os.RemoveAll(scratch)
			return "", err
		}
	}
	return scratch, nil
}

// ---- tampering mutations (pure file operations) -----------------------------

// frame is one spool frame: the record's canonical bytes and its trailing hash.
type frame struct {
	body []byte
	hash [32]byte
}

// tamperModifyEvent flips a byte inside the earliest segment's first (non-last)
// record body and recomputes the frame's trailing hash so the frame stays
// internally consistent. Because the record content changed, the next record's
// prev_hash no longer links to it, breaking the hash chain (F-CHAIN).
func tamperModifyEvent(spoolDir string) (string, error) {
	files, err := segmentFiles(spoolDir)
	if err != nil {
		return "", err
	}
	if len(files) == 0 {
		return "", errors.New("no spool segments")
	}
	path := files[0]
	frames, err := readFrames(path)
	if err != nil {
		return "", err
	}
	if len(frames) < 2 {
		return "", fmt.Errorf("need >=2 records, have %d", len(frames))
	}
	if !flipField(frames[0].body, `"event_time":"`) {
		return "", errors.New("event_time field not found in record")
	}
	frames[0].hash = sha256.Sum256(frames[0].body)
	if err := writeFrames(path, frames); err != nil {
		return "", err
	}
	return fmt.Sprintf("altered the first record in %s and rewrote its frame hash",
		filepath.Base(path)), nil
}

// tamperDeleteSegment removes a contiguous block of records from the middle of
// the earliest segment (the agent keeps one append-only spool file, so a whole
// upload segment is a run of frames, not a separate file). The seq jump across
// the hole breaks the chain (F-CHAIN, sequence gap).
func tamperDeleteSegment(spoolDir string) (string, error) {
	files, err := segmentFiles(spoolDir)
	if err != nil {
		return "", err
	}
	if len(files) == 0 {
		return "", errors.New("no spool segments")
	}
	path := files[0]
	frames, err := readFrames(path)
	if err != nil {
		return "", err
	}
	if len(frames) < 4 {
		return "", fmt.Errorf("need >=4 records to drop a middle block, have %d", len(frames))
	}
	lo := len(frames) / 4
	if lo < 1 {
		lo = 1
	}
	hi := len(frames) / 2
	if hi > len(frames)-2 {
		hi = len(frames) - 2
	}
	kept := append(append([]frame{}, frames[:lo]...), frames[hi+1:]...)
	if err := writeFrames(path, kept); err != nil {
		return "", err
	}
	return fmt.Sprintf("dropped %d consecutive records from the middle of %s",
		hi-lo+1, filepath.Base(path)), nil
}

// tamperTruncateLog drops the tail of the spool so fewer records remain than the
// largest accepted checkpoint commits to. The kept prefix is still an internally
// valid hash chain (no F-CHAIN), yet the independent signed checkpoint proves
// records are missing: its Merkle root cannot be recomputed from the short leaf
// prefix, so consistency fails (F-FORK). This is the case where on-disk evidence
// looks clean but the external witness still catches the loss.
func tamperTruncateLog(spoolDir, notesPath string) (string, error) {
	files, err := segmentFiles(spoolDir)
	if err != nil {
		return "", err
	}
	if len(files) != 1 {
		// The agent keeps a single append-only spool file; truncating across
		// multiple files is out of scope for the demo.
		if len(files) == 0 {
			return "", errors.New("no spool segments")
		}
	}
	path := files[len(files)-1]
	frames, err := readFrames(path)
	if err != nil {
		return "", err
	}
	maxSize, err := maxCheckpointSize(notesPath)
	if err != nil {
		return "", err
	}
	if maxSize < 2 {
		return "", fmt.Errorf("no checkpoint commits to >=2 records (max size %d)", maxSize)
	}
	// Keep one fewer record than the largest checkpoint commits to, guaranteeing
	// that checkpoint's root can no longer be recomputed from the leaf prefix.
	keep := int(maxSize) - 1
	if keep >= len(frames) {
		keep = len(frames) - 1
	}
	if keep < 1 {
		keep = 1
	}
	if err := writeFrames(path, frames[:keep]); err != nil {
		return "", err
	}
	return fmt.Sprintf("truncated %s to its first %d of %d records (last signed checkpoint commits to %d)",
		filepath.Base(path), keep, len(frames), maxSize), nil
}

// maxCheckpointSize returns the largest tree size across the signed checkpoints
// persisted in notesPath.
func maxCheckpointSize(notesPath string) (uint64, error) {
	data, err := os.ReadFile(notesPath)
	if err != nil {
		return 0, fmt.Errorf("read notes: %w", err)
	}
	var maxSize uint64
	for _, line := range strings.Split(strings.TrimRight(string(data), "\n"), "\n") {
		if line == "" {
			continue
		}
		var signed string
		if err := json.Unmarshal([]byte(line), &signed); err != nil {
			return 0, fmt.Errorf("decode note: %w", err)
		}
		split := strings.LastIndex(signed, "\n\n")
		if split < 0 {
			return 0, errors.New("malformed signed note")
		}
		cp, err := note.ParseCheckpoint(signed[:split+1])
		if err != nil {
			return 0, fmt.Errorf("parse checkpoint: %w", err)
		}
		if cp.Size > maxSize {
			maxSize = cp.Size
		}
	}
	return maxSize, nil
}

// tamperRewriteCheckpoint alters a byte in a signed checkpoint's body so its
// Ed25519 signature no longer verifies (F-SIG); the checkpoint set then stops
// being an append-only extension, so the fork is rejected (F-FORK).
func tamperRewriteCheckpoint(notesPath string) (string, error) {
	data, err := os.ReadFile(notesPath)
	if err != nil {
		return "", fmt.Errorf("read notes: %w", err)
	}
	lines := strings.Split(strings.TrimRight(string(data), "\n"), "\n")
	if len(lines) == 0 || lines[0] == "" {
		return "", errors.New("no signed checkpoints")
	}
	var signed string
	if err := json.Unmarshal([]byte(lines[0]), &signed); err != nil {
		return "", fmt.Errorf("decode note: %w", err)
	}
	split := strings.LastIndex(signed, "\n\n")
	if split < 0 {
		return "", errors.New("malformed signed note")
	}
	body := []byte(signed[:split])
	if !flipFirstLetter(body) {
		return "", errors.New("no mutable byte in checkpoint body")
	}
	signed = string(body) + signed[split:]
	enc, err := json.Marshal(signed)
	if err != nil {
		return "", fmt.Errorf("encode note: %w", err)
	}
	lines[0] = string(enc)
	if err := os.WriteFile(notesPath, []byte(strings.Join(lines, "\n")+"\n"), 0o600); err != nil {
		return "", err
	}
	return "rewrote the first signed checkpoint body in " + filepath.Base(notesPath), nil
}

// flipField advances past prefix and increments the digit that follows it (mod
// 10), keeping the surrounding JSON string well formed. Returns false if the
// prefix is absent or the following byte is not a digit.
func flipField(b []byte, prefix string) bool {
	i := bytes.Index(b, []byte(prefix))
	if i < 0 {
		return false
	}
	j := i + len(prefix)
	if j >= len(b) || b[j] < '0' || b[j] > '9' {
		return false
	}
	b[j] = '0' + (b[j]-'0'+1)%10
	return true
}

// flipFirstLetter changes the first ASCII letter in b to a different letter.
func flipFirstLetter(b []byte) bool {
	for i, c := range b {
		switch {
		case c >= 'a' && c <= 'z':
			b[i] = 'a' + (c-'a'+1)%26
			return true
		case c >= 'A' && c <= 'Z':
			b[i] = 'A' + (c-'A'+1)%26
			return true
		}
	}
	return false
}

// ---- spool frame IO ---------------------------------------------------------

func segmentFiles(dir string) ([]string, error) {
	files, err := filepath.Glob(filepath.Join(dir, "*.plogseg"))
	if err != nil {
		return nil, fmt.Errorf("list segments: %w", err)
	}
	sort.Strings(files)
	return files, nil
}

// readFrames reads all frames from a segment file: uvarint(len) || body ||
// sha256(body)[32], matching the spool on-disk format.
func readFrames(path string) ([]frame, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open segment: %w", err)
	}
	defer f.Close()
	r := bufio.NewReader(f)
	var out []frame
	for {
		length, err := binary.ReadUvarint(r)
		if errors.Is(err, io.EOF) {
			return out, nil
		}
		if err != nil {
			return nil, fmt.Errorf("read frame length: %w", err)
		}
		body := make([]byte, length)
		if _, err := io.ReadFull(r, body); err != nil {
			return nil, fmt.Errorf("read frame body: %w", err)
		}
		var h [32]byte
		if _, err := io.ReadFull(r, h[:]); err != nil {
			return nil, fmt.Errorf("read frame hash: %w", err)
		}
		out = append(out, frame{body: body, hash: h})
	}
}

func writeFrames(path string, frames []frame) error {
	var buf bytes.Buffer
	var hdr [binary.MaxVarintLen64]byte
	for _, fr := range frames {
		n := binary.PutUvarint(hdr[:], uint64(len(fr.body)))
		buf.Write(hdr[:n])
		buf.Write(fr.body)
		buf.Write(fr.hash[:])
	}
	if err := os.WriteFile(path, buf.Bytes(), 0o600); err != nil {
		return fmt.Errorf("rewrite segment: %w", err)
	}
	return nil
}

// ---- helpers ----------------------------------------------------------------

// checkpointNotesFile returns the per-source checkpoint notes path, matching the
// verifier's source-id sanitization ("/ \ space ." → "_").
func checkpointNotesFile(dir, source string) string {
	name := strings.NewReplacer("/", "_", " ", "_", "\\", "_", ".", "_").Replace(source)
	return filepath.Join(dir, name+".notes")
}

func spoolHasEvent(dir, eventType string) bool {
	sp, err := spool.Open(spool.Config{Dir: dir})
	if err != nil {
		return false
	}
	defer sp.Close()
	it, err := sp.Iter(0)
	if err != nil {
		return false
	}
	defer it.Close()
	for {
		rec, ok, err := it.Next()
		if err != nil || !ok {
			return false
		}
		if rec.EventType == eventType {
			return true
		}
	}
}

func fileNonEmpty(path string) bool {
	fi, err := os.Stat(path)
	return err == nil && fi.Size() > 0
}

func (d *demo) waitPort(addr string) error {
	dialer := net.Dialer{Timeout: 200 * time.Millisecond}
	for i := 0; i < 50; i++ {
		c, err := dialer.DialContext(d.ctx, "tcp", addr)
		if err == nil {
			_ = c.Close()
			return nil
		}
		time.Sleep(200 * time.Millisecond)
	}
	return fmt.Errorf("timeout waiting for %s", addr)
}

func waitCond(timeout time.Duration, cond func() bool) error {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if cond() {
			return nil
		}
		time.Sleep(200 * time.Millisecond)
	}
	return fmt.Errorf("condition not met within %s", timeout)
}

// copyTree recursively copies src (file or directory) to dst.
func copyTree(src, dst string) error {
	fi, err := os.Stat(src)
	if err != nil {
		return fmt.Errorf("copy stat %s: %w", src, err)
	}
	if !fi.IsDir() {
		data, err := os.ReadFile(src)
		if err != nil {
			return fmt.Errorf("copy read %s: %w", src, err)
		}
		if err := os.MkdirAll(filepath.Dir(dst), 0o700); err != nil {
			return err
		}
		return os.WriteFile(dst, data, fi.Mode().Perm())
	}
	if err := os.MkdirAll(dst, 0o700); err != nil {
		return err
	}
	entries, err := os.ReadDir(src)
	if err != nil {
		return fmt.Errorf("copy readdir %s: %w", src, err)
	}
	for _, e := range entries {
		if err := copyTree(filepath.Join(src, e.Name()), filepath.Join(dst, e.Name())); err != nil {
			return err
		}
	}
	return nil
}

// extractFindings returns the finding lines ("- [sev] F-ID: title") from a
// verify summary.
func extractFindings(out string) []string {
	var findings []string
	for _, line := range strings.Split(out, "\n") {
		t := strings.TrimSpace(line)
		if strings.HasPrefix(t, "- [") {
			findings = append(findings, strings.TrimPrefix(t, "- "))
		}
	}
	return findings
}

// ---- output styling ---------------------------------------------------------

type styler struct{ on bool }

func newStyler() styler {
	if os.Getenv("NO_COLOR") != "" {
		return styler{on: false}
	}
	fi, err := os.Stdout.Stat()
	return styler{on: err == nil && fi.Mode()&os.ModeCharDevice != 0}
}

func (s styler) wrap(code, text string) string {
	if !s.on {
		return text
	}
	return "\033[" + code + "m" + text + "\033[0m"
}

func (s styler) cyan(t string) string    { return s.wrap("1;36", t) }
func (s styler) green(t string) string   { return s.wrap("1;32", t) }
func (s styler) redBold(t string) string { return s.wrap("1;31", t) }
func (s styler) dim(t string) string     { return s.wrap("2", t) }

func (d *demo) section(title string) {
	fmt.Printf("\n%s\n", d.st.cyan("== "+title+" =="))
}

func (d *demo) info(msg string) {
	fmt.Printf("   %s\n", msg)
}

// colorizeSummary re-emits a verify summary with the verdict greened and any
// findings reddened.
func (d *demo) colorizeSummary(out string) string {
	var b strings.Builder
	for _, line := range strings.Split(out, "\n") {
		t := strings.TrimSpace(line)
		switch {
		case strings.Contains(line, "VERDICT: clean"):
			b.WriteString(d.st.green(line))
		case strings.HasPrefix(t, "- [") || strings.HasPrefix(t, "FINDINGS ("):
			b.WriteString(d.st.redBold(line))
		default:
			b.WriteString(line)
		}
		b.WriteByte('\n')
	}
	return strings.TrimRight(b.String(), "\n") + "\n"
}
