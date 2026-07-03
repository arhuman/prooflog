// Package agent is the local agent daemon: it accepts events over CLI/HTTP/stdin,
// assigns a monotonic seq and ingest_time, serializes and chains each record,
// appends it to the durable spool (fsync before ACK), batches records into
// signed segments, and uploads them to the store with retry/backoff/replay.
// It also produces heartbeats and brackets outages with system events
// (REQ-E-04, REQ-E-06, REQ-E-09).
package agent

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"filippo.io/age"
	"google.golang.org/grpc"

	"github.com/arhuman/prooflog/internal/api"
	"github.com/arhuman/prooflog/internal/chain"
	"github.com/arhuman/prooflog/internal/envelope"
	"github.com/arhuman/prooflog/internal/heartbeat"
	"github.com/arhuman/prooflog/internal/keys"
	"github.com/arhuman/prooflog/internal/pseudonym"
	"github.com/arhuman/prooflog/internal/seal"
	"github.com/arhuman/prooflog/internal/segment"
	"github.com/arhuman/prooflog/internal/spool"
)

const (
	uploadQueueDepth     = 4096
	checkpointQueueDepth = 256
	backoffInitial       = 200 * time.Millisecond
	backoffMax           = 10 * time.Second
	sealTickInterval     = time.Second
	submitTimeout        = 5 * time.Second
	drainTimeout         = 10 * time.Second
)

// Agent-emitted system event types for signing-key lifecycle (REQ-C-11).
const (
	// EventKeyRotated records a signing-key handoff: the outgoing key seals the
	// checkpoint covering this event, and subsequent checkpoints are signed by
	// the incoming key. Both public keys stay registered so the chain verifies
	// cleanly across the change.
	EventKeyRotated = "system.key_rotated"
	// EventKeyRevoked records that a signing key must no longer be trusted from
	// the suspected-exposure time onward. It surfaces as an F-KEYREV finding.
	EventKeyRevoked = "system.key_revoked"
)

// buildFunc produces the record to append given the assigned seq, chain head,
// and ingest time. It is the single serialization point per record.
type buildFunc func(seq uint64, prevHash string, now time.Time) (envelope.Record, error)

// EventInput is a decoded ingest request from any path (HTTP/CLI/stdin).
type EventInput struct {
	EventType string
	EventTime time.Time // zero => use ingest time
	Actor     string
	Outcome   string
	Labels    map[string]string
	// Payload is the business payload plaintext for normal events (encrypted),
	// or the clear JSON payload for system.* events.
	Payload json.RawMessage
}

// Agent orchestrates ingest, spooling, sealing, and upload for one source.
type Agent struct {
	cfg    Config
	log    *slog.Logger
	origin string

	agentKey   keys.AgentKey
	recipients []age.Recipient
	sealer     seal.Sealer
	salts      *pseudonym.Store

	spool *spool.Spool

	mu       sync.Mutex // guards seq, prevHash, batcher, and spool appends
	seq      uint64
	prevHash string
	batcher  *segment.Batcher

	startTime time.Time

	storeConn      *grpc.ClientConn
	storeClient    api.StoreServiceClient
	verifierConn   *grpc.ClientConn
	verifierClient api.VerifierServiceClient

	uploadCh     chan segment.Sealed
	checkpointCh chan segment.Sealed
	pressureCh   chan uint64

	inOutage        atomic.Bool
	outageStartAck  atomic.Uint64
	lastUploadedSeq atomic.Uint64
	lastAckSeq      atomic.Uint64

	// lifecycle: producers run under runCtx; the uploader runs under uploadCtx
	// so Stop can drain the queue after producers have stopped.
	runCtx       context.Context
	runCancel    context.CancelFunc
	uploadCtx    context.Context
	uploadCancel context.CancelFunc
	stopUploader chan struct{}
	uploaderDone chan struct{}
	producerWG   sync.WaitGroup
	stopOnce     sync.Once
	closing      atomic.Bool
}

// New builds an agent from cfg: it opens the spool, loads the agent key, parses
// the recipient, reconstructs chain and Merkle state from the spool, and dials
// the store (and verifier, if configured). The connections are lazy and
// auto-reconnecting so an outage recovers without redialing (REQ-E-04).
func New(cfg Config, log *slog.Logger) (*Agent, error) {
	if log == nil {
		log = slog.Default()
	}
	agentKey, err := keys.LoadAgentKey(cfg.AgentKeyPath)
	if err != nil {
		return nil, err
	}
	recipients, err := parseRecipients(cfg)
	if err != nil {
		return nil, err
	}

	saltPath := cfg.SaltStorePath
	if saltPath == "" {
		saltPath = filepath.Join(filepath.Dir(cfg.AgentKeyPath), "salts.json")
	}
	salts, err := pseudonym.Open(saltPath)
	if err != nil {
		return nil, fmt.Errorf("agent: open salt store: %w", err)
	}

	a := &Agent{
		cfg:          cfg,
		log:          log,
		origin:       cfg.Origin(),
		agentKey:     agentKey,
		recipients:   recipients,
		sealer:       seal.AgeSealer{},
		salts:        salts,
		prevHash:     chain.Genesis,
		uploadCh:     make(chan segment.Sealed, uploadQueueDepth),
		checkpointCh: make(chan segment.Sealed, checkpointQueueDepth),
		pressureCh:   make(chan uint64, 1),
		startTime:    time.Now(),
	}

	sp, err := spool.Open(spool.Config{
		Dir:            cfg.SpoolDir,
		ThresholdBytes: cfg.SpoolThresholdBytes,
		Policy:         cfg.spoolPolicy(),
		OnPressure:     a.onPressure,
	})
	if err != nil {
		return nil, err
	}
	a.spool = sp

	// The signing name is bound to the public key inside the C2SP key id, so the
	// agent key file is authoritative: after a rotation writes a new-named key to
	// the key path, that name must survive a restart. cfg.AgentName only seeds the
	// name at init (where the two are equal), so preferring the key file here is
	// behaviour-neutral for freshly initialised agents (REQ-C-11).
	name := agentKey.Name
	if name == "" {
		name = cfg.AgentName
	}
	a.agentKey.Name = name
	a.batcher = segment.New(a.origin, name, agentKey.Private,
		segment.WithMaxRecords(sealRecords(cfg)),
		segment.WithMaxAge(sealAge(cfg)))

	if err := a.recover(); err != nil {
		a.spool.Close()
		return nil, err
	}

	storeConn, err := api.Dial(cfg.StoreAddr, cfg.TLS)
	if err != nil {
		a.spool.Close()
		return nil, err
	}
	a.storeConn = storeConn
	a.storeClient = api.NewStoreClient(storeConn)

	if cfg.VerifierAddr != "" {
		vConn, err := api.Dial(cfg.VerifierAddr, cfg.TLS)
		if err != nil {
			a.spool.Close()
			storeConn.Close()
			return nil, err
		}
		a.verifierConn = vConn
		a.verifierClient = api.NewVerifierClient(vConn)
	}
	return a, nil
}

// parseRecipients builds the age recipient list. When cfg.Recipients is set it
// supersedes OrgRecipient (multi-recipient sealing); otherwise the single org
// recipient is used — the documented default.
func parseRecipients(cfg Config) ([]age.Recipient, error) {
	raw := cfg.Recipients
	if len(raw) == 0 {
		raw = []string{cfg.OrgRecipient}
	}
	out := make([]age.Recipient, 0, len(raw))
	for _, r := range raw {
		rec, err := age.ParseX25519Recipient(r)
		if err != nil {
			return nil, fmt.Errorf("agent: parse recipient: %w", err)
		}
		out = append(out, rec)
	}
	return out, nil
}

func sealRecords(cfg Config) int {
	if cfg.SealMaxRecords > 0 {
		return cfg.SealMaxRecords
	}
	return segment.DefaultMaxRecords
}

func sealAge(cfg Config) time.Duration {
	if cfg.SealMaxAge > 0 {
		return time.Duration(cfg.SealMaxAge)
	}
	return segment.DefaultMaxAge
}

// recover reconstructs seq, chain head, and Merkle state from the spool after a
// restart: records at or below the last ACKed seq are restored as already
// sealed; later records are re-added as pending for re-sealing (REQ-C-01).
func (a *Agent) recover() error {
	it, err := a.spool.Iter(0)
	if err != nil {
		return err
	}
	defer it.Close()

	acked := a.spool.AckedSeq()
	now := time.Now()
	var last envelope.Record
	var count uint64
	for {
		rec, ok, err := it.Next()
		if err != nil {
			return fmt.Errorf("agent: recover spool: %w", err)
		}
		if !ok {
			break
		}
		if rec.Seq <= acked {
			a.batcher.Restore(rec.Bytes())
		} else if err := a.batcher.Add(rec.Bytes(), rec.Seq, now); err != nil {
			return fmt.Errorf("agent: recover batcher: %w", err)
		}
		last = rec
		count++
	}
	a.seq = a.spool.LastSeq()
	if count > 0 {
		a.prevHash = last.HashHex()
	}
	return nil
}

// AcceptEvent ingests one event, returning the durably-accepted record. It
// blocks until the record is fsynced to the spool, so an HTTP 200 to the caller
// means durable acceptance (REQ-E-04).
func (a *Agent) AcceptEvent(in EventInput) (envelope.Record, error) {
	if !envelope.ValidOutcomes[in.Outcome] {
		return envelope.Record{}, fmt.Errorf("agent: invalid outcome %q, allowed: %s", in.Outcome, allowedOutcomes())
	}
	return a.accept(func(seq uint64, prev string, now time.Time) (envelope.Record, error) {
		return a.buildRecord(in, seq, prev, now)
	})
}

// allowedOutcomes lists the accepted non-empty outcome values for error text.
func allowedOutcomes() string {
	out := make([]string, 0, len(envelope.ValidOutcomes))
	for o := range envelope.ValidOutcomes {
		if o != "" {
			out = append(out, o)
		}
	}
	sort.Strings(out)
	return strings.Join(out, ", ") + `, "" (unknown)`
}

func (a *Agent) buildRecord(in EventInput, seq uint64, prev string, now time.Time) (envelope.Record, error) {
	ts := envelope.FormatTime(now)
	eventTime := ts
	if !in.EventTime.IsZero() {
		eventTime = envelope.FormatTime(in.EventTime)
	}
	rec := envelope.Record{
		Version:    envelope.Version,
		SourceID:   a.cfg.SourceID,
		Seq:        seq,
		EventType:  in.EventType,
		EventTime:  eventTime,
		IngestTime: ts,
		Outcome:    in.Outcome,
		PrevHash:   prev,
	}
	// Actors become erasable HMAC pseudonyms; system events carry no actor.
	if in.Actor != "" && !rec.IsSystem() {
		actor, err := a.salts.Pseudonym(in.Actor)
		if err != nil {
			return envelope.Record{}, fmt.Errorf("agent: pseudonymize actor: %w", err)
		}
		rec.Actor = actor
	}
	if rec.IsSystem() {
		clearPayload, err := wrapPayload(in.Payload, in.Labels)
		if err != nil {
			return envelope.Record{}, err
		}
		if len(clearPayload) == 0 {
			clearPayload = json.RawMessage("{}")
		}
		rec.PayloadClear = clearPayload
	} else {
		wrapped, err := wrapPayload(in.Payload, in.Labels)
		if err != nil {
			return envelope.Record{}, err
		}
		ct, hashHex, err := a.encryptPayload(wrapped)
		if err != nil {
			return envelope.Record{}, err
		}
		rec.PayloadCT = ct
		rec.PayloadHash = hashHex
		rec.KeyID = a.cfg.KeyID
	}
	if err := rec.Serialize(); err != nil {
		return envelope.Record{}, err
	}
	return rec, nil
}

// wrapPayload folds free-text labels into the payload so they leave the
// envelope entirely. When labels are present the payload becomes
// {"labels":{…},"data":<payload or null>}; with no labels the original payload
// is returned unchanged (the wrapper only exists when labels are non-empty).
func wrapPayload(payload json.RawMessage, labels map[string]string) (json.RawMessage, error) {
	if len(labels) == 0 {
		return payload, nil
	}
	data := json.RawMessage("null")
	if len(payload) > 0 {
		data = payload
	}
	wrapped := struct {
		Labels map[string]string `json:"labels"`
		Data   json.RawMessage   `json:"data"`
	}{Labels: labels, Data: data}
	b, err := json.Marshal(wrapped)
	if err != nil {
		return nil, fmt.Errorf("agent: wrap labels: %w", err)
	}
	return b, nil
}

func (a *Agent) encryptPayload(plain []byte) (ctB64, hashHex string, err error) {
	ct, err := a.sealer.Seal(plain, a.recipients)
	if err != nil {
		return "", "", err
	}
	sum := sha256.Sum256(plain)
	return seal.EncodeBase64(ct), hex.EncodeToString(sum[:]), nil
}

// accept runs the single serialized critical section: assign seq, build, chain,
// spool (fsync), advance state, and batch. If a seal threshold is crossed it
// seals and enqueues the segment outside the lock to avoid deadlock.
func (a *Agent) accept(build buildFunc) (envelope.Record, error) {
	a.mu.Lock()
	rec, sealed, err := a.acceptLocked(build)
	a.mu.Unlock()
	if err != nil {
		return rec, err
	}
	if sealed != nil {
		a.enqueue(*sealed)
	}
	return rec, nil
}

// acceptLocked runs the serialized ingest critical section assuming a.mu is
// already held: assign seq, build, chain, spool (fsync), advance state, and
// batch. If a seal threshold is crossed it returns the sealed segment for the
// caller to enqueue outside the lock. It lets key rotation emit a record and
// seal under the held lock without re-entering the mutex through AcceptEvent.
func (a *Agent) acceptLocked(build buildFunc) (envelope.Record, *segment.Sealed, error) {
	now := time.Now()
	seq := a.seq + 1
	rec, err := build(seq, a.prevHash, now)
	if err != nil {
		return envelope.Record{}, nil, err
	}
	if err := rec.Validate(); err != nil {
		return envelope.Record{}, nil, fmt.Errorf("agent: validate: %w", err)
	}
	if err := a.spool.Append(rec); err != nil {
		return envelope.Record{}, nil, fmt.Errorf("agent: spool append: %w", err)
	}
	a.seq = seq
	a.prevHash = rec.HashHex()
	if err := a.batcher.Add(rec.Bytes(), seq, now); err != nil {
		return envelope.Record{}, nil, fmt.Errorf("agent: batch add: %w", err)
	}
	if a.batcher.Ready(now) {
		s, err := a.batcher.Seal(now)
		if err != nil {
			return rec, nil, fmt.Errorf("agent: seal: %w", err)
		}
		return rec, &s, nil
	}
	return rec, nil, nil
}

func (a *Agent) enqueue(s segment.Sealed) {
	// During shutdown we stop enqueuing: the segment is durably in the spool and
	// will be replayed on next start. The channel is never closed, so a late
	// send races harmlessly into the buffer.
	if a.closing.Load() {
		return
	}
	a.uploadCh <- s
	select {
	case a.checkpointCh <- s:
	default:
		a.log.Warn("checkpoint queue full, dropping submission", "segment", s.ID.String())
	}
}

// Flush seals any pending records immediately, regardless of age or count. Used
// on graceful shutdown and by tests to force a segment boundary.
func (a *Agent) Flush() {
	a.mu.Lock()
	if a.batcher.Pending() == 0 {
		a.mu.Unlock()
		return
	}
	s, err := a.batcher.Seal(time.Now())
	a.mu.Unlock()
	if err != nil {
		a.log.Error("flush seal failed", "err", err)
		return
	}
	a.enqueue(s)
}

// Heartbeat emits one heartbeat immediately (REQ-E-06).
func (a *Agent) Heartbeat() (envelope.Record, error) {
	return a.accept(func(seq uint64, prev string, now time.Time) (envelope.Record, error) {
		return heartbeat.Build(a.cfg.SourceID, seq, prev, now, a.sampleState())
	})
}

func (a *Agent) sampleState() heartbeat.State {
	return heartbeat.State{
		Version:         a.cfg.Version,
		UptimeSeconds:   uint64(time.Since(a.startTime).Seconds()),
		LastLocalSeq:    a.seq,
		LastUploadedSeq: a.lastUploadedSeq.Load(),
		LastAckSeq:      a.lastAckSeq.Load(),
		QueueDepth:      uint64(len(a.uploadCh)),
		TimeSource:      heartbeat.TimeSource{Source: "none", SyncState: "unsynchronised"},
	}
}

// emitSystem appends a system.* event with a clear payload (REQ-E-09).
func (a *Agent) emitSystem(eventType string, payload any) {
	clearPayload, err := json.Marshal(payload)
	if err != nil {
		a.log.Error("marshal system payload", "type", eventType, "err", err)
		return
	}
	if _, err := a.AcceptEvent(EventInput{EventType: eventType, Payload: clearPayload}); err != nil {
		a.log.Error("emit system event", "type", eventType, "err", err)
	}
}

// onPressure is the spool disk-pressure callback. It must not append inline (it
// runs under the spool/ingest lock), so it hands off to the pressure emitter.
func (a *Agent) onPressure(freeBytes uint64) {
	select {
	case a.pressureCh <- freeBytes:
	default:
	}
}

// Start launches the background goroutines and records agent startup. When ctx
// is cancelled the producers stop; call Stop to flush, drain the upload queue,
// and release resources cleanly.
func (a *Agent) Start(ctx context.Context) {
	a.runCtx, a.runCancel = context.WithCancel(context.Background())
	a.uploadCtx, a.uploadCancel = context.WithCancel(context.Background())
	a.stopUploader = make(chan struct{})
	a.uploaderDone = make(chan struct{})

	if a.cfg.TLS.Insecure {
		a.log.Warn("running without TLS; store and verifier gRPC traffic is plaintext", "insecure", true)
	}

	a.emitSystem("system.agent_started", map[string]any{
		"version":    a.cfg.Version,
		"agent_name": a.agentKey.Name,
	})

	go a.runUploader()

	a.producerWG.Add(4)
	go func() { defer a.producerWG.Done(); a.runCheckpointer(a.runCtx) }()
	go func() { defer a.producerWG.Done(); a.runSealTicker(a.runCtx) }()
	go func() { defer a.producerWG.Done(); a.runHeartbeat(a.runCtx) }()
	go func() { defer a.producerWG.Done(); a.runPressureEmitter(a.runCtx) }()

	// External cancellation stops the producers; Stop() finalizes shutdown.
	go func() {
		select {
		case <-ctx.Done():
			a.runCancel()
		case <-a.runCtx.Done():
		}
	}()
}

func (a *Agent) runSealTicker(ctx context.Context) {
	t := time.NewTicker(sealTickInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			a.mu.Lock()
			now := time.Now()
			if !a.batcher.Ready(now) {
				a.mu.Unlock()
				continue
			}
			s, err := a.batcher.Seal(now)
			a.mu.Unlock()
			if err != nil {
				a.log.Error("seal tick failed", "err", err)
				continue
			}
			a.enqueue(s)
		}
	}
}

func (a *Agent) runHeartbeat(ctx context.Context) {
	interval := time.Duration(a.cfg.HeartbeatInterval)
	if interval <= 0 {
		interval = 60 * time.Second
	}
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if _, err := a.Heartbeat(); err != nil {
				a.log.Error("heartbeat failed", "err", err)
			}
		}
	}
}

func (a *Agent) runPressureEmitter(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case free := <-a.pressureCh:
			a.emitSystem("system.local_spool_pressure", map[string]any{
				"free_bytes": free,
				"policy":     a.cfg.SpoolPolicy,
			})
		}
	}
}

// Stop shuts the agent down cleanly: it stops the producers, flushes pending
// records, records system.agent_stopped (so the verifier can bound any
// observation gap, REQ-E-06), then drains the upload queue to the store with a
// bounded timeout before releasing resources. Whatever cannot be uploaded in
// time stays durably in the spool for replay on the next start.
func (a *Agent) Stop() {
	a.stopOnce.Do(func() {
		// Stop the producers, if Start was ever called.
		if a.runCancel != nil {
			a.runCancel()
			a.producerWG.Wait()
		}

		a.Flush()
		a.emitSystem("system.agent_stopped", map[string]any{"reason": "shutdown"})
		a.Flush()

		// Drain the upload queue if the uploader is running.
		if a.stopUploader != nil {
			a.closing.Store(true)
			close(a.stopUploader)
			select {
			case <-a.uploaderDone:
			case <-time.After(drainTimeout):
				a.uploadCancel()
				<-a.uploaderDone
			}
		}

		if a.storeConn != nil {
			a.storeConn.Close()
		}
		if a.verifierConn != nil {
			a.verifierConn.Close()
		}
		if err := a.spool.Close(); err != nil {
			a.log.Error("spool close", "err", err)
		}
	})
}

// LastSeq returns the highest durably-accepted sequence number.
func (a *Agent) LastSeq() uint64 { return a.spool.LastSeq() }

// AckedSeq returns the highest sequence number the store has ACKed.
func (a *Agent) AckedSeq() uint64 { return a.spool.AckedSeq() }

// Spool exposes the underlying spool for read-only inspection in tests.
func (a *Agent) Spool() *spool.Spool { return a.spool }
