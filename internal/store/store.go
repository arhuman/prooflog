// Package store is the central store service: a SQLite index over a blob
// directory of segment files. It ACKs an upload only after the blob is fsynced
// and the index committed, dedups by (source_id, seq range, root), and serves
// the exact stored frames back to the verifier (REQ-E-04, REQ-E-11, REQ-R-10).
package store

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	_ "modernc.org/sqlite" // registers the "sqlite" database/sql driver

	"github.com/arhuman/prooflog/internal/api"
	"github.com/arhuman/prooflog/internal/envelope"
	"github.com/arhuman/prooflog/internal/hashid"
	"github.com/arhuman/prooflog/internal/note"
	"github.com/arhuman/prooflog/internal/segment"
)

const (
	blobExt     = ".plogseg"
	hashSize    = 32
	maxFrameLen = 16 << 20
	// maxSegmentFrames caps the frames accepted in one UploadSegment stream. A
	// sealed segment holds at most segment.DefaultMaxRecords records; the ×4
	// headroom tolerates non-default agent seal thresholds while bounding a
	// single stream, so a hostile client cannot stream frames without end to
	// exhaust disk (paired with the per-frame maxFrameLen ceiling) (REQ-E-04).
	maxSegmentFrames = 4 * segment.DefaultMaxRecords
	// schemaVersion is the on-disk PRAGMA user_version. v2 added retention
	// tombstones (segments.deleted_at) plus the holds and retention_policies
	// tables (WS6). Pre-v2 stores are not migrated (pre-alpha).
	schemaVersion = 2
	// retentionUpdateBatch caps segment IDs per batched deleted_at UPDATE,
	// well under SQLite's host-parameter limit.
	retentionUpdateBatch = 512
	// listPageMax is the server default and hard cap for list-endpoint page
	// sizes: a request page_size of 0 defaults to it and larger values clamp
	// down to it.
	listPageMax = 1000
)

// maxSegmentBytes is the cumulative record-byte ceiling for one UploadSegment
// stream. maxSegmentFrames bounds frame COUNT but not SIZE: at the maxFrameLen
// ceiling a single authenticated stream could spool maxSegmentFrames*maxFrameLen
// (1024*16 MiB = 16 GiB) of tmp before any index row is written. Budgeting a
// 512 KiB average frame keeps the ceiling far above realistic evidence records
// (heartbeats/events are a few KiB) yet ~32x below that worst case; a hostile
// client is cut off with ResourceExhausted once the running total is exceeded
// (REQ-E-04). It is a var, not a const, only so tests can lower it cheaply.
var maxSegmentBytes = maxSegmentFrames * (512 << 10)

// RetentionPolicy is the deletion policy: DefaultDays drives v1 deletion;
// Frameworks is recorded and reported for chain of custody but does not (yet)
// drive per-framework deletion.
type RetentionPolicy struct {
	DefaultDays int            `json:"default_days"`
	Frameworks  map[string]int `json:"frameworks,omitempty"`
}

// canonicalJSON renders p to deterministic JSON for equality comparison and
// event payloads. json.Marshal sorts map keys and pins struct field order.
func (p RetentionPolicy) canonicalJSON() (string, error) {
	b, err := json.Marshal(p)
	if err != nil {
		return "", fmt.Errorf("store: marshal retention policy: %w", err)
	}
	return string(b), nil
}

// Tombstone is the record of one segment deleted under retention: the blob is
// gone but the row (seq range, root, checkpoint) survives forever so the
// verifier reports an expired-but-retained range instead of a false gap.
type Tombstone struct {
	SegmentID string
	SourceID  string
	SeqFirst  uint64
	SeqLast   uint64
	Root      []byte
	DeletedAt time.Time
	Policy    string
}

// Config configures a Store.
type Config struct {
	// DBPath is the SQLite index file.
	DBPath string
	// BlobDir holds one segment blob file per stored segment.
	BlobDir string
	// Retention is the minimum period segments are kept, kept as a shorthand
	// that synthesizes a DefaultDays policy when Policy is unset.
	Retention time.Duration
	// Policy is the effective retention policy driving EnforceRetention.
	Policy RetentionPolicy
	// Logger receives operational logs; defaults to slog.Default.
	Logger *slog.Logger
}

// Store is the SQLite+filesystem SegmentStore and gRPC StoreService (REQ-E-04).
type Store struct {
	api.UnimplementedStoreServiceServer
	db        *sql.DB
	rdb       *sql.DB
	blobDir   string
	retention time.Duration
	policy    RetentionPolicy
	log       *slog.Logger
	emit      EventSink
}

const schema = `
CREATE TABLE IF NOT EXISTS segments (
    segment_id TEXT PRIMARY KEY,
    source_id  TEXT NOT NULL,
    seq_first  INTEGER NOT NULL,
    seq_last   INTEGER NOT NULL,
    root       BLOB NOT NULL,
    checkpoint TEXT NOT NULL,
    blob_path  TEXT NOT NULL,
    created_at TEXT NOT NULL,
    deleted_at TEXT,
    UNIQUE(source_id, seq_first, seq_last, root)
);
CREATE INDEX IF NOT EXISTS idx_segments_source_seq ON segments(source_id, seq_first);
-- Partial indexes over live (non-tombstoned) rows serve the hot scans directly.
-- The prior idx_segments_live on (source_id, deleted_at) WHERE deleted_at IS NULL
-- was degenerate: deleted_at is constant under the predicate, so it collapsed to
-- (source_id) and served neither the retention scan nor PullSegments' seq order.
-- idx_segments_live now covers PullSegments (per-source filter + seq_first keyset
-- order); idx_segments_live_id keeps the EnforceRetention scan on the segment_id
-- keyset order while skipping accumulated tombstones (P-perf).
CREATE INDEX IF NOT EXISTS idx_segments_live ON segments(source_id, seq_first) WHERE deleted_at IS NULL;
CREATE INDEX IF NOT EXISTS idx_segments_live_id ON segments(segment_id) WHERE deleted_at IS NULL;
CREATE TABLE IF NOT EXISTS checkpoints (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    source_id   TEXT,
    origin      TEXT,
    note        TEXT NOT NULL,
    received_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS holds (
    hold_id     TEXT PRIMARY KEY,
    source_id   TEXT NOT NULL,
    seq_first   INTEGER,
    seq_last    INTEGER,
    reason      TEXT NOT NULL,
    placed_by   TEXT,
    placed_at   TEXT NOT NULL,
    released_at TEXT
);
CREATE TABLE IF NOT EXISTS retention_policies (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    policy_json  TEXT NOT NULL,
    effective_at TEXT NOT NULL
);
`

// Open opens or creates the store at cfg's paths and applies the schema. It
// gates on PRAGMA user_version: a fresh or v2 store is (re)initialized to
// schema v2; a pre-v2 store (segments without deleted_at) is rejected — there
// is no ALTER migration in pre-alpha.
func Open(cfg Config) (*Store, error) {
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	if cfg.Policy.DefaultDays == 0 && len(cfg.Policy.Frameworks) == 0 && cfg.Retention > 0 {
		cfg.Policy = RetentionPolicy{DefaultDays: int(cfg.Retention.Hours() / 24)}
	}
	if err := os.MkdirAll(cfg.BlobDir, 0o700); err != nil {
		return nil, fmt.Errorf("store: mkdir blob dir: %w", err)
	}
	if dir := filepath.Dir(cfg.DBPath); dir != "" {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return nil, fmt.Errorf("store: mkdir db dir: %w", err)
		}
	}
	dsn := "file:" + cfg.DBPath + "?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)&_pragma=synchronous(NORMAL)"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("store: open db: %w", err)
	}
	// modernc.org/sqlite serializes best with a single writer connection.
	db.SetMaxOpenConns(1)
	if err := gateSchemaVersion(db); err != nil {
		db.Close()
		return nil, err
	}
	if _, err := db.ExecContext(context.Background(), schema); err != nil {
		db.Close()
		return nil, fmt.Errorf("store: apply schema: %w", err)
	}
	if _, err := db.ExecContext(context.Background(), fmt.Sprintf("PRAGMA user_version=%d", schemaVersion)); err != nil {
		db.Close()
		return nil, fmt.Errorf("store: set user_version: %w", err)
	}
	// Reads run through a separate connection pool (rdb) so a long PullSegments
	// or retention scan holding the single writer connection (db) cannot
	// serialize list/dedup queries behind it. Under WAL, these readers run
	// concurrently against the last committed snapshot. rdb is opened AFTER the
	// writer applied the schema, so the -wal/-shm sidecars already exist. We use
	// a plain read/write handle (issuing only SELECTs), not mode=ro: a mode=ro
	// handle cannot create those sidecars and modernc.org/sqlite rejects PRAGMA
	// journal_mode(WAL) on a read-only connection, which would risk locking
	// flakiness. A plain second handle sidesteps both and gives the same WAL read
	// concurrency (P4).
	rdb, err := sql.Open("sqlite", dsn)
	if err != nil {
		db.Close()
		return nil, fmt.Errorf("store: open read db: %w", err)
	}
	readPool := runtime.NumCPU()
	if readPool < 4 {
		readPool = 4
	}
	rdb.SetMaxOpenConns(readPool)
	return &Store{
		db:        db,
		rdb:       rdb,
		blobDir:   cfg.BlobDir,
		retention: cfg.Retention,
		policy:    cfg.Policy,
		log:       cfg.Logger,
	}, nil
}

// gateSchemaVersion enforces the user_version contract: 0 (fresh or a store
// already migrated in this process) or the current schemaVersion are accepted;
// a version-0 store carrying a pre-v2 segments table (no deleted_at) is rejected
// with a clear "start fresh" error; any other version is unsupported.
func gateSchemaVersion(db *sql.DB) error {
	var version int
	if err := db.QueryRowContext(context.Background(), "PRAGMA user_version").Scan(&version); err != nil {
		return fmt.Errorf("store: read user_version: %w", err)
	}
	switch version {
	case 0:
		hasSegments, err := tableExists(db, "segments")
		if err != nil {
			return err
		}
		if !hasSegments {
			return nil // fresh database
		}
		hasDeletedAt, err := columnExists(db, "segments", "deleted_at")
		if err != nil {
			return err
		}
		if !hasDeletedAt {
			return fmt.Errorf("store: incompatible pre-v2 store at this path; " +
				"delete the store directory and start fresh (pre-alpha, no migration)")
		}
		return nil
	case schemaVersion:
		return nil
	default:
		return fmt.Errorf("store: unsupported schema version %d (want 0 or %d)", version, schemaVersion)
	}
}

func tableExists(db *sql.DB, name string) (bool, error) {
	var n int
	err := db.QueryRowContext(context.Background(),
		`SELECT COUNT(1) FROM sqlite_master WHERE type='table' AND name=?`, name).Scan(&n)
	if err != nil {
		return false, fmt.Errorf("store: check table %s: %w", name, err)
	}
	return n > 0, nil
}

func columnExists(db *sql.DB, table, column string) (bool, error) {
	rows, err := db.QueryContext(context.Background(), fmt.Sprintf("PRAGMA table_info(%s)", table))
	if err != nil {
		return false, fmt.Errorf("store: table_info %s: %w", table, err)
	}
	defer rows.Close()
	for rows.Next() {
		var cid int
		var name, typ string
		var notNull, pk int
		var dflt any
		if err := rows.Scan(&cid, &name, &typ, &notNull, &dflt, &pk); err != nil {
			return false, fmt.Errorf("store: scan table_info: %w", err)
		}
		if name == column {
			return true, nil
		}
	}
	return false, rows.Err()
}

// Close closes the underlying databases, the read pool first then the writer.
func (s *Store) Close() error {
	if err := s.rdb.Close(); err != nil {
		return fmt.Errorf("store: close read db: %w", err)
	}
	if err := s.db.Close(); err != nil {
		return fmt.Errorf("store: close: %w", err)
	}
	return nil
}

// UploadSegment receives a segment (meta header then frames) and ACKs only
// after the blob is fsynced and the index row committed. Segments already
// present (dedup key: source_id, seq range, root) are acked with duplicate set
// and no rewrite (REQ-E-04).
func (s *Store) UploadSegment(stream api.StoreUploadStream) error {
	first, err := stream.Recv()
	if err != nil {
		return fmt.Errorf("store: recv meta: %w", err)
	}
	meta := first.GetMeta()
	if meta == nil {
		return fmt.Errorf("store: first upload message must be meta")
	}
	if err := validateMeta(meta); err != nil {
		return err
	}
	// Re-canonicalize the id and build the path from it (never the raw wire
	// string) so a hostile segment_id cannot escape the blob dir (REQ-C-14).
	id, err := segment.ParseID(meta.SegmentId)
	if err != nil {
		return status.Errorf(codes.InvalidArgument, "store: invalid segment id: %v", err)
	}

	dup, err := s.isDuplicate(stream.Context(), meta)
	if err != nil {
		return err
	}

	blobPath := filepath.Join(s.blobDir, id.String()+blobExt)
	var tmpPath string
	var blob *os.File
	if !dup {
		// A unique temp name (os.CreateTemp opens O_EXCL with a random suffix)
		// so two concurrent uploads of the same UUIDv7 cannot share one tmp file
		// and clobber each other's bytes before the create-exclusive publish. The
		// final blob name is still derived from id.String() (REQ-C-14, REQ-E-04).
		blob, err = os.CreateTemp(s.blobDir, id.String()+"-*.tmp")
		if err != nil {
			return fmt.Errorf("store: create blob: %w", err)
		}
		tmpPath = blob.Name()
		defer func() {
			if blob != nil {
				blob.Close()
				os.Remove(tmpPath)
			}
		}()
	}

	frames := 0
	segmentBytes := 0
	// expectedSeq walks the declared [SeqFirst,SeqLast] range: each persisted
	// frame's record must carry the next contiguous seq and this segment's
	// source, so a stream that lies about its seq range or splices in another
	// source's records is rejected at ingest instead of surfacing later as a
	// confusing verifier gap (REQ-E-04).
	expectedSeq := meta.SeqFirst
	for {
		msg, err := stream.Recv()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return fmt.Errorf("store: recv frame: %w", err)
		}
		fr := msg.GetFrame()
		if fr == nil {
			return fmt.Errorf("store: expected frame message")
		}
		frames++
		if frames > maxSegmentFrames {
			return status.Errorf(codes.ResourceExhausted,
				"store: too many frames in one segment (max %d)", maxSegmentFrames)
		}
		// Cumulative byte ceiling: the frame-count cap alone leaves ~16 GiB of
		// tmp reachable at the maxFrameLen ceiling. Count every frame (dup drain
		// included) so a hostile stream is bounded regardless of path (REQ-E-04).
		segmentBytes += len(fr.RecordBytes)
		if segmentBytes > maxSegmentBytes {
			return status.Errorf(codes.ResourceExhausted,
				"store: segment exceeds byte cap (max %d bytes)", maxSegmentBytes)
		}
		if dup {
			continue // drain the stream without persisting
		}
		if err := verifyFrame(fr); err != nil {
			return err
		}
		rec, err := envelope.Parse(fr.RecordBytes)
		if err != nil {
			return status.Errorf(codes.InvalidArgument, "store: parse frame record: %v", err)
		}
		if rec.SourceID != meta.SourceId {
			return status.Errorf(codes.InvalidArgument,
				"store: frame source %q does not match segment source %q", rec.SourceID, meta.SourceId)
		}
		if rec.Seq != expectedSeq {
			return status.Errorf(codes.InvalidArgument,
				"store: frame seq %d out of order (want %d)", rec.Seq, expectedSeq)
		}
		expectedSeq++
		if err := writeFrame(blob, fr.RecordBytes, fr.RecordHash); err != nil {
			return err
		}
	}

	// The frames must cover exactly the declared range: expectedSeq has advanced
	// past SeqLast+1 iff SeqFirst..SeqLast were all present and contiguous. A
	// short or empty non-duplicate stream is a lying seq range and is rejected.
	if !dup && expectedSeq != meta.SeqLast+1 {
		return status.Errorf(codes.InvalidArgument,
			"store: segment declares seq range [%d,%d] but frames end at %d",
			meta.SeqFirst, meta.SeqLast, expectedSeq-1)
	}

	if dup {
		s.log.Debug("segment already present", "segment", meta.SegmentId, "source", meta.SourceId)
		return stream.SendAndClose(&api.SegmentAck{
			AckedSeq:  meta.SeqLast,
			SegmentId: meta.SegmentId,
			Duplicate: true,
		})
	}

	// Durability barrier: fsync the blob, then commit the index row (REQ-E-04).
	if err := blob.Sync(); err != nil {
		return fmt.Errorf("store: fsync blob: %w", err)
	}
	if err := blob.Close(); err != nil {
		return fmt.Errorf("store: close blob: %w", err)
	}
	// Publish create-exclusively: os.Link refuses to overwrite an existing
	// evidence blob, closing the replayed-UUID clobber window that a plain
	// rename would leave open before the segment_id PK insert rejects it. The
	// cleanup defer (blob still non-nil) removes tmpPath on the AlreadyExists
	// path (REQ-E-04).
	if err := os.Link(tmpPath, blobPath); err != nil {
		if errors.Is(err, os.ErrExist) {
			return status.Error(codes.AlreadyExists, "store: segment id already stored")
		}
		return fmt.Errorf("store: commit blob: %w", err)
	}
	if err := os.Remove(tmpPath); err != nil {
		return fmt.Errorf("store: remove tmp blob: %w", err)
	}
	blob = nil // disarm the cleanup defer

	if err := s.commitSegment(stream.Context(), meta, blobPath); err != nil {
		os.Remove(blobPath)
		return err
	}
	s.log.Info("segment stored", "segment", meta.SegmentId, "source", meta.SourceId,
		"seq_first", meta.SeqFirst, "seq_last", meta.SeqLast)
	return stream.SendAndClose(&api.SegmentAck{
		AckedSeq:  meta.SeqLast,
		SegmentId: meta.SegmentId,
		Duplicate: false,
	})
}

func (s *Store) isDuplicate(ctx context.Context, meta *api.SegmentMeta) (bool, error) {
	var n int
	err := s.rdb.QueryRowContext(ctx,
		`SELECT COUNT(1) FROM segments WHERE source_id=? AND seq_first=? AND seq_last=? AND root=?`,
		meta.SourceId, meta.SeqFirst, meta.SeqLast, meta.Root).Scan(&n)
	if err != nil {
		return false, fmt.Errorf("store: dedup query: %w", err)
	}
	return n > 0, nil
}

func (s *Store) commitSegment(ctx context.Context, meta *api.SegmentMeta, blobPath string) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO segments(segment_id, source_id, seq_first, seq_last, root, checkpoint, blob_path, created_at)
		 VALUES(?,?,?,?,?,?,?,?)`,
		meta.SegmentId, meta.SourceId, meta.SeqFirst, meta.SeqLast, meta.Root,
		meta.Checkpoint, blobPath, envelope.FormatTime(time.Now()))
	if err != nil {
		return fmt.Errorf("store: insert segment: %w", err)
	}
	return nil
}

// pullChunkSize bounds how many segment blob paths PullSegments buffers per
// keyset chunk, so a source with a huge segment count streams incrementally
// instead of materializing every path at once.
const pullChunkSize = 1024

// PullSegments streams back the exact stored frames of a source with
// seq >= from_seq, in seq order, for the verifier (REQ-E-05). Blob paths are
// fetched in keyset chunks on seq_first so a source with a huge segment count
// never buffers every path at once.
func (s *Store) PullSegments(req *api.PullRequest, stream api.StorePullStream) error {
	var afterSeqFirst uint64
	hasCursor := false
	for {
		paths, lastSeqFirst, err := s.segmentBlobPaths(stream.Context(), req.SourceId, req.FromSeq, afterSeqFirst, hasCursor)
		if err != nil {
			return err
		}
		for _, p := range paths {
			if err := s.streamBlob(p, req.FromSeq, stream); err != nil {
				return err
			}
		}
		if len(paths) < pullChunkSize {
			return nil
		}
		afterSeqFirst = lastSeqFirst
		hasCursor = true
	}
}

// segmentBlobPaths returns up to pullChunkSize live segment blob paths of source
// with seq_last >= fromSeq, in seq order, starting after afterSeqFirst when
// hasCursor is set (keyset pagination; per-source seq_first is unique). It also
// returns the chunk's last seq_first so the caller can advance the cursor.
func (s *Store) segmentBlobPaths(ctx context.Context, sourceID string, fromSeq, afterSeqFirst uint64, hasCursor bool) ([]string, uint64, error) {
	query := `SELECT blob_path, seq_first FROM segments WHERE source_id=? AND seq_last>=? AND deleted_at IS NULL`
	args := []any{sourceID, fromSeq}
	if hasCursor {
		query += ` AND seq_first > ?`
		args = append(args, afterSeqFirst)
	}
	query += ` ORDER BY seq_first LIMIT ?`
	args = append(args, pullChunkSize)
	rows, err := s.rdb.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, 0, fmt.Errorf("store: pull query: %w", err)
	}
	defer rows.Close()
	paths := make([]string, 0, pullChunkSize)
	var lastSeqFirst uint64
	for rows.Next() {
		var p string
		var seqFirst uint64
		if err := rows.Scan(&p, &seqFirst); err != nil {
			return nil, 0, fmt.Errorf("store: pull scan: %w", err)
		}
		paths = append(paths, p)
		lastSeqFirst = seqFirst
	}
	if err := rows.Err(); err != nil {
		return nil, 0, fmt.Errorf("store: pull rows: %w", err)
	}
	return paths, lastSeqFirst, nil
}

func (s *Store) streamBlob(path string, fromSeq uint64, stream api.StorePullStream) error {
	f, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("store: open blob: %w", err)
	}
	defer f.Close()
	r := newFrameReader(f)
	for {
		body, hash, err := r.next()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return err
		}
		rec, err := envelope.Parse(body)
		if err != nil {
			return fmt.Errorf("store: parse stored record: %w", err)
		}
		if rec.Seq < fromSeq {
			continue
		}
		if err := stream.Send(&api.Frame{RecordBytes: body, RecordHash: hash[:]}); err != nil {
			return fmt.Errorf("store: send frame: %w", err)
		}
	}
}

// SubmitCheckpoint records a checkpoint the store may forward to the verifier.
// v1 persists it; forwarding to the verifier is a TODO (the agent also submits
// checkpoints directly, so this is a belt-and-suspenders path).
func (s *Store) SubmitCheckpoint(ctx context.Context, n *api.SignedNote) (*api.CheckpointAck, error) {
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO checkpoints(source_id, origin, note, received_at) VALUES(?,?,?,?)`,
		n.SourceId, n.Origin, n.Note, envelope.FormatTime(time.Now()))
	if err != nil {
		return nil, fmt.Errorf("store: insert checkpoint: %w", err)
	}
	// TODO(REQ-C-07): forward checkpoints to the configured verifier.
	return &api.CheckpointAck{Accepted: true}, nil
}

// ApplyPolicy persists the effective policy when it differs from the latest
// stored retention_policies row (canonical-JSON comparison), returning whether a
// change was recorded plus the old and new policy JSON so the caller can seal a
// system.retention_policy_changed event. oldJSON is "" when no prior policy
// existed (REQ-E-11).
func (s *Store) ApplyPolicy(ctx context.Context) (changed bool, oldJSON, newJSON string, err error) {
	newJSON, err = s.policy.canonicalJSON()
	if err != nil {
		return false, "", "", err
	}
	var latest string
	row := s.db.QueryRowContext(ctx,
		`SELECT policy_json FROM retention_policies ORDER BY id DESC LIMIT 1`)
	switch err := row.Scan(&latest); {
	case errors.Is(err, sql.ErrNoRows):
		latest = ""
	case err != nil:
		return false, "", "", fmt.Errorf("store: read latest policy: %w", err)
	}
	if latest == newJSON {
		return false, latest, newJSON, nil
	}
	if _, err := s.db.ExecContext(ctx,
		`INSERT INTO retention_policies(policy_json, effective_at) VALUES(?,?)`,
		newJSON, envelope.FormatTime(time.Now())); err != nil {
		return false, "", "", fmt.Errorf("store: insert policy: %w", err)
	}
	return true, latest, newJSON, nil
}

// Policy returns the effective retention policy.
func (s *Store) Policy() RetentionPolicy { return s.policy }

// retentionCandidate is a live segment eligible for retention deletion.
type retentionCandidate struct {
	id, sourceID, blobPath string
	seqFirst, seqLast      uint64
	root                   []byte
}

// retentionCandidates returns up to limit live segments whose created_at
// predates cutoff, in segment_id order, starting after afterSegmentID (keyset
// pagination on the segment_id primary key). Held segments stay live so they
// re-match the filter; advancing the cursor by segment_id past every fetched
// row keeps a single enforcement run from re-fetching them and looping forever.
func (s *Store) retentionCandidates(ctx context.Context, cutoff time.Time, afterSegmentID string, limit int) ([]retentionCandidate, error) {
	query := `SELECT segment_id, source_id, seq_first, seq_last, root, blob_path
		   FROM segments WHERE deleted_at IS NULL AND created_at < ?`
	args := []any{envelope.FormatTime(cutoff)}
	if afterSegmentID != "" {
		query += ` AND segment_id > ?`
		args = append(args, afterSegmentID)
	}
	query += ` ORDER BY segment_id LIMIT ?`
	args = append(args, limit)
	// Read pool, not the single writer connection: a large retention scan must
	// not serialize behind upload ACKs. Safe against read-your-writes because the
	// segment_id keyset cursor only ever advances past already-fetched rows, so a
	// deleted_at UPDATE flushed earlier in the same pass can never resurface here
	// even under a slightly stale WAL snapshot (P-perf).
	rows, err := s.rdb.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("store: retention query: %w", err)
	}
	defer rows.Close()
	candidates := make([]retentionCandidate, 0, limit)
	for rows.Next() {
		var c retentionCandidate
		if err := rows.Scan(&c.id, &c.sourceID, &c.seqFirst, &c.seqLast, &c.root, &c.blobPath); err != nil {
			return nil, fmt.Errorf("store: retention scan: %w", err)
		}
		candidates = append(candidates, c)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store: retention rows: %w", err)
	}
	return candidates, nil
}

// EnforceRetention deletes live segments whose created_at predates the policy
// cutoff (DefaultDays), excluding any segment overlapping an active legal hold.
// Deletion removes the blob file and sets deleted_at; the row survives as a
// permanent tombstone. It returns the tombstones for event emission. A
// DefaultDays <= 0 disables deletion (REQ-E-11, REQ-R-10).
func (s *Store) EnforceRetention(ctx context.Context) ([]Tombstone, error) {
	if s.policy.DefaultDays <= 0 {
		return nil, nil
	}
	cutoff := time.Now().AddDate(0, 0, -s.policy.DefaultDays)
	policyJSON, err := s.policy.canonicalJSON()
	if err != nil {
		return nil, err
	}

	holds, err := s.activeHolds(ctx)
	if err != nil {
		return nil, err
	}

	// One timestamp per enforcement run: the tombstones record the pass that
	// deleted them, and a single batched UPDATE replaces one round-trip per
	// segment. Blobs are removed before their rows are marked (chunked so a
	// mid-run failure leaves at most one chunk of removed-but-live rows).
	deletedAt := time.Now()
	deletedAtStr := envelope.FormatTime(deletedAt)
	var tombstones []Tombstone
	var batch []string
	flush := func() error {
		if len(batch) == 0 {
			return nil
		}
		args := make([]any, 0, len(batch)+1)
		args = append(args, deletedAtStr)
		for _, id := range batch {
			args = append(args, id)
		}
		placeholders := strings.TrimSuffix(strings.Repeat("?,", len(batch)), ",")
		if _, err := s.db.ExecContext(ctx,
			`UPDATE segments SET deleted_at=? WHERE segment_id IN (`+placeholders+`)`,
			args...); err != nil {
			return fmt.Errorf("store: set deleted_at: %w", err)
		}
		batch = batch[:0]
		return nil
	}

	// Candidates are fetched in keyset chunks on segment_id so a source with a
	// huge expired-segment count never buffers every row. Each chunk removes its
	// blobs before flushing its deleted_at UPDATE; the cursor advances past every
	// fetched row (held or not) so a run terminates.
	afterSegmentID := ""
	for {
		candidates, err := s.retentionCandidates(ctx, cutoff, afterSegmentID, retentionUpdateBatch)
		if err != nil {
			return nil, err
		}
		if len(candidates) == 0 {
			break
		}
		for _, c := range candidates {
			if heldBy(holds, c.sourceID, c.seqFirst, c.seqLast) {
				continue
			}
			if err := os.Remove(c.blobPath); err != nil && !errors.Is(err, os.ErrNotExist) {
				return nil, fmt.Errorf("store: remove blob %s: %w", c.blobPath, err)
			}
			batch = append(batch, c.id)
			if len(batch) >= retentionUpdateBatch {
				if err := flush(); err != nil {
					return nil, err
				}
			}
			tombstones = append(tombstones, Tombstone{
				SegmentID: c.id, SourceID: c.sourceID, SeqFirst: c.seqFirst, SeqLast: c.seqLast,
				Root: c.root, DeletedAt: deletedAt.UTC(), Policy: policyJSON,
			})
			s.log.Info("segment expired under retention", "segment", c.id, "source", c.sourceID,
				"seq_first", c.seqFirst, "seq_last", c.seqLast)
		}
		if err := flush(); err != nil {
			return nil, err
		}
		afterSegmentID = candidates[len(candidates)-1].id
		if len(candidates) < retentionUpdateBatch {
			break
		}
	}
	return tombstones, nil
}

// activeHold is an in-memory view of an unreleased hold. hasRange false means
// the hold covers the whole source.
type activeHold struct {
	sourceID          string
	hasRange          bool
	seqFirst, seqLast uint64
}

func (s *Store) activeHolds(ctx context.Context) ([]activeHold, error) {
	// Read pool: this pure SELECT is read once at the start of an enforcement
	// pass, before any write in that pass, so no read-your-writes dependency ties
	// it to the writer connection (P-perf).
	rows, err := s.rdb.QueryContext(ctx,
		`SELECT source_id, seq_first, seq_last FROM holds WHERE released_at IS NULL`)
	if err != nil {
		return nil, fmt.Errorf("store: active holds query: %w", err)
	}
	defer rows.Close()
	var out []activeHold
	for rows.Next() {
		var src string
		var first, last sql.NullInt64
		if err := rows.Scan(&src, &first, &last); err != nil {
			return nil, fmt.Errorf("store: active holds scan: %w", err)
		}
		h := activeHold{sourceID: src}
		if first.Valid && last.Valid {
			h.hasRange = true
			h.seqFirst = uint64(first.Int64)
			h.seqLast = uint64(last.Int64)
		}
		out = append(out, h)
	}
	return out, rows.Err()
}

// heldBy reports whether a segment [first,last] on source is exempted by any
// active hold: a whole-source hold always matches; a ranged hold matches when
// the seq intervals intersect.
func heldBy(holds []activeHold, source string, first, last uint64) bool {
	for _, h := range holds {
		if h.sourceID != source {
			continue
		}
		if !h.hasRange {
			return true
		}
		if first <= h.seqLast && last >= h.seqFirst {
			return true
		}
	}
	return false
}

// EventSink seals a store-originated system event into the evidence chain via a
// designated agent's HTTP ingest. A nil sink (no --agent-http configured)
// degrades gracefully: the action still takes effect, only the event is not
// chain-sealed (WS6 settled decision).
type EventSink func(ctx context.Context, eventType string, payload any)

// SetEventSink wires the designated-agent event emitter for retention and hold
// system events.
func (s *Store) SetEventSink(sink EventSink) { s.emit = sink }

// emitEvent forwards a system event to the sink, warning when none is wired.
func (s *Store) emitEvent(ctx context.Context, eventType string, payload any) {
	if s.emit == nil {
		s.log.Warn("system event not chain-sealed (no --agent-http)", "event", eventType)
		return
	}
	s.emit(ctx, eventType, payload)
}

// PlaceHold records a legal hold and seals a system.legal_hold_placed event.
// reason is required (REQ-E-11).
func (s *Store) PlaceHold(ctx context.Context, req *api.PlaceHoldRequest) (*api.Hold, error) {
	if req.SourceId == "" {
		return nil, status.Error(codes.InvalidArgument, "store: source_id is required")
	}
	if req.Reason == "" {
		return nil, status.Error(codes.InvalidArgument, "store: reason is required for a legal hold")
	}
	id, err := segment.NewID(time.Now(), rand.Reader)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "store: mint hold id: %v", err)
	}
	holdID := id.String()
	placedAt := envelope.FormatTime(time.Now())
	var first, last any
	if req.HasRange {
		first, last = int64(req.SeqFirst), int64(req.SeqLast)
	}
	if _, err := s.db.ExecContext(ctx,
		`INSERT INTO holds(hold_id, source_id, seq_first, seq_last, reason, placed_by, placed_at)
		 VALUES(?,?,?,?,?,?,?)`,
		holdID, req.SourceId, first, last, req.Reason, req.PlacedBy, placedAt); err != nil {
		return nil, status.Errorf(codes.Internal, "store: insert hold: %v", err)
	}
	s.log.Info("legal hold placed", "hold", holdID, "source", req.SourceId, "reason", req.Reason)
	s.emitEvent(ctx, "system.legal_hold_placed", map[string]any{
		"hold_id": holdID, "source_id": req.SourceId, "has_range": req.HasRange,
		"seq_first": req.SeqFirst, "seq_last": req.SeqLast, "reason": req.Reason, "placed_by": req.PlacedBy,
	})
	return &api.Hold{
		HoldId: holdID, SourceId: req.SourceId, SeqFirst: req.SeqFirst, SeqLast: req.SeqLast,
		HasRange: req.HasRange, Reason: req.Reason, PlacedBy: req.PlacedBy, PlacedAt: placedAt,
	}, nil
}

// ReleaseHold releases an active legal hold and seals a
// system.legal_hold_released event. Releasing an already-released hold errors.
func (s *Store) ReleaseHold(ctx context.Context, req *api.ReleaseHoldRequest) (*api.Hold, error) {
	if req.HoldId == "" {
		return nil, status.Error(codes.InvalidArgument, "store: hold_id is required")
	}
	h, err := s.loadHold(ctx, req.HoldId)
	if err != nil {
		return nil, err
	}
	if h.ReleasedAt != "" {
		return nil, status.Errorf(codes.FailedPrecondition, "store: hold %s already released", req.HoldId)
	}
	releasedAt := envelope.FormatTime(time.Now())
	if _, err := s.db.ExecContext(ctx,
		`UPDATE holds SET released_at=? WHERE hold_id=?`, releasedAt, req.HoldId); err != nil {
		return nil, status.Errorf(codes.Internal, "store: release hold: %v", err)
	}
	h.ReleasedAt = releasedAt
	s.log.Info("legal hold released", "hold", req.HoldId, "source", h.SourceId)
	s.emitEvent(ctx, "system.legal_hold_released", map[string]any{
		"hold_id": h.HoldId, "source_id": h.SourceId, "has_range": h.HasRange,
		"seq_first": h.SeqFirst, "seq_last": h.SeqLast, "reason": h.Reason,
	})
	return h, nil
}

// clampPageSize maps a requested page size to the effective server size:
// 0 becomes listPageMax (the default) and oversized values clamp to listPageMax.
func clampPageSize(requested uint32) int {
	if requested == 0 || requested > listPageMax {
		return listPageMax
	}
	return int(requested)
}

// ListHolds returns holds, optionally filtered to one source, paginated by
// keyset on hold_id. hold_id is a UUIDv7 primary key, so ascending lexicographic
// order is placement order. A non-empty NextPageToken is the last returned
// hold_id; an empty token means the listing is complete.
func (s *Store) ListHolds(ctx context.Context, req *api.ListHoldsRequest) (*api.ListHoldsResponse, error) {
	size := clampPageSize(req.PageSize)
	query := `SELECT hold_id, source_id, seq_first, seq_last, reason, placed_by, placed_at, released_at FROM holds WHERE 1=1`
	var args []any
	if req.SourceId != "" {
		query += ` AND source_id=?`
		args = append(args, req.SourceId)
	}
	if req.PageToken != "" {
		query += ` AND hold_id > ?`
		args = append(args, req.PageToken)
	}
	query += ` ORDER BY hold_id LIMIT ?`
	args = append(args, size+1)
	rows, err := s.rdb.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "store: list holds: %v", err)
	}
	defer rows.Close()
	out := make([]*api.Hold, 0, size)
	for rows.Next() {
		h, err := scanHold(rows)
		if err != nil {
			return nil, status.Errorf(codes.Internal, "store: scan hold: %v", err)
		}
		out = append(out, h)
	}
	if err := rows.Err(); err != nil {
		return nil, status.Errorf(codes.Internal, "store: list holds rows: %v", err)
	}
	var nextToken string
	if len(out) > size {
		out = out[:size]
		nextToken = out[len(out)-1].HoldId
	}
	return &api.ListHoldsResponse{Holds: out, NextPageToken: nextToken}, nil
}

// ListTombstones returns segments deleted under retention (blob gone, row
// retained), optionally filtered to one source, paginated by keyset on
// segment_id (a UUIDv7 TEXT primary key). A non-empty NextPageToken is the last
// returned segment_id; an empty token means the listing is complete.
func (s *Store) ListTombstones(ctx context.Context, req *api.ListTombstonesRequest) (*api.ListTombstonesResponse, error) {
	policyJSON, err := s.policy.canonicalJSON()
	if err != nil {
		return nil, status.Errorf(codes.Internal, "%v", err)
	}
	size := clampPageSize(req.PageSize)
	query := `SELECT segment_id, source_id, seq_first, seq_last, root, deleted_at
	            FROM segments WHERE deleted_at IS NOT NULL`
	var args []any
	if req.SourceId != "" {
		query += ` AND source_id=?`
		args = append(args, req.SourceId)
	}
	if req.PageToken != "" {
		query += ` AND segment_id > ?`
		args = append(args, req.PageToken)
	}
	query += ` ORDER BY segment_id LIMIT ?`
	args = append(args, size+1)
	rows, err := s.rdb.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "store: list tombstones: %v", err)
	}
	defer rows.Close()
	out := make([]*api.Tombstone, 0, size)
	for rows.Next() {
		var t api.Tombstone
		if err := rows.Scan(&t.SegmentId, &t.SourceId, &t.SeqFirst, &t.SeqLast, &t.Root, &t.DeletedAt); err != nil {
			return nil, status.Errorf(codes.Internal, "store: scan tombstone: %v", err)
		}
		t.Policy = policyJSON
		out = append(out, &t)
	}
	if err := rows.Err(); err != nil {
		return nil, status.Errorf(codes.Internal, "store: list tombstones rows: %v", err)
	}
	var nextToken string
	if len(out) > size {
		out = out[:size]
		nextToken = out[len(out)-1].SegmentId
	}
	return &api.ListTombstonesResponse{Tombstones: out, NextPageToken: nextToken}, nil
}

func (s *Store) loadHold(ctx context.Context, holdID string) (*api.Hold, error) {
	row := s.db.QueryRowContext(ctx,
		`SELECT hold_id, source_id, seq_first, seq_last, reason, placed_by, placed_at, released_at
		   FROM holds WHERE hold_id=?`, holdID)
	h, err := scanHold(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, status.Errorf(codes.NotFound, "store: hold %s not found", holdID)
	}
	if err != nil {
		return nil, status.Errorf(codes.Internal, "store: load hold: %v", err)
	}
	return h, nil
}

// rowScanner abstracts *sql.Row and *sql.Rows for shared hold scanning.
type rowScanner interface {
	Scan(dest ...any) error
}

func scanHold(r rowScanner) (*api.Hold, error) {
	var h api.Hold
	var first, last sql.NullInt64
	var placedBy, releasedAt sql.NullString
	if err := r.Scan(&h.HoldId, &h.SourceId, &first, &last, &h.Reason, &placedBy, &h.PlacedAt, &releasedAt); err != nil {
		return nil, err
	}
	if first.Valid && last.Valid {
		h.HasRange = true
		h.SeqFirst = uint64(first.Int64)
		h.SeqLast = uint64(last.Int64)
	}
	h.PlacedBy = placedBy.String
	h.ReleasedAt = releasedAt.String
	return &h, nil
}

// validateMeta rejects a malformed or hostile segment header before any blob is
// created. It is the meta-level sibling of verifyFrame: the SegmentId must be a
// canonical UUIDv7 (guards the blob path against traversal), the source and seq
// range must be well-formed, and the root must be a 32-byte hash (REQ-C-14,
// REQ-E-04).
func validateMeta(m *api.SegmentMeta) error {
	if _, err := segment.ParseID(m.SegmentId); err != nil {
		return status.Errorf(codes.InvalidArgument, "store: invalid segment id: %v", err)
	}
	if m.SourceId == "" {
		return status.Error(codes.InvalidArgument, "store: source_id is required")
	}
	if m.SeqFirst == 0 || m.SeqFirst > m.SeqLast {
		return status.Errorf(codes.InvalidArgument, "store: invalid seq range [%d,%d]", m.SeqFirst, m.SeqLast)
	}
	root, err := hashid.ParseDigest(m.Root)
	if err != nil {
		return status.Errorf(codes.InvalidArgument, "store: %v", err)
	}
	// Bind the declared root to the signed checkpoint the store persists
	// alongside it. The checkpoint (a C2SP tlog-checkpoint) commits to
	// (tree size, root); a segment whose declared root or seq-last disagrees
	// with its own checkpoint is internally inconsistent and is rejected here
	// rather than persisted as an unverifiable claim. The store does NOT
	// recompute the cumulative Merkle root at ingest: that root spans the
	// source's full history [1..seq_last], whose earlier frames are not in this
	// stream, so re-deriving it would cost O(history) per upload — full root
	// recomputation against the signed checkpoint is the offline verifier's job
	// (RootsValid). What the store CAN do cheaply is refuse a root that
	// contradicts the checkpoint already in hand (REQ-C-07, REQ-E-04). See
	// docs/trust-boundaries.md and ADR-0009.
	cp, err := note.CheckpointOf(m.Checkpoint)
	if err != nil {
		return status.Errorf(codes.InvalidArgument, "store: malformed checkpoint: %v", err)
	}
	if cp.Size != m.SeqLast {
		return status.Errorf(codes.InvalidArgument,
			"store: checkpoint size %d does not match seq_last %d", cp.Size, m.SeqLast)
	}
	if root != cp.Hash {
		return status.Error(codes.InvalidArgument, "store: root does not match checkpoint")
	}
	return nil
}

func verifyFrame(fr *api.Frame) error {
	hash, err := hashid.ParseDigest(fr.RecordHash)
	if err != nil {
		return fmt.Errorf("store: frame hash: %w", err)
	}
	// Enforce the frame-length ceiling on the write path too, not just on
	// read-back, so a hostile client cannot spool an oversized frame (REQ-E-04).
	if n := len(fr.RecordBytes); n == 0 || n > maxFrameLen {
		return status.Errorf(codes.InvalidArgument, "store: implausible frame length %d", n)
	}
	if sha256.Sum256(fr.RecordBytes) != hash {
		return fmt.Errorf("store: frame hash mismatch")
	}
	return nil
}

func writeFrame(w io.Writer, body, hash []byte) error {
	var hdr [binary.MaxVarintLen64]byte
	n := binary.PutUvarint(hdr[:], uint64(len(body)))
	if _, err := w.Write(hdr[:n]); err != nil {
		return fmt.Errorf("store: write frame len: %w", err)
	}
	if _, err := w.Write(body); err != nil {
		return fmt.Errorf("store: write frame body: %w", err)
	}
	if _, err := w.Write(hash); err != nil {
		return fmt.Errorf("store: write frame hash: %w", err)
	}
	return nil
}

// frameReader reads the length-prefixed frames written by writeFrame.
type frameReader struct {
	r *bufio.Reader
}

func newFrameReader(r io.Reader) *frameReader {
	return &frameReader{r: bufio.NewReader(r)}
}

// next returns the next frame's record bytes and hash, or io.EOF at a clean end.
func (fr *frameReader) next() ([]byte, [hashSize]byte, error) {
	var hash [hashSize]byte
	if _, err := fr.r.Peek(1); err != nil {
		if errors.Is(err, io.EOF) {
			return nil, hash, io.EOF
		}
		return nil, hash, fmt.Errorf("store: peek frame: %w", err)
	}
	length, err := binary.ReadUvarint(fr.r)
	if err != nil {
		return nil, hash, fmt.Errorf("store: read frame len: %w", err)
	}
	if length == 0 || length > maxFrameLen {
		return nil, hash, fmt.Errorf("store: implausible frame length %d", length)
	}
	body := make([]byte, length)
	if _, err := io.ReadFull(fr.r, body); err != nil {
		return nil, hash, fmt.Errorf("store: read frame body: %w", err)
	}
	if _, err := io.ReadFull(fr.r, hash[:]); err != nil {
		return nil, hash, fmt.Errorf("store: read frame hash: %w", err)
	}
	return body, hash, nil
}
