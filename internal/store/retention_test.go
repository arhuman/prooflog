package store

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	_ "modernc.org/sqlite"

	"github.com/arhuman/prooflog/internal/api"
	"github.com/arhuman/prooflog/internal/envelope"
)

// seedSegment inserts a live segment row with a controllable created_at and a
// placeholder blob file, returning the blob path.
func seedSegment(t *testing.T, s *Store, id, source string, first, last uint64, createdAt time.Time) string {
	t.Helper()
	blobPath := filepath.Join(s.blobDir, id+blobExt)
	if err := os.WriteFile(blobPath, []byte("blob-"+id), 0o600); err != nil {
		t.Fatal(err)
	}
	root := make([]byte, 32)
	root[0] = byte(first)
	_, err := s.db.ExecContext(context.Background(),
		`INSERT INTO segments(segment_id, source_id, seq_first, seq_last, root, checkpoint, blob_path, created_at)
		 VALUES(?,?,?,?,?,?,?,?)`,
		id, source, first, last, root, "cp", blobPath, envelope.FormatTime(createdAt))
	if err != nil {
		t.Fatal(err)
	}
	return blobPath
}

func fileGone(path string) bool {
	_, err := os.Stat(path)
	return os.IsNotExist(err)
}

func TestEnforceRetentionExpiresAndTombstones(t *testing.T) {
	s := newTestStore(t)
	s.policy = RetentionPolicy{DefaultDays: 30}
	old := seedSegment(t, s, "seg-old", "vps-01/api", 1, 10, time.Now().AddDate(0, 0, -40))
	fresh := seedSegment(t, s, "seg-new", "vps-01/api", 11, 20, time.Now())

	tombstones, err := s.EnforceRetention(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(tombstones) != 1 {
		t.Fatalf("want 1 tombstone, got %d", len(tombstones))
	}
	if tombstones[0].SegmentID != "seg-old" {
		t.Fatalf("tombstoned wrong segment: %s", tombstones[0].SegmentID)
	}
	if !fileGone(old) {
		t.Fatal("expired blob should be removed")
	}
	if fileGone(fresh) {
		t.Fatal("fresh blob should survive")
	}
	// The row survives as a permanent tombstone with deleted_at set.
	var deletedAt sql.NullString
	if err := s.db.QueryRowContext(context.Background(), `SELECT deleted_at FROM segments WHERE segment_id='seg-old'`).Scan(&deletedAt); err != nil {
		t.Fatal(err)
	}
	if !deletedAt.Valid || deletedAt.String == "" {
		t.Fatal("tombstone row must retain deleted_at")
	}
}

func TestEnforceRetentionSkipsHeldSegments(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)
	s.policy = RetentionPolicy{DefaultDays: 30}
	blob := seedSegment(t, s, "seg-held", "vps-01/api", 1, 10, time.Now().AddDate(0, 0, -40))

	// Whole-source active hold: the old segment must survive the pass.
	hold, err := s.PlaceHold(ctx, &api.PlaceHoldRequest{SourceId: "vps-01/api", Reason: "litigation"})
	if err != nil {
		t.Fatal(err)
	}
	tombstones, err := s.EnforceRetention(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(tombstones) != 0 {
		t.Fatalf("held segment must not be deleted, got %d tombstones", len(tombstones))
	}
	if fileGone(blob) {
		t.Fatal("held blob should survive")
	}

	// After release, the next pass expires it.
	if _, err := s.ReleaseHold(ctx, &api.ReleaseHoldRequest{HoldId: hold.HoldId}); err != nil {
		t.Fatal(err)
	}
	tombstones, err = s.EnforceRetention(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(tombstones) != 1 {
		t.Fatalf("released hold should let the segment expire, got %d tombstones", len(tombstones))
	}
	if !fileGone(blob) {
		t.Fatal("blob should be removed after release")
	}
}

func TestEnforceRetentionRangedHold(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)
	s.policy = RetentionPolicy{DefaultDays: 30}
	held := seedSegment(t, s, "seg-a", "vps-01/api", 1, 10, time.Now().AddDate(0, 0, -40))
	free := seedSegment(t, s, "seg-b", "vps-01/api", 11, 20, time.Now().AddDate(0, 0, -40))

	// A ranged hold covering seq 5..8 intersects seg-a only.
	if _, err := s.PlaceHold(ctx, &api.PlaceHoldRequest{
		SourceId: "vps-01/api", HasRange: true, SeqFirst: 5, SeqLast: 8, Reason: "hold range",
	}); err != nil {
		t.Fatal(err)
	}
	tombstones, err := s.EnforceRetention(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(tombstones) != 1 || tombstones[0].SegmentID != "seg-b" {
		t.Fatalf("only seg-b should expire, got %+v", tombstones)
	}
	if fileGone(held) {
		t.Fatal("range-held seg-a should survive")
	}
	if !fileGone(free) {
		t.Fatal("unheld seg-b should be removed")
	}
}

// TestEnforceRetentionBatchBoundary crosses the retentionUpdateBatch chunk so
// both the mid-loop flush and the final partial flush mark their rows.
func TestEnforceRetentionBatchBoundary(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)
	s.policy = RetentionPolicy{DefaultDays: 30}

	n := retentionUpdateBatch + 3
	old := time.Now().AddDate(0, 0, -40)
	for i := 0; i < n; i++ {
		first := uint64(i*10 + 1)
		seedSegment(t, s, fmt.Sprintf("seg-%04d", i), "vps-01/api", first, first+9, old)
	}

	tombstones, err := s.EnforceRetention(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(tombstones) != n {
		t.Fatalf("want %d tombstones, got %d", n, len(tombstones))
	}
	var marked, live int
	if err := s.db.QueryRowContext(ctx,
		`SELECT COUNT(1) FROM segments WHERE deleted_at IS NOT NULL`).Scan(&marked); err != nil {
		t.Fatal(err)
	}
	if err := s.db.QueryRowContext(ctx,
		`SELECT COUNT(1) FROM segments WHERE deleted_at IS NULL`).Scan(&live); err != nil {
		t.Fatal(err)
	}
	if marked != n || live != 0 {
		t.Fatalf("want %d marked and 0 live rows, got %d marked, %d live", n, marked, live)
	}
}

func TestApplyPolicyIdempotent(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)
	s.policy = RetentionPolicy{DefaultDays: 90, Frameworks: map[string]int{"gdpr": 365}}

	changed, oldJSON, newJSON, err := s.ApplyPolicy(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if !changed || oldJSON != "" || newJSON == "" {
		t.Fatalf("first apply: changed=%v old=%q new=%q", changed, oldJSON, newJSON)
	}
	changed, _, _, err = s.ApplyPolicy(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if changed {
		t.Fatal("re-applying the same policy should not record a change")
	}
	var rows int
	if err := s.db.QueryRowContext(ctx, `SELECT COUNT(1) FROM retention_policies`).Scan(&rows); err != nil {
		t.Fatal(err)
	}
	if rows != 1 {
		t.Fatalf("want exactly 1 policy row, got %d", rows)
	}
}

func TestOpenRejectsPreV2Store(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "index.db")
	// Build a pre-v2 store: a segments table without deleted_at, user_version 0.
	db, err := sql.Open("sqlite", "file:"+dbPath)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(context.Background(), `CREATE TABLE segments (segment_id TEXT PRIMARY KEY, source_id TEXT)`); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(Config{DBPath: dbPath, BlobDir: filepath.Join(dir, "blobs")}); err == nil {
		t.Fatal("opening a pre-v2 store should fail with an incompatibility error")
	}
}

func TestListTombstonesAndHoldRoundTrip(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)
	client := dialStore(t, s)

	// Place, list, release a hold over gRPC.
	placed, err := client.PlaceHold(ctx, &api.PlaceHoldRequest{
		SourceId: "vps-01/api", Reason: "audit", PlacedBy: "dpo",
	})
	if err != nil {
		t.Fatal(err)
	}
	if placed.HoldId == "" || placed.HasRange {
		t.Fatalf("unexpected hold: %+v", placed)
	}
	list, err := client.ListHolds(ctx, &api.ListHoldsRequest{SourceId: "vps-01/api"})
	if err != nil {
		t.Fatal(err)
	}
	if len(list.Holds) != 1 {
		t.Fatalf("want 1 hold, got %d", len(list.Holds))
	}
	if _, err := client.ReleaseHold(ctx, &api.ReleaseHoldRequest{HoldId: placed.HoldId}); err != nil {
		t.Fatal(err)
	}
	if _, err := client.ReleaseHold(ctx, &api.ReleaseHoldRequest{HoldId: placed.HoldId}); err == nil {
		t.Fatal("releasing an already-released hold should error")
	}

	// A missing reason is rejected.
	if _, err := client.PlaceHold(ctx, &api.PlaceHoldRequest{SourceId: "vps-01/api"}); err == nil {
		t.Fatal("PlaceHold without a reason should fail")
	}

	// Tombstones survive as rows and are listable.
	s.policy = RetentionPolicy{DefaultDays: 30}
	seedSegment(t, s, "seg-x", "vps-01/api", 1, 5, time.Now().AddDate(0, 0, -40))
	if _, err := s.EnforceRetention(ctx); err != nil {
		t.Fatal(err)
	}
	tomb, err := client.ListTombstones(ctx, &api.ListTombstonesRequest{SourceId: "vps-01/api"})
	if err != nil {
		t.Fatal(err)
	}
	if len(tomb.Tombstones) != 1 || tomb.Tombstones[0].SegmentId != "seg-x" {
		t.Fatalf("want seg-x tombstone, got %+v", tomb.Tombstones)
	}
}
