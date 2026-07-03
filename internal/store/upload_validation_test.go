package store

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/arhuman/prooflog/internal/api"
)

// newTestStoreWithDir opens a store and returns it alongside its blob directory
// so a test can inspect exactly what landed on disk.
func newTestStoreWithDir(t *testing.T) (*Store, string) {
	t.Helper()
	dir := t.TempDir()
	blobDir := filepath.Join(dir, "blobs")
	s, err := Open(Config{DBPath: filepath.Join(dir, "index.db"), BlobDir: blobDir})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s, blobDir
}

func TestUploadRejectsTraversalSegmentID(t *testing.T) {
	s, blobDir := newTestStoreWithDir(t)
	client := dialStore(t, s)

	meta := sampleMeta(t)
	meta.SegmentId = "../../evil"
	// No frames: validateMeta rejects on the meta message, so sending frames
	// would race the server closing the stream.
	_, err := upload(t, client, meta, nil)
	if status.Code(err) != codes.InvalidArgument {
		t.Fatalf("traversal segment id: got code %v (err %v), want InvalidArgument", status.Code(err), err)
	}

	// Nothing was written inside the blob dir, and nothing escaped above it.
	entries, err := os.ReadDir(blobDir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("blob dir should be empty, has %d entries", len(entries))
	}
	if _, err := os.Stat(filepath.Join(blobDir, "..", "evil"+blobExt)); !os.IsNotExist(err) {
		t.Fatalf("traversal wrote a blob outside blob dir: %v", err)
	}
}

func TestUploadReusedSegmentIDDoesNotOverwrite(t *testing.T) {
	s, blobDir := newTestStoreWithDir(t)
	client := dialStore(t, s)

	if _, err := upload(t, client, sampleMeta(t), []*api.Frame{makeFrame(t, 1), makeFrame(t, 2)}); err != nil {
		t.Fatalf("first upload: %v", err)
	}

	entries, err := os.ReadDir(blobDir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		t.Fatalf("expected exactly one stored blob, got %d", len(entries))
	}
	blobPath := filepath.Join(blobDir, entries[0].Name())
	original, err := os.ReadFile(blobPath)
	if err != nil {
		t.Fatal(err)
	}

	// Same segment_id, different content (distinct root) so it is not a dedup
	// hit: the create-exclusive publish must reject it rather than clobber. The
	// frames still carry the declared seq range [1,2] so the upload reaches the
	// publish step (a mismatched seq range is rejected earlier at ingest).
	var replayRoot [32]byte
	for i := range replayRoot {
		replayRoot[i] = 0xAA
	}
	replay := metaWithRoot(t, replayRoot)
	_, err = upload(t, client, replay, []*api.Frame{makeFrame(t, 1), makeFrame(t, 2)})
	if status.Code(err) != codes.AlreadyExists {
		t.Fatalf("reused segment id: got code %v (err %v), want AlreadyExists", status.Code(err), err)
	}

	after, err := os.ReadFile(blobPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(original, after) {
		t.Fatal("original evidence blob was overwritten by a reused segment id")
	}
}

// TestUploadRejectsByteCap lowers the cumulative byte ceiling to just above two
// frames and confirms a third frame — still under maxSegmentFrames — crosses the
// byte cap and is rejected with ResourceExhausted. The frames are real envelopes
// (the ingest path now parses each frame), so the byte cap fires on the third
// frame's size check before it would be parsed.
func TestUploadRejectsByteCap(t *testing.T) {
	f1, f2, f3 := makeFrame(t, 1), makeFrame(t, 2), makeFrame(t, 3)
	saved := maxSegmentBytes
	maxSegmentBytes = len(f1.RecordBytes) + len(f2.RecordBytes) + 1
	t.Cleanup(func() { maxSegmentBytes = saved })

	client := dialStore(t, newTestStore(t))
	if _, err := upload(t, client, sampleMeta(t), []*api.Frame{f1, f2, f3}); status.Code(err) != codes.ResourceExhausted {
		t.Fatalf("byte cap: got code %v (err %v), want ResourceExhausted", status.Code(err), err)
	}
}

// TestConcurrentSameIDUploadsNoCorruption fires two uploads of the same
// segment_id with different content at once. With per-upload unique temp files,
// exactly one publish wins, the other is rejected AlreadyExists, and no partial
// or leftover .tmp file survives to corrupt the published blob.
func TestConcurrentSameIDUploadsNoCorruption(t *testing.T) {
	s, blobDir := newTestStoreWithDir(t)
	client := dialStore(t, s)

	metaA := sampleMeta(t)
	// Same segment_id, distinct root (with matching checkpoint) => not a dedup hit.
	var rootB [32]byte
	for i := range rootB {
		rootB[i] = 0xBB
	}
	metaB := metaWithRoot(t, rootB)

	var wg sync.WaitGroup
	errs := make([]error, 2)
	wg.Add(2)
	go func() {
		defer wg.Done()
		_, errs[0] = upload(t, client, metaA, []*api.Frame{makeFrame(t, 1), makeFrame(t, 2)})
	}()
	go func() {
		defer wg.Done()
		_, errs[1] = upload(t, client, metaB, []*api.Frame{makeFrame(t, 1), makeFrame(t, 2)})
	}()
	wg.Wait()

	winners, conflicts := 0, 0
	for _, err := range errs {
		switch {
		case err == nil:
			winners++
		case status.Code(err) == codes.AlreadyExists:
			conflicts++
		default:
			t.Fatalf("unexpected upload error: %v", err)
		}
	}
	if winners != 1 || conflicts != 1 {
		t.Fatalf("want exactly one winner and one AlreadyExists, got winners=%d conflicts=%d", winners, conflicts)
	}

	entries, err := os.ReadDir(blobDir)
	if err != nil {
		t.Fatal(err)
	}
	var blobs, tmps int
	for _, e := range entries {
		switch {
		case strings.HasSuffix(e.Name(), blobExt):
			blobs++
		case strings.Contains(e.Name(), ".tmp"):
			tmps++
		}
	}
	if blobs != 1 {
		t.Fatalf("want exactly one published blob, got %d", blobs)
	}
	if tmps != 0 {
		t.Fatalf("temp files leaked: %d", tmps)
	}
}

// TestUploadRejectsRootMismatch proves the store no longer persists a segment
// whose declared root disagrees with the checkpoint it carries: the meta commits
// to the zero root via its checkpoint, but Root is set to a different value, so
// ingest rejects it with InvalidArgument instead of storing an unverifiable
// claim that only a later verifier pass would catch (REQ-E-04).
func TestUploadRejectsRootMismatch(t *testing.T) {
	client := dialStore(t, newTestStore(t))
	meta := sampleMeta(t)
	meta.Root = bytes.Repeat([]byte{0x11}, 32) // checkpoint still commits to the zero root
	// Meta-level rejection: send no frames so the client does not race the
	// server closing the stream.
	if _, err := upload(t, client, meta, nil); status.Code(err) != codes.InvalidArgument {
		t.Fatalf("root/checkpoint mismatch: got code %v (err %v), want InvalidArgument", status.Code(err), err)
	}
}

// TestUploadRejectsCheckpointSizeMismatch rejects a segment whose declared
// seq_last disagrees with the tree size committed in its checkpoint.
func TestUploadRejectsCheckpointSizeMismatch(t *testing.T) {
	client := dialStore(t, newTestStore(t))
	meta := sampleMeta(t)
	meta.SeqLast = 3 // checkpoint commits to size 2
	if _, err := upload(t, client, meta, nil); status.Code(err) != codes.InvalidArgument {
		t.Fatalf("checkpoint size mismatch: got code %v (err %v), want InvalidArgument", status.Code(err), err)
	}
}

// TestUploadRejectsSeqRangeMismatch rejects a stream whose frames do not cover
// the declared [seq_first,seq_last] range: the meta declares [1,2] but only a
// single seq-1 frame arrives. It uses a raw stream (ignoring send errors) because
// this is a frame-level rejection the server may close early.
func TestUploadRejectsSeqRangeMismatch(t *testing.T) {
	client := dialStore(t, newTestStore(t))
	stream, err := client.UploadSegment(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	_ = stream.Send(&api.UploadRequest{Kind: &api.UploadRequestMeta{Meta: sampleMeta(t)}})
	_ = stream.Send(&api.UploadRequest{Kind: &api.UploadRequestFrame{Frame: makeFrame(t, 1)}})
	if _, err := stream.CloseAndRecv(); status.Code(err) != codes.InvalidArgument {
		t.Fatalf("short seq range: got code %v (err %v), want InvalidArgument", status.Code(err), err)
	}
}

func TestUploadRejectsInvalidMeta(t *testing.T) {
	client := dialStore(t, newTestStore(t))
	cases := []struct {
		name   string
		mutate func(*api.SegmentMeta)
	}{
		{"empty source", func(m *api.SegmentMeta) { m.SourceId = "" }},
		{"zero seq first", func(m *api.SegmentMeta) { m.SeqFirst = 0 }},
		{"seq first > seq last", func(m *api.SegmentMeta) { m.SeqFirst, m.SeqLast = 5, 2 }},
		{"short root", func(m *api.SegmentMeta) { m.Root = make([]byte, 8) }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			meta := sampleMeta(t)
			tc.mutate(meta)
			_, err := upload(t, client, meta, nil)
			if status.Code(err) != codes.InvalidArgument {
				t.Fatalf("%s: got code %v (err %v), want InvalidArgument", tc.name, status.Code(err), err)
			}
		})
	}
}
