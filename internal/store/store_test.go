package store

import (
	"context"
	"crypto/ed25519"
	"io"
	"net"
	"path/filepath"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/test/bufconn"

	"github.com/arhuman/prooflog/internal/api"
	"github.com/arhuman/prooflog/internal/envelope"
	"github.com/arhuman/prooflog/internal/note"
)

// testSigningKey is a deterministic Ed25519 key for store tests. The store binds
// a segment's declared root to its checkpoint but never verifies the signature,
// so any well-formed signed note over the matching (size, root) suffices.
var testSigningKey = ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))

// signedCheckpoint returns a signed C2SP note committing to (size, root), the
// form the agent uploads as SegmentMeta.Checkpoint.
func signedCheckpoint(t *testing.T, size uint64, root [32]byte) string {
	t.Helper()
	cp := note.Checkpoint{Origin: "prooflog/acme/vps-01/api", Size: size, Hash: root}
	signed, err := note.Sign(cp.Marshal(), "vps-01-api", testSigningKey)
	if err != nil {
		t.Fatal(err)
	}
	return signed
}

// metaWithRoot returns sampleMeta committed to a specific root (its checkpoint
// updated to match), for tests that need a distinct root to force a dedup miss
// without tripping the root/checkpoint binding.
func metaWithRoot(t *testing.T, root [32]byte) *api.SegmentMeta {
	t.Helper()
	m := sampleMeta(t)
	m.Root = root[:]
	m.Checkpoint = signedCheckpoint(t, m.SeqLast, root)
	return m
}

func newTestStore(t *testing.T) *Store {
	t.Helper()
	dir := t.TempDir()
	s, err := Open(Config{DBPath: filepath.Join(dir, "index.db"), BlobDir: filepath.Join(dir, "blobs")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

// dialStore serves s over an in-memory bufconn and returns a client.
func dialStore(t *testing.T, s *Store) api.StoreServiceClient {
	t.Helper()
	lis := bufconn.Listen(1 << 20)
	srv := grpc.NewServer()
	api.RegisterStore(srv, s)
	go func() { _ = srv.Serve(lis) }()
	t.Cleanup(srv.Stop)

	cc, err := grpc.NewClient("passthrough:///bufnet",
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) {
			return lis.DialContext(ctx)
		}),
		grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cc.Close() })
	return api.NewStoreClient(cc)
}

func makeFrame(t *testing.T, seq uint64) *api.Frame {
	t.Helper()
	ts := envelope.FormatTime(time.Unix(int64(seq), 0))
	rec := envelope.Record{
		Version: envelope.Version, SourceID: "vps-01/api", Seq: seq,
		EventType: "system.heartbeat", EventTime: ts, IngestTime: ts,
		PayloadClear: []byte(`{}`), PrevHash: envelope.ZeroHash,
	}
	if err := rec.Serialize(); err != nil {
		t.Fatal(err)
	}
	h := rec.Hash()
	return &api.Frame{RecordBytes: rec.Bytes(), RecordHash: h[:]}
}

func upload(t *testing.T, client api.StoreServiceClient, meta *api.SegmentMeta, frames []*api.Frame) (*api.SegmentAck, error) {
	t.Helper()
	stream, err := client.UploadSegment(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if err := stream.Send(&api.UploadRequest{Kind: &api.UploadRequestMeta{Meta: meta}}); err != nil {
		t.Fatal(err)
	}
	for _, fr := range frames {
		if err := stream.Send(&api.UploadRequest{Kind: &api.UploadRequestFrame{Frame: fr}}); err != nil {
			t.Fatal(err)
		}
	}
	return stream.CloseAndRecv()
}

func sampleMeta(t *testing.T) *api.SegmentMeta {
	t.Helper()
	var root [32]byte // all-zero root, matched by the checkpoint below
	return &api.SegmentMeta{
		SegmentId:  "01890000-0000-7000-8000-000000000001",
		SourceId:   "vps-01/api",
		SeqFirst:   1,
		SeqLast:    2,
		Root:       root[:],
		Checkpoint: signedCheckpoint(t, 2, root),
	}
}

func TestUploadAndPull(t *testing.T) {
	client := dialStore(t, newTestStore(t))
	frames := []*api.Frame{makeFrame(t, 1), makeFrame(t, 2)}

	ack, err := upload(t, client, sampleMeta(t), frames)
	if err != nil {
		t.Fatalf("upload: %v", err)
	}
	if ack.Duplicate || ack.AckedSeq != 2 {
		t.Fatalf("ack = %+v, want acked_seq 2, not duplicate", ack)
	}

	stream, err := client.PullSegments(context.Background(), &api.PullRequest{SourceId: "vps-01/api", FromSeq: 1})
	if err != nil {
		t.Fatal(err)
	}
	var got int
	for {
		fr, err := stream.Recv()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		if len(fr.RecordBytes) == 0 || len(fr.RecordHash) != 32 {
			t.Fatalf("bad frame: %+v", fr)
		}
		got++
	}
	if got != 2 {
		t.Fatalf("pulled %d frames, want 2", got)
	}
}

func TestUploadDedup(t *testing.T) {
	client := dialStore(t, newTestStore(t))
	frames := []*api.Frame{makeFrame(t, 1), makeFrame(t, 2)}

	if _, err := upload(t, client, sampleMeta(t), frames); err != nil {
		t.Fatal(err)
	}
	ack, err := upload(t, client, sampleMeta(t), frames)
	if err != nil {
		t.Fatal(err)
	}
	if !ack.Duplicate {
		t.Fatal("second identical upload should be marked duplicate")
	}
}

func TestPullFromSeqFilters(t *testing.T) {
	client := dialStore(t, newTestStore(t))
	if _, err := upload(t, client, sampleMeta(t), []*api.Frame{makeFrame(t, 1), makeFrame(t, 2)}); err != nil {
		t.Fatal(err)
	}
	stream, err := client.PullSegments(context.Background(), &api.PullRequest{SourceId: "vps-01/api", FromSeq: 2})
	if err != nil {
		t.Fatal(err)
	}
	var seqs int
	for {
		_, err := stream.Recv()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		seqs++
	}
	if seqs != 1 {
		t.Fatalf("from_seq=2 should yield 1 frame, got %d", seqs)
	}
}

func TestUploadRejectsHashMismatch(t *testing.T) {
	client := dialStore(t, newTestStore(t))
	bad := makeFrame(t, 1)
	bad.RecordHash[0] ^= 0xff
	if _, err := upload(t, client, sampleMeta(t), []*api.Frame{bad}); err == nil {
		t.Fatal("upload with wrong frame hash should fail")
	}
}

func TestSubmitCheckpoint(t *testing.T) {
	client := dialStore(t, newTestStore(t))
	ack, err := client.SubmitCheckpoint(context.Background(), &api.SignedNote{
		Note:     "prooflog/acme/vps-01/api\n2\nAAA=\n\n— vps-01-api sig\n",
		SourceId: "vps-01/api", Origin: "prooflog/acme/vps-01/api",
	})
	if err != nil {
		t.Fatal(err)
	}
	if !ack.Accepted {
		t.Fatal("checkpoint should be accepted")
	}
}

func TestEnforceRetentionNoPolicy(t *testing.T) {
	s := newTestStore(t)
	tombstones, err := s.EnforceRetention(context.Background())
	if err != nil {
		t.Fatalf("retention with no policy should not error: %v", err)
	}
	if len(tombstones) != 0 {
		t.Fatalf("no-policy retention should delete nothing, got %d tombstones", len(tombstones))
	}
}
