package verifierd

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"path/filepath"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/test/bufconn"

	"github.com/arhuman/prooflog/internal/api"
	"github.com/arhuman/prooflog/internal/chain"
	"github.com/arhuman/prooflog/internal/envelope"
	"github.com/arhuman/prooflog/internal/evidence"
	"github.com/arhuman/prooflog/internal/note"
	"github.com/arhuman/prooflog/internal/segment"
	"github.com/arhuman/prooflog/internal/store"
	"github.com/arhuman/prooflog/internal/verifier"
)

const (
	keyName = "vps-01-api"
	origin  = "prooflog/acme/vps-01/api"
	srcID   = "vps-01/api"
)

// uploadKey signs the checkpoints attached to segments preloaded into a real
// store. The store binds a segment's root to its checkpoint but never verifies
// the signature, so a deterministic throwaway key suffices for the ingest path.
var uploadKey = ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))

// builder assembles a properly chained record stream and matching signed
// checkpoints for one source. It mirrors the builder in package verifier's
// tests; the two are independent because test helpers do not cross packages.
type builder struct {
	t        *testing.T
	prev     string
	seq      uint64
	now      time.Time
	batcher  *segment.Batcher
	entries  []chain.Entry
	checkpts []string
}

func newBuilder(t *testing.T, priv ed25519.PrivateKey) *builder {
	return &builder{
		t:       t,
		prev:    envelope.ZeroHash,
		now:     time.Date(2026, 7, 3, 0, 0, 0, 0, time.UTC),
		batcher: segment.New(origin, keyName, priv),
	}
}

func (b *builder) add(eventType string, clearPayload any) {
	b.t.Helper()
	b.seq++
	ts := envelope.FormatTime(b.now)
	rec := envelope.Record{
		Version:    envelope.Version,
		SourceID:   srcID,
		Seq:        b.seq,
		EventType:  eventType,
		EventTime:  ts,
		IngestTime: ts,
		PrevHash:   b.prev,
	}
	if clearPayload != nil {
		raw, err := json.Marshal(clearPayload)
		if err != nil {
			b.t.Fatal(err)
		}
		rec.PayloadClear = raw
	} else {
		rec.PayloadClear = []byte(`{}`)
	}
	if err := rec.Serialize(); err != nil {
		b.t.Fatal(err)
	}
	b.entries = append(b.entries, chain.Entry{Bytes: rec.Bytes(), Hash: rec.HashHex()})
	if err := b.batcher.Add(rec.Bytes(), rec.Seq, b.now); err != nil {
		b.t.Fatal(err)
	}
	b.prev = rec.HashHex()
}

func (b *builder) heartbeat(driftMS int64) {
	b.add(evHeartbeat, map[string]any{"health": map[string]any{"clock_drift_ms": driftMS}})
}

func (b *builder) tick(d time.Duration) { b.now = b.now.Add(d) }

func (b *builder) seal() {
	b.t.Helper()
	sealed, err := b.batcher.Seal(b.now)
	if err != nil {
		b.t.Fatal(err)
	}
	b.checkpts = append(b.checkpts, sealed.Checkpoint)
}

// System event types the builder emits, matching package verifier's constants.
const (
	evHeartbeat = "system.heartbeat"
	evOutage    = "system.network_outage"
	evReplay    = "system.replay_completed"
)

func testKeyring(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey, verifier.Keyring) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return pub, priv, verifier.Keyring{keyName: pub}
}

// newRegistry builds a one-source registry through the public loader so the test
// never reaches into verifier's unexported fields: it writes a keys.json with
// AppendKey and reads it back with LoadRegistry, exactly as the CLI does.
func newRegistry(t *testing.T, pub ed25519.PublicKey) *verifier.Registry {
	t.Helper()
	path := filepath.Join(t.TempDir(), "keys.json")
	if err := verifier.AppendKey(path, verifier.SourceKey{
		SourceID: srcID, Origin: origin, KeyName: keyName, PublicKey: pub,
	}); err != nil {
		t.Fatal(err)
	}
	reg, err := verifier.LoadRegistry(path)
	if err != nil {
		t.Fatal(err)
	}
	return reg
}

func newDaemon(t *testing.T, reg *verifier.Registry, storeClient api.StoreServiceClient) *Daemon {
	t.Helper()
	d, err := NewDaemon(DaemonConfig{Registry: reg, DataDir: t.TempDir(), Store: storeClient})
	if err != nil {
		t.Fatal(err)
	}
	return d
}

func signedCP(t *testing.T, priv ed25519.PrivateKey, size uint64, root [32]byte) string {
	t.Helper()
	cp := note.Checkpoint{Origin: origin, Size: size, Hash: root}
	s, err := note.Sign(cp.Marshal(), keyName, priv)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// checkpointRootFor parses a signed checkpoint note and returns its RFC 6962
// tree root, used to bind a tombstone to an accepted checkpoint.
func checkpointRootFor(t *testing.T, signed string, pub ed25519.PublicKey) [32]byte {
	t.Helper()
	text, err := note.Verify(signed, keyName, pub)
	if err != nil {
		t.Fatal(err)
	}
	cp, err := note.ParseCheckpoint(text)
	if err != nil {
		t.Fatal(err)
	}
	return cp.Hash
}

func hasFinding(fs []evidence.Finding, id string) bool {
	for _, f := range fs {
		if f.ID == id {
			return true
		}
	}
	return false
}

// segUpload is one segment's worth of frames to preload into a real store: its
// starting seq and the ordered entries that follow it.
type segUpload struct {
	seqFirst uint64
	entries  []chain.Entry
}

// bufconnStore serves a real store preloaded with one or more segments over
// bufconn and returns a client, so the daemon's PullSegments path runs against
// the production store implementation (REQ-E-05).
func bufconnStore(t *testing.T, segs ...segUpload) api.StoreServiceClient {
	t.Helper()
	dir := t.TempDir()
	st, err := store.Open(store.Config{DBPath: dir + "/i.db", BlobDir: dir + "/b"})
	if err != nil {
		t.Fatal(err)
	}
	lis := bufconn.Listen(1 << 20)
	srv := grpc.NewServer()
	api.RegisterStore(srv, st)
	go func() { _ = srv.Serve(lis) }()
	t.Cleanup(func() { srv.Stop(); _ = st.Close() })

	client := dialBufconn(t, lis)
	for i, sg := range segs {
		uploadSegment(t, client, i, sg)
	}
	return client
}

func uploadSegment(t *testing.T, client api.StoreServiceClient, index int, sg segUpload) {
	t.Helper()
	stream, err := client.UploadSegment(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	seqLast := sg.seqFirst + uint64(len(sg.entries)) - 1
	// The store binds a segment's declared root to its checkpoint at ingest, so
	// preloaded segments carry a signed checkpoint committing to (seqLast, root).
	// The daemon recomputes roots from the pulled frames against separately
	// submitted checkpoints, so this preload root is never read back — a
	// deterministic zero root with a matching checkpoint suffices.
	var root [32]byte
	cp := note.Checkpoint{Origin: origin, Size: seqLast, Hash: root}
	signed, err := note.Sign(cp.Marshal(), keyName, uploadKey)
	if err != nil {
		t.Fatal(err)
	}
	meta := &api.SegmentMeta{
		SegmentId:  fmt.Sprintf("01890000-0000-7000-8000-%012d", index+1),
		SourceId:   srcID,
		SeqFirst:   sg.seqFirst,
		SeqLast:    seqLast,
		Root:       root[:],
		Checkpoint: signed,
	}
	if err := stream.Send(&api.UploadRequest{Kind: &api.UploadRequestMeta{Meta: meta}}); err != nil {
		t.Fatal(err)
	}
	for _, fr := range framesOf(t, sg.entries) {
		if err := stream.Send(&api.UploadRequest{Kind: &api.UploadRequestFrame{Frame: fr}}); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := stream.CloseAndRecv(); err != nil {
		t.Fatal(err)
	}
}

// framesOf converts entries to wire frames.
func framesOf(t *testing.T, entries []chain.Entry) []*api.Frame {
	t.Helper()
	out := make([]*api.Frame, 0, len(entries))
	for _, e := range entries {
		hb, err := hex.DecodeString(e.Hash)
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, &api.Frame{RecordBytes: e.Bytes, RecordHash: hb})
	}
	return out
}

// fakeStore is a minimal StoreServiceServer that streams caller-supplied frames
// and tombstones. It drives the daemon's real streamInto/PullSegments/bufconn
// path for conditions the production store validates away on upload (a
// hash-mismatched frame) or cannot age into on demand (a retention tombstone).
type fakeStore struct {
	api.UnimplementedStoreServiceServer
	frames     []*api.Frame
	tombstones []*api.Tombstone
}

func (f *fakeStore) PullSegments(_ *api.PullRequest, stream api.StorePullStream) error {
	for _, fr := range f.frames {
		if err := stream.Send(fr); err != nil {
			return err
		}
	}
	return nil
}

func (f *fakeStore) ListTombstones(_ context.Context, _ *api.ListTombstonesRequest) (*api.ListTombstonesResponse, error) {
	return &api.ListTombstonesResponse{Tombstones: f.tombstones}, nil
}

// fakeStoreClient serves fs over bufconn and returns a client.
func fakeStoreClient(t *testing.T, fs *fakeStore) api.StoreServiceClient {
	t.Helper()
	lis := bufconn.Listen(1 << 20)
	srv := grpc.NewServer()
	api.RegisterStore(srv, fs)
	go func() { _ = srv.Serve(lis) }()
	t.Cleanup(func() { srv.Stop() })
	return dialBufconn(t, lis)
}

func dialBufconn(t *testing.T, lis *bufconn.Listener) api.StoreServiceClient {
	t.Helper()
	cc, err := grpc.NewClient("passthrough:///bufnet",
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) { return lis.DialContext(ctx) }),
		grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cc.Close() })
	return api.NewStoreClient(cc)
}
