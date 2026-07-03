// Package api wraps the generated protobuf types with shared gRPC plumbing:
// TLS/mTLS credential construction, dial helpers, and server builders. It is
// the only place transport concerns live; services depend on it, nothing below
// does (REQ-E-04).
package api

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"

	prooflogv1 "github.com/arhuman/prooflog/proto/prooflog/v1"
)

// Re-export the generated client/server surface so callers depend only on api.
type (
	// StoreServiceClient talks to the central store.
	StoreServiceClient = prooflogv1.StoreServiceClient
	// StoreServiceServer is implemented by the store.
	StoreServiceServer = prooflogv1.StoreServiceServer
	// VerifierServiceClient talks to the verifier.
	VerifierServiceClient = prooflogv1.VerifierServiceClient
	// VerifierServiceServer is implemented by the verifier.
	VerifierServiceServer = prooflogv1.VerifierServiceServer

	// Frame is one uploaded/stored record with its hash.
	Frame = prooflogv1.Frame
	// SegmentMeta is the header of an UploadSegment stream.
	SegmentMeta = prooflogv1.SegmentMeta
	// UploadRequest is one message of the UploadSegment stream.
	UploadRequest = prooflogv1.UploadRequest
	// SegmentAck confirms durable persistence of a segment.
	SegmentAck = prooflogv1.SegmentAck
	// PullRequest asks the store for a source's frames from a seq.
	PullRequest = prooflogv1.PullRequest
	// SignedNote wraps a C2SP signed note for submission.
	SignedNote = prooflogv1.SignedNote
	// CheckpointAck acknowledges a checkpoint.
	CheckpointAck = prooflogv1.CheckpointAck

	// Hold is a legal hold exempting a source (or range) from deletion.
	Hold = prooflogv1.Hold
	// PlaceHoldRequest places a legal hold.
	PlaceHoldRequest = prooflogv1.PlaceHoldRequest
	// ReleaseHoldRequest releases a legal hold.
	ReleaseHoldRequest = prooflogv1.ReleaseHoldRequest
	// ListHoldsRequest lists legal holds.
	ListHoldsRequest = prooflogv1.ListHoldsRequest
	// ListHoldsResponse carries matching holds.
	ListHoldsResponse = prooflogv1.ListHoldsResponse
	// Tombstone is the permanent record of a retention-deleted segment.
	Tombstone = prooflogv1.Tombstone
	// ListTombstonesRequest lists tombstones.
	ListTombstonesRequest = prooflogv1.ListTombstonesRequest
	// ListTombstonesResponse carries matching tombstones.
	ListTombstonesResponse = prooflogv1.ListTombstonesResponse
)

// Aliases for the oneof wrappers and unimplemented embeds used by services.
type (
	// UploadRequestMeta wraps a SegmentMeta in an UploadRequest.
	UploadRequestMeta = prooflogv1.UploadRequest_Meta
	// UploadRequestFrame wraps a Frame in an UploadRequest.
	UploadRequestFrame = prooflogv1.UploadRequest_Frame
	// UnimplementedStoreServiceServer is embedded by the store for forward compat.
	UnimplementedStoreServiceServer = prooflogv1.UnimplementedStoreServiceServer
	// UnimplementedVerifierServiceServer is embedded by the verifier.
	UnimplementedVerifierServiceServer = prooflogv1.UnimplementedVerifierServiceServer
	// StoreUploadStream is the server side of the UploadSegment stream.
	StoreUploadStream = prooflogv1.StoreService_UploadSegmentServer
	// StorePullStream is the server side of the PullSegments stream.
	StorePullStream = prooflogv1.StoreService_PullSegmentsServer
)

// TLSConfig configures transport security. In v1 mTLS is optional: when
// Insecure is set the transport runs without TLS (demo/loopback). The field
// structure for cert, key, CA, and client auth exists so mTLS can be turned on
// without an API change (REQ-E-04).
type TLSConfig struct {
	Insecure   bool   `json:"insecure"`
	CertFile   string `json:"cert_file"`
	KeyFile    string `json:"key_file"`
	CAFile     string `json:"ca_file"`
	ServerName string `json:"server_name"`
	// ClientAuth requires clients to present a certificate (mTLS) on servers.
	ClientAuth bool `json:"client_auth"`
}

// clientCreds builds dial transport credentials from cfg.
func (cfg TLSConfig) clientCreds() (credentials.TransportCredentials, error) {
	if cfg.Insecure {
		return insecure.NewCredentials(), nil
	}
	tc := &tls.Config{ServerName: cfg.ServerName, MinVersion: tls.VersionTLS13}
	if cfg.CAFile != "" {
		pool, err := loadCertPool(cfg.CAFile)
		if err != nil {
			return nil, err
		}
		tc.RootCAs = pool
	}
	if cfg.CertFile != "" && cfg.KeyFile != "" {
		cert, err := tls.LoadX509KeyPair(cfg.CertFile, cfg.KeyFile)
		if err != nil {
			return nil, fmt.Errorf("api: load client cert: %w", err)
		}
		tc.Certificates = []tls.Certificate{cert}
	}
	return credentials.NewTLS(tc), nil
}

// ServerCreds builds server transport credentials from cfg. It returns nil
// (insecure server) when cfg.Insecure is set.
func (cfg TLSConfig) ServerCreds() (credentials.TransportCredentials, error) {
	if cfg.Insecure {
		return nil, nil
	}
	if cfg.CertFile == "" || cfg.KeyFile == "" {
		return nil, fmt.Errorf("api: server TLS requires cert_file and key_file")
	}
	cert, err := tls.LoadX509KeyPair(cfg.CertFile, cfg.KeyFile)
	if err != nil {
		return nil, fmt.Errorf("api: load server cert: %w", err)
	}
	tc := &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS13}
	if cfg.ClientAuth {
		pool, err := loadCertPool(cfg.CAFile)
		if err != nil {
			return nil, err
		}
		tc.ClientCAs = pool
		tc.ClientAuth = tls.RequireAndVerifyClientCert
	}
	return credentials.NewTLS(tc), nil
}

func loadCertPool(path string) (*x509.CertPool, error) {
	if path == "" {
		return nil, fmt.Errorf("api: CA file required but empty")
	}
	pem, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("api: read CA: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		return nil, fmt.Errorf("api: no certificates in %s", path)
	}
	return pool, nil
}

// maxMsgBytes caps gRPC messages explicitly rather than relying on the 4 MiB
// library default: frames are capped at 16 MiB by store and spool, and the
// margin covers proto envelope overhead.
const maxMsgBytes = 20 << 20

// NewServer builds a gRPC server with cfg's transport security. Additional opts
// are appended after the message-size caps and credentials, letting callers add
// interceptors (e.g. RequireMTLS) without this package knowing service policy.
func NewServer(cfg TLSConfig, opts ...grpc.ServerOption) (*grpc.Server, error) {
	creds, err := cfg.ServerCreds()
	if err != nil {
		return nil, err
	}
	serverOpts := []grpc.ServerOption{
		grpc.MaxRecvMsgSize(maxMsgBytes),
		grpc.MaxSendMsgSize(maxMsgBytes),
	}
	if creds != nil {
		serverOpts = append(serverOpts, grpc.Creds(creds))
	}
	serverOpts = append(serverOpts, opts...)
	return grpc.NewServer(serverOpts...), nil
}

// Privileged reports whether fullMethod names an RPC that must be gated on mTLS
// client authentication. A service supplies its own predicate (see
// StorePrivileged) so this package holds no per-service policy (REQ-E-04).
type Privileged func(fullMethod string) bool

// RequireMTLS returns the server options that gate every privileged RPC (as
// decided by priv) on mTLS client authentication. A unary interceptor alone
// cannot cover client- or server-streaming methods (UploadSegment,
// PullSegments), so both a unary and a stream gate are installed. Both gates
// share the same rule: a privileged method with no verified client certificate
// chain is denied unless allowUnauthenticated is set for demo/loopback use. The
// trust boundary is the verified client certificate chain, nothing below the
// transport (REQ-E-04).
func RequireMTLS(allowUnauthenticated bool, priv Privileged) []grpc.ServerOption {
	return []grpc.ServerOption{
		grpc.ChainUnaryInterceptor(unaryGate(allowUnauthenticated, priv)),
		grpc.ChainStreamInterceptor(streamGate(allowUnauthenticated, priv)),
	}
}

// unaryGate builds the unary half of RequireMTLS. It is unexported so tests can
// drive it directly without standing up a server.
func unaryGate(allowUnauthenticated bool, priv Privileged) grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
		if err := gate(ctx, info.FullMethod, allowUnauthenticated, priv); err != nil {
			return nil, err
		}
		return handler(ctx, req)
	}
}

// streamGate builds the streaming half of RequireMTLS. It reads the peer from
// the stream's context and, when permitted, delegates to the wrapped handler.
func streamGate(allowUnauthenticated bool, priv Privileged) grpc.StreamServerInterceptor {
	return func(srv any, ss grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
		if err := gate(ss.Context(), info.FullMethod, allowUnauthenticated, priv); err != nil {
			return err
		}
		return handler(srv, ss)
	}
}

// gate is the shared authorization check for both the unary and stream halves
// of RequireMTLS.
func gate(ctx context.Context, fullMethod string, allowUnauthenticated bool, priv Privileged) error {
	if priv(fullMethod) && !allowUnauthenticated && !mTLSVerified(ctx) {
		return status.Error(codes.PermissionDenied,
			"privileged RPC "+fullMethod+" requires an mTLS-verified client; enable --tls-client-auth (require client cert) on the store or pass --allow-unauthenticated for local demos")
	}
	return nil
}

// StorePrivileged reports whether fullMethod is a privileged StoreService RPC.
//
// POLICY: only mutations are privileged. UploadSegment and SubmitCheckpoint
// write evidence into the chain, and PlaceHold/ReleaseHold override retention;
// all four are gated. PullSegments, ListHolds, and ListTombstones are reads and
// stay open — the offline verifier depends on pulling segments without a client
// certificate, and gating reads is a deployment policy left for later.
func StorePrivileged(fullMethod string) bool {
	switch fullMethod {
	case prooflogv1.StoreService_UploadSegment_FullMethodName,
		prooflogv1.StoreService_SubmitCheckpoint_FullMethodName,
		prooflogv1.StoreService_PlaceHold_FullMethodName,
		prooflogv1.StoreService_ReleaseHold_FullMethodName:
		return true
	default:
		return false
	}
}

// StoreReadPrivileged reports whether fullMethod is a StoreService read RPC that
// an operator may opt to gate on mTLS client authentication.
//
// POLICY: PullSegments streams the stored evidence corpus, and ListHolds and
// ListTombstones expose hold/retention metadata; on a network-reachable store
// any peer could otherwise exfiltrate all three. Read gating is opt-in (see the
// store's --require-read-auth) because the offline verifier depends on pulling
// segments without a client certificate, so the default posture keeps reads
// open. Compose this with StorePrivileged to gate reads on top of the always-on
// mutation gating (REQ-E-04).
func StoreReadPrivileged(fullMethod string) bool {
	switch fullMethod {
	case prooflogv1.StoreService_PullSegments_FullMethodName,
		prooflogv1.StoreService_ListHolds_FullMethodName,
		prooflogv1.StoreService_ListTombstones_FullMethodName:
		return true
	default:
		return false
	}
}

// mTLSVerified reports whether ctx's peer presented a certificate that the
// server verified against its client CA (a non-empty verified chain).
func mTLSVerified(ctx context.Context) bool {
	p, ok := peer.FromContext(ctx)
	if !ok {
		return false
	}
	tlsInfo, ok := p.AuthInfo.(credentials.TLSInfo)
	if !ok {
		return false
	}
	return len(tlsInfo.State.VerifiedChains) > 0
}

// RegisterStore registers a store implementation on s.
func RegisterStore(s *grpc.Server, srv StoreServiceServer) {
	prooflogv1.RegisterStoreServiceServer(s, srv)
}

// RegisterVerifier registers a verifier implementation on s.
func RegisterVerifier(s *grpc.Server, srv VerifierServiceServer) {
	prooflogv1.RegisterVerifierServiceServer(s, srv)
}

// Dial opens a lazily-connecting, auto-reconnecting client connection to addr
// with cfg's transport security. The connection is reused across retries so an
// outage recovers without redialing (REQ-E-04).
func Dial(addr string, cfg TLSConfig) (*grpc.ClientConn, error) {
	creds, err := cfg.clientCreds()
	if err != nil {
		return nil, err
	}
	cc, err := grpc.NewClient(addr,
		grpc.WithTransportCredentials(creds),
		grpc.WithDefaultCallOptions(
			grpc.MaxCallRecvMsgSize(maxMsgBytes),
			grpc.MaxCallSendMsgSize(maxMsgBytes),
		),
	)
	if err != nil {
		return nil, fmt.Errorf("api: dial %s: %w", addr, err)
	}
	return cc, nil
}

// NewStoreClient wraps a connection in a StoreServiceClient.
func NewStoreClient(cc *grpc.ClientConn) StoreServiceClient {
	return prooflogv1.NewStoreServiceClient(cc)
}

// NewVerifierClient wraps a connection in a VerifierServiceClient.
func NewVerifierClient(cc *grpc.ClientConn) VerifierServiceClient {
	return prooflogv1.NewVerifierServiceClient(cc)
}
