package api

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"

	prooflogv1 "github.com/arhuman/prooflog/proto/prooflog/v1"
)

// verifiedTLSContext returns a context whose peer carries a TLS auth info with
// a non-empty verified chain (an mTLS-authenticated client).
func verifiedTLSContext() context.Context {
	return peer.NewContext(context.Background(), &peer.Peer{
		AuthInfo: credentials.TLSInfo{State: tls.ConnectionState{
			VerifiedChains: [][]*x509.Certificate{{{}}},
		}},
	})
}

// serverTLSContext returns a context whose peer carries a TLS auth info with no
// verified chains (server-authenticated TLS, but no client certificate).
func serverTLSContext() context.Context {
	return peer.NewContext(context.Background(), &peer.Peer{
		AuthInfo: credentials.TLSInfo{State: tls.ConnectionState{}},
	})
}

// fakeServerStream is a minimal grpc.ServerStream carrying a fixed context; the
// stream gate only reads Context(), so the embedded nil interface is never used.
type fakeServerStream struct {
	grpc.ServerStream
	ctx context.Context
}

func (s fakeServerStream) Context() context.Context { return s.ctx }

// readGated gates both mutations and reads, mirroring the predicate the store
// installs under --require-read-auth.
func readGated(m string) bool { return StorePrivileged(m) || StoreReadPrivileged(m) }

func TestUnaryGate(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		method     string
		priv       Privileged
		ctx        context.Context
		allow      bool
		wantCalled bool
		wantCode   codes.Code
	}{
		{
			name:       "place hold no peer denied",
			method:     prooflogv1.StoreService_PlaceHold_FullMethodName,
			priv:       StorePrivileged,
			ctx:        context.Background(),
			allow:      false,
			wantCalled: false,
			wantCode:   codes.PermissionDenied,
		},
		{
			name:       "release hold server-tls without client cert denied",
			method:     prooflogv1.StoreService_ReleaseHold_FullMethodName,
			priv:       StorePrivileged,
			ctx:        serverTLSContext(),
			allow:      false,
			wantCalled: false,
			wantCode:   codes.PermissionDenied,
		},
		{
			name:       "place hold with verified client cert allowed",
			method:     prooflogv1.StoreService_PlaceHold_FullMethodName,
			priv:       StorePrivileged,
			ctx:        verifiedTLSContext(),
			allow:      false,
			wantCalled: true,
			wantCode:   codes.OK,
		},
		{
			name:       "place hold no peer allowed when unauthenticated permitted",
			method:     prooflogv1.StoreService_PlaceHold_FullMethodName,
			priv:       StorePrivileged,
			ctx:        context.Background(),
			allow:      true,
			wantCalled: true,
			wantCode:   codes.OK,
		},
		{
			name:       "list holds passes through when reads are not gated",
			method:     prooflogv1.StoreService_ListHolds_FullMethodName,
			priv:       StorePrivileged,
			ctx:        context.Background(),
			allow:      false,
			wantCalled: true,
			wantCode:   codes.OK,
		},
		{
			name:       "list holds no peer denied when reads are gated",
			method:     prooflogv1.StoreService_ListHolds_FullMethodName,
			priv:       readGated,
			ctx:        context.Background(),
			allow:      false,
			wantCalled: false,
			wantCode:   codes.PermissionDenied,
		},
		{
			name:       "list holds allowed when read-gated but unauthenticated permitted",
			method:     prooflogv1.StoreService_ListHolds_FullMethodName,
			priv:       readGated,
			ctx:        context.Background(),
			allow:      true,
			wantCalled: true,
			wantCode:   codes.OK,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			gate := unaryGate(tt.allow, tt.priv)
			called := false
			handler := func(_ context.Context, _ any) (any, error) {
				called = true
				return "ok", nil
			}
			info := &grpc.UnaryServerInfo{FullMethod: tt.method}

			resp, err := gate(tt.ctx, nil, info, handler)

			if called != tt.wantCalled {
				t.Fatalf("handler called = %v, want %v", called, tt.wantCalled)
			}
			if got := status.Code(err); got != tt.wantCode {
				t.Fatalf("status code = %v, want %v (err=%v)", got, tt.wantCode, err)
			}
			if tt.wantCalled && resp != "ok" {
				t.Fatalf("resp = %v, want handler result", resp)
			}
		})
	}
}

func TestStreamGate(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		method     string
		priv       Privileged
		ctx        context.Context
		allow      bool
		wantCalled bool
		wantCode   codes.Code
	}{
		{
			name:       "upload segment no peer denied",
			method:     prooflogv1.StoreService_UploadSegment_FullMethodName,
			priv:       StorePrivileged,
			ctx:        context.Background(),
			allow:      false,
			wantCalled: false,
			wantCode:   codes.PermissionDenied,
		},
		{
			name:       "upload segment server-tls without client cert denied",
			method:     prooflogv1.StoreService_UploadSegment_FullMethodName,
			priv:       StorePrivileged,
			ctx:        serverTLSContext(),
			allow:      false,
			wantCalled: false,
			wantCode:   codes.PermissionDenied,
		},
		{
			name:       "upload segment with verified client cert allowed",
			method:     prooflogv1.StoreService_UploadSegment_FullMethodName,
			priv:       StorePrivileged,
			ctx:        verifiedTLSContext(),
			allow:      false,
			wantCalled: true,
			wantCode:   codes.OK,
		},
		{
			name:       "upload segment no peer allowed when unauthenticated permitted",
			method:     prooflogv1.StoreService_UploadSegment_FullMethodName,
			priv:       StorePrivileged,
			ctx:        context.Background(),
			allow:      true,
			wantCalled: true,
			wantCode:   codes.OK,
		},
		{
			name:       "pull segments passes through when reads are not gated",
			method:     prooflogv1.StoreService_PullSegments_FullMethodName,
			priv:       StorePrivileged,
			ctx:        context.Background(),
			allow:      false,
			wantCalled: true,
			wantCode:   codes.OK,
		},
		{
			name:       "pull segments no peer denied when reads are gated",
			method:     prooflogv1.StoreService_PullSegments_FullMethodName,
			priv:       readGated,
			ctx:        context.Background(),
			allow:      false,
			wantCalled: false,
			wantCode:   codes.PermissionDenied,
		},
		{
			name:       "pull segments allowed when read-gated but unauthenticated permitted",
			method:     prooflogv1.StoreService_PullSegments_FullMethodName,
			priv:       readGated,
			ctx:        context.Background(),
			allow:      true,
			wantCalled: true,
			wantCode:   codes.OK,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			gate := streamGate(tt.allow, tt.priv)
			called := false
			handler := func(_ any, _ grpc.ServerStream) error {
				called = true
				return nil
			}
			info := &grpc.StreamServerInfo{FullMethod: tt.method}
			ss := fakeServerStream{ctx: tt.ctx}

			err := gate(nil, ss, info, handler)

			if called != tt.wantCalled {
				t.Fatalf("handler called = %v, want %v", called, tt.wantCalled)
			}
			if got := status.Code(err); got != tt.wantCode {
				t.Fatalf("status code = %v, want %v (err=%v)", got, tt.wantCode, err)
			}
		})
	}
}

func TestStorePrivileged(t *testing.T) {
	t.Parallel()

	tests := []struct {
		method string
		want   bool
	}{
		{prooflogv1.StoreService_UploadSegment_FullMethodName, true},
		{prooflogv1.StoreService_SubmitCheckpoint_FullMethodName, true},
		{prooflogv1.StoreService_PlaceHold_FullMethodName, true},
		{prooflogv1.StoreService_ReleaseHold_FullMethodName, true},
		{prooflogv1.StoreService_PullSegments_FullMethodName, false},
		{prooflogv1.StoreService_ListHolds_FullMethodName, false},
		{prooflogv1.StoreService_ListTombstones_FullMethodName, false},
	}

	for _, tt := range tests {
		t.Run(tt.method, func(t *testing.T) {
			t.Parallel()
			if got := StorePrivileged(tt.method); got != tt.want {
				t.Fatalf("StorePrivileged(%q) = %v, want %v", tt.method, got, tt.want)
			}
		})
	}
}

func TestStoreReadPrivileged(t *testing.T) {
	t.Parallel()

	tests := []struct {
		method string
		want   bool
	}{
		{prooflogv1.StoreService_PullSegments_FullMethodName, true},
		{prooflogv1.StoreService_ListHolds_FullMethodName, true},
		{prooflogv1.StoreService_ListTombstones_FullMethodName, true},
		{prooflogv1.StoreService_UploadSegment_FullMethodName, false},
		{prooflogv1.StoreService_SubmitCheckpoint_FullMethodName, false},
		{prooflogv1.StoreService_PlaceHold_FullMethodName, false},
		{prooflogv1.StoreService_ReleaseHold_FullMethodName, false},
	}

	for _, tt := range tests {
		t.Run(tt.method, func(t *testing.T) {
			t.Parallel()
			if got := StoreReadPrivileged(tt.method); got != tt.want {
				t.Fatalf("StoreReadPrivileged(%q) = %v, want %v", tt.method, got, tt.want)
			}
		})
	}
}
