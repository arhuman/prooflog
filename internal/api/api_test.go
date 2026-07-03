package api

import (
	"testing"
)

func TestServerCreds(t *testing.T) {
	tests := []struct {
		name    string
		cfg     TLSConfig
		wantNil bool
		wantErr bool
	}{
		{"insecure", TLSConfig{Insecure: true}, true, false},
		{"missing cert", TLSConfig{}, false, true},
		{"bad cert path", TLSConfig{CertFile: "/no/such", KeyFile: "/no/such"}, false, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			creds, err := tt.cfg.ServerCreds()
			if tt.wantErr != (err != nil) {
				t.Fatalf("err = %v, wantErr %v", err, tt.wantErr)
			}
			if err == nil && tt.wantNil != (creds == nil) {
				t.Fatalf("creds nil = %v, want %v", creds == nil, tt.wantNil)
			}
		})
	}
}

func TestNewServer(t *testing.T) {
	srv, err := NewServer(TLSConfig{Insecure: true})
	if err != nil || srv == nil {
		t.Fatalf("insecure server: srv=%v err=%v", srv, err)
	}
	srv.Stop()

	if _, err := NewServer(TLSConfig{}); err == nil {
		t.Fatal("secure server without cert should error")
	}
}

func TestDialInsecure(t *testing.T) {
	cc, err := Dial("passthrough:///x", TLSConfig{Insecure: true})
	if err != nil {
		t.Fatal(err)
	}
	defer cc.Close()
	if NewStoreClient(cc) == nil || NewVerifierClient(cc) == nil {
		t.Fatal("clients should be constructible from a connection")
	}
}

func TestDialBadCA(t *testing.T) {
	if _, err := Dial("passthrough:///x", TLSConfig{CAFile: "/no/such/ca.pem"}); err == nil {
		t.Fatal("dial with unreadable CA should fail")
	}
}
