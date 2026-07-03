package api

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// genTestCert generates a self-signed ECDSA P-256 TLS certificate and writes
// it plus its private key as PEM files to dir. The cert is also a CA, so it
// can double as the CAFile for mTLS tests.
func genTestCert(t *testing.T, dir string) (certFile, keyFile string) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "prooflog-test"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatal(err)
	}
	certFile = filepath.Join(dir, "cert.pem")
	keyFile = filepath.Join(dir, "key.pem")

	if err := os.WriteFile(certFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER}), 0o600); err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}), 0o600); err != nil {
		t.Fatal(err)
	}
	return certFile, keyFile
}

// TestClientCreds exercises the unexported clientCreds helper across all branches.
func TestClientCreds(t *testing.T) {
	dir := t.TempDir()
	certFile, keyFile := genTestCert(t, dir)

	// Invalid PEM file (not a cert) to trigger "no certificates in" error.
	badPEM := filepath.Join(dir, "bad.pem")
	if err := os.WriteFile(badPEM, []byte("not-a-pem-certificate"), 0o600); err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name    string
		cfg     TLSConfig
		wantErr bool
	}{
		{"insecure", TLSConfig{Insecure: true}, false},
		{"tls default (no CA, no cert)", TLSConfig{}, false},
		{"with valid CA only", TLSConfig{CAFile: certFile}, false},
		{"with valid cert+key+CA", TLSConfig{CertFile: certFile, KeyFile: keyFile, CAFile: certFile}, false},
		{"bad CA file (missing)", TLSConfig{CAFile: "/no/such/ca.pem"}, true},
		{"bad CA file (invalid PEM)", TLSConfig{CAFile: badPEM}, true},
		{"bad client cert files", TLSConfig{CertFile: "/no/such/cert.pem", KeyFile: "/no/such/key.pem"}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			creds, err := tt.cfg.clientCreds()
			if tt.wantErr {
				if err == nil {
					t.Fatalf("clientCreds(%+v): want error, got nil", tt.cfg)
				}
				return
			}
			if err != nil {
				t.Fatalf("clientCreds(%+v): unexpected error: %v", tt.cfg, err)
			}
			if creds == nil {
				t.Fatalf("clientCreds(%+v): want non-nil credentials", tt.cfg)
			}
		})
	}
}

// TestServerCredsClientAuth covers ServerCreds with ClientAuth enabled.
func TestServerCredsClientAuth(t *testing.T) {
	dir := t.TempDir()
	certFile, keyFile := genTestCert(t, dir)

	// Valid cert+key with ClientAuth and the cert itself as CA → success.
	cfg := TLSConfig{
		CertFile:   certFile,
		KeyFile:    keyFile,
		CAFile:     certFile, // self-signed, so cert == CA
		ClientAuth: true,
	}
	creds, err := cfg.ServerCreds()
	if err != nil {
		t.Fatalf("ServerCreds with ClientAuth: %v", err)
	}
	if creds == nil {
		t.Fatal("expected non-nil credentials")
	}

	// ClientAuth with missing CAFile → error from loadCertPool.
	cfg2 := TLSConfig{CertFile: certFile, KeyFile: keyFile, ClientAuth: true}
	if _, err := cfg2.ServerCreds(); err == nil {
		t.Fatal("ServerCreds with ClientAuth but no CAFile should fail")
	}
}

// TestLoadCertPool exercises all branches of the unexported loadCertPool helper.
func TestLoadCertPool(t *testing.T) {
	dir := t.TempDir()
	certFile, _ := genTestCert(t, dir)

	// Valid PEM file → success.
	pool, err := loadCertPool(certFile)
	if err != nil || pool == nil {
		t.Fatalf("loadCertPool valid cert: err=%v pool=%v", err, pool)
	}

	// Empty path → error ("CA file required but empty").
	if _, err := loadCertPool(""); err == nil {
		t.Fatal("loadCertPool empty path: want error, got nil")
	}

	// Non-existent file → read error.
	if _, err := loadCertPool("/no/such/ca.pem"); err == nil {
		t.Fatal("loadCertPool missing file: want error, got nil")
	}

	// File with no PEM block → "no certificates in" error.
	badPEM := filepath.Join(dir, "bad.pem")
	if err := os.WriteFile(badPEM, []byte("this is not a PEM certificate"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadCertPool(badPEM); err == nil {
		t.Fatal("loadCertPool invalid PEM: want error, got nil")
	}
}

// TestRegisterStoreAndVerifier covers RegisterStore and RegisterVerifier (both 0%).
// These are thin wrappers around protobuf-generated registration functions.
func TestRegisterStoreAndVerifier(t *testing.T) {
	srv, err := NewServer(TLSConfig{Insecure: true})
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Stop()

	type dummyStore struct {
		UnimplementedStoreServiceServer
	}
	type dummyVerifier struct {
		UnimplementedVerifierServiceServer
	}

	// Calling these reaches the currently 0% branches.
	RegisterStore(srv, &dummyStore{})
	RegisterVerifier(srv, &dummyVerifier{})
}

// TestDialBadClientCert covers the clientCreds error path inside Dial.
func TestDialBadClientCert(t *testing.T) {
	cfg := TLSConfig{CertFile: "/no/such/cert.pem", KeyFile: "/no/such/key.pem"}
	if _, err := Dial("passthrough:///x", cfg); err == nil {
		t.Fatal("Dial with bad client cert should fail")
	}
}
