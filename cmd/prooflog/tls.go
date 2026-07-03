package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/arhuman/prooflog/internal/api"
)

// tlsFlags registers the mTLS flag structure on fs and returns a config pointer
// populated after fs.Parse. TLS is the secure default; --insecure is an explicit
// opt-in for loopback/demo use only. The full flag structure exists so mTLS can
// be enabled without a code change (REQ-E-04).
func tlsFlags(fs *flag.FlagSet) *api.TLSConfig {
	cfg := &api.TLSConfig{}
	fs.BoolVar(&cfg.Insecure, "insecure", false, "run without TLS (explicit opt-in; loopback/demo only)")
	fs.StringVar(&cfg.CertFile, "tls-cert", "", "TLS certificate file")
	fs.StringVar(&cfg.KeyFile, "tls-key", "", "TLS private key file")
	fs.StringVar(&cfg.CAFile, "tls-ca", "", "CA bundle for peer verification")
	fs.StringVar(&cfg.ServerName, "tls-server-name", "", "expected server name (client)")
	fs.BoolVar(&cfg.ClientAuth, "tls-client-auth", false, "require client certificates (mTLS)")
	return cfg
}

// warnInsecure prints a single prominent stderr line when a component proceeds
// without TLS, so plaintext transport is never silent (REQ-E-04).
func warnInsecure(component string) {
	fmt.Fprintf(os.Stderr, "WARNING: %s: running without TLS; all gRPC traffic is plaintext (--insecure)\n", component)
}
