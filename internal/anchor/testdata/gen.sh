#!/usr/bin/env bash
# gen.sh — regenerate the RFC 3161 TSA test fixtures with OpenSSL.
#
# Produces, in this directory:
#   note.bin      the exact bytes that are timestamped (the "signed note")
#   response.der  a real DER TimeStampResp (granted) from a local test TSA
#
# The test (tsa_test.go) reads the nonce and genTime back out of response.der,
# so regenerating here does not require editing any Go constant. Requires an
# OpenSSL with the `ts` subcommand (tested with OpenSSL 3.6).
set -euo pipefail
cd "$(dirname "$0")"

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

cat > "$work/tsa.cnf" <<'EOF'
[ req ]
distinguished_name = dn
prompt = no
x509_extensions = tsa_ext
[ dn ]
CN = Prooflog Test TSA
O  = Prooflog
[ tsa_ext ]
basicConstraints = critical, CA:false
keyUsage = critical, digitalSignature
extendedKeyUsage = critical, timeStamping
[ tsa_section ]
serial = $ENV::SERIAL
crypto_device = builtin
signer_cert = $ENV::CERT
signer_key = $ENV::KEY
signer_digest = sha256
certs = $ENV::CERT
default_policy = 1.2.3.4.1
digests = sha256, sha512
accuracy = secs:1
ordering = yes
tsa_name = yes
EOF

export CERT="$work/tsacert.pem" KEY="$work/tsakey.pem" SERIAL="$work/tsaserial"
openssl req -new -x509 -newkey rsa:2048 -nodes \
  -keyout "$KEY" -out "$CERT" -days 36500 -config "$work/tsa.cnf" >/dev/null 2>&1
echo 01 > "$SERIAL"

# note.bin is a realistic C2SP signed checkpoint note (origin / size / root,
# then a signature block). The anchor timestamps these exact bytes and parses
# the checkpoint identity back out of them.
root="$(head -c 32 /dev/zero | openssl base64 -A)"
printf 'prooflog/test/anchor\n100\n%s\n\n\xe2\x80\x94 prooflog/test/anchor dGVzdHNpZw==\n' "$root" > note.bin

openssl ts -query -data note.bin -sha256 -cert -out "$work/request.tsq" >/dev/null 2>&1
openssl ts -reply -queryfile "$work/request.tsq" -config "$work/tsa.cnf" \
  -section tsa_section -out response.der >/dev/null 2>&1

echo "wrote note.bin and response.der"
openssl ts -reply -in response.der -text 2>/dev/null | grep -E 'Status:|Nonce:|Time stamp:'
