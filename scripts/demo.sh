#!/usr/bin/env bash
# demo.sh — end-to-end Prooflog demo and narrated walkthrough.
#
# It builds the binary, initializes keys, starts the store, verifier, and agent,
# sends events and a heartbeat, simulates a store outage (buffering events
# locally), restarts the store, waits for replay, stops the agent gracefully,
# then verifies the evidence and generates the continuity/integrity report.
#
# Everything runs on loopback with the demo defaults. Re-runnable and self
# cleaning.
set -euo pipefail

cd "$(dirname "$0")/.."
ROOT="$(pwd)"
BIN="$ROOT/bin/prooflog"
DEMO="$ROOT/demo"

STORE_ADDR="127.0.0.1:9700"
VERIFIER_ADDR="127.0.0.1:9800"
AGENT_ADDR="127.0.0.1:9600"
SOURCE="vps-01/api"

STORE_PID="" VERIFIER_PID="" AGENT_PID=""

step() { printf '\n\033[1;36m== %s ==\033[0m\n' "$*"; }
info() { printf '   %s\n' "$*"; }

cleanup() {
  step "Cleanup"
  for pid in "$AGENT_PID" "$VERIFIER_PID" "$STORE_PID"; do
    [ -n "$pid" ] && kill "$pid" 2>/dev/null || true
  done
  wait 2>/dev/null || true
}
trap cleanup EXIT

wait_port() {
  local host=${1%:*} port=${1#*:} i
  for i in $(seq 1 50); do
    if (exec 3<>"/dev/tcp/$host/$port") 2>/dev/null; then exec 3>&- 3<&-; return 0; fi
    sleep 0.2
  done
  echo "timeout waiting for $1" >&2; return 1
}

wait_spool_event() { # <event-type> <timeout-seconds>
  local ev=$1 timeout=$2 i
  for i in $(seq 1 "$((timeout * 5))"); do
    if "$BIN" spool cat "$DEMO/spool" 2>/dev/null | grep -q "$ev"; then return 0; fi
    sleep 0.2
  done
  echo "timeout waiting for $ev in spool" >&2; return 1
}

send() { "$BIN" event "$@" --config "$DEMO/config.json"; }

step "Build"
CGO_ENABLED=0 go build -trimpath -o "$BIN" ./cmd/prooflog
info "built $BIN"

step "Reset demo workspace"
rm -rf "$DEMO"
mkdir -p "$DEMO"

step "init — generate org + agent keys, config, verifier registration"
"$BIN" init --dir "$DEMO" --org acme --source-id "$SOURCE" \
  --store-addr "$STORE_ADDR" --verifier-addr "$VERIFIER_ADDR" \
  --seal-max-records 3 --seal-max-age 3s --heartbeat-interval 5s >/dev/null
info "keys, config.json and verifier-keys.json written to $DEMO"

step "Start store"
"$BIN" store --dir "$DEMO/store-data" --listen "$STORE_ADDR" --insecure --allow-unauthenticated-holds & STORE_PID=$!
wait_port "$STORE_ADDR"; info "store up (pid $STORE_PID)"

step "Start verifier (trust anchor)"
"$BIN" verifier --listen "$VERIFIER_ADDR" --store-addr "$STORE_ADDR" \
  --data-dir "$DEMO/verifier-data" --keys "$DEMO/verifier-keys.json" --interval 3s --insecure & VERIFIER_PID=$!
wait_port "$VERIFIER_ADDR"; info "verifier up (pid $VERIFIER_PID)"

step "Start agent"
"$BIN" agent --config "$DEMO/config.json" & AGENT_PID=$!
wait_port "$AGENT_ADDR"; info "agent up (pid $AGENT_PID)"

step "Send events while everything is healthy"
send deploy.completed --actor ci --outcome success --payload-json '{"version":"1.4.2"}'
send access.granted   --actor admin@acme --outcome success --payload-json '{"user":"alice"}'
send access.revoked   --actor admin@acme --outcome success --payload-json '{"user":"bob"}'
"$BIN" heartbeat --config "$DEMO/config.json"
info "waiting for segments to seal and upload"
sleep 3

step "Simulate a store outage (kill the store)"
kill "$STORE_PID" 2>/dev/null || true
wait "$STORE_PID" 2>/dev/null || true
STORE_PID=""
info "store down — the agent must keep accepting events locally"

step "Send events during the outage (buffered to the local spool)"
send access.granted --actor admin@acme --outcome success --payload-json '{"user":"carol"}'
send access.revoked --actor admin@acme --outcome success --payload-json '{"user":"carol"}'
send deploy.completed --actor ci --outcome success --payload-json '{"version":"1.4.3"}'
wait_spool_event "system.network_outage" 10
info "outage recorded (system.network_outage)"

step "Restart the store"
"$BIN" store --dir "$DEMO/store-data" --listen "$STORE_ADDR" --insecure --allow-unauthenticated-holds & STORE_PID=$!
wait_port "$STORE_ADDR"; info "store back up (pid $STORE_PID)"

step "Wait for replay of buffered events"
wait_spool_event "system.replay_completed" 20
info "replay completed — buffered events uploaded"

step "Stop the agent gracefully (records system.agent_stopped)"
kill -TERM "$AGENT_PID" 2>/dev/null || true
wait "$AGENT_PID" 2>/dev/null || true
AGENT_PID=""

step "Verify the evidence (offline, from the local spool + verifier checkpoints)"
if "$BIN" verify --spool "$DEMO/spool" \
     --checkpoints "$DEMO/verifier-data" --keys "$DEMO/verifier-keys.json" \
     --heartbeat-interval 5s --insecure; then
  info "verification clean"
else
  info "verification raised findings (see above)"
fi

step "Generate the continuity / integrity report (period derived from the records, signed)"
TODAY="$(date -u +%F)"
"$BIN" report --spool "$DEMO/spool" \
  --checkpoints "$DEMO/verifier-data" --keys "$DEMO/verifier-keys.json" \
  --org acme --report-id "rpt-$TODAY-demo" \
  --verifier-name "prooflog demo verifier" \
  --verifier-operator "demo-verifier" \
  --heartbeat-interval 5s \
  --sign-key "$DEMO/agent.key" \
  --out "$DEMO/report.md" --insecure

step "Verify the report signature"
if "$BIN" report verify --verify-key "$DEMO/agent.key" "$DEMO/report.md"; then
  info "report signature verified"
else
  info "report signature check failed"
fi

step "Reproduce command emitted in the report (§10)"
grep -A4 '^prooflog verify' "$DEMO/report.md" || true

step "Privacy model (WS4) — pseudonymous actors + erasable linkability"
"$BIN" agent --config "$DEMO/config.json" & AGENT_PID=$!
wait_port "$AGENT_ADDR"; info "agent back up (pid $AGENT_PID)"
send access.revoked --actor alice@acme --outcome success \
  --label team=platform --payload-json '{"user":"alice"}'
wait_spool_event "access.revoked" 10
info "recorded an event for alice@acme (actor stored as an HMAC pseudonym)"

step "Look up alice's pseudonym in the salt store"
PSEUDO="$("$BIN" actor id --salts "$DEMO/salts.json" alice@acme)"
info "alice@acme -> $PSEUDO"

step "Erase alice's linkability (GDPR Art. 17 crypto-shredding)"
"$BIN" actor erase --salts "$DEMO/salts.json" alice@acme

step "Stop the agent again"
kill -TERM "$AGENT_PID" 2>/dev/null || true
wait "$AGENT_PID" 2>/dev/null || true
AGENT_PID=""

step "Re-verify after erasure — the chain still verifies without the salt"
if "$BIN" verify --spool "$DEMO/spool" \
     --checkpoints "$DEMO/verifier-data" --keys "$DEMO/verifier-keys.json" \
     --heartbeat-interval 5s --insecure; then
  info "verification clean — records intact and verifiable after erasure"
else
  info "verification raised findings (see above)"
fi

step "Legal hold — place and list (retention override, WS6)"
"$BIN" hold place --store-addr "$STORE_ADDR" --source "$SOURCE" \
  --reason "demo litigation hold" --placed-by "dpo" --insecure
"$BIN" hold list --store-addr "$STORE_ADDR" --source "$SOURCE" --insecure
info "held segments are exempt from retention deletion until released"

step "Done"
info "report: $DEMO/report.md"
info "sections:"
grep -E '^## ' "$DEMO/report.md"
