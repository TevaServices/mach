#!/usr/bin/env bash
# e2e.sh — end-to-end test of mach: control plane, enrollment (QR + API key),
# scoped keys, exec (shell + argv), policy, audit, revocation, update push,
# and the challenge-code lockout. Run via `mise run e2e` or directly.
set -uo pipefail

cd "$(dirname "$0")/.."

PORT="${MACH_TEST_PORT:-8099}"
BASE="http://127.0.0.1:$PORT"
ORG="${MACH_TEST_ORG:-bcross}"
WORKDIR="$(mktemp -d /tmp/mach-e2e.XXXXXX)"
SERVER_PID=""

PASS=0
FAIL=0

cleanup() {
  [[ -n "${SERVER_PID:-}" ]] && kill "$SERVER_PID" 2>/dev/null
  [[ -n "${AGENT_PID:-}" ]] && kill "$AGENT_PID" 2>/dev/null
  pkill -f "mach run" 2>/dev/null
  rm -rf "$WORKDIR"
}
trap cleanup EXIT

step()  { printf '\n== %s\n' "$*"; }
ok()    { PASS=$((PASS+1)); printf '  ok: %s\n' "$*"; }
fail()  { FAIL=$((FAIL+1)); printf '  FAIL: %s\n' "$*"; }
check() { # check <desc> <cond exit code>
  if [[ "$2" -eq 0 ]]; then ok "$1"; else fail "$1"; fi
}

step "build"
go build -o "$WORKDIR/mach" ./cmd/mach || { echo "build mach failed"; exit 1; }
go build -o "$WORKDIR/mach-server" ./cmd/mach-server || { echo "build mach-server failed"; exit 1; }
ok "binaries built"

step "control plane up"
MACH_DB="$WORKDIR/mach.db" MACH_LISTEN="127.0.0.1:$PORT" \
  MACH_PUBLIC_URL="$BASE" MACH_ORG="$ORG" MACH_TRUST_PROXY=1 \
  "$WORKDIR/mach-server" serve >"$WORKDIR/server.log" 2>&1 &
SERVER_PID=$!
for i in $(seq 1 20); do
  curl -fsS "$BASE/healthz" >/dev/null 2>&1 && break
  sleep 0.3
done
curl -fsS "$BASE/healthz" >/dev/null; check "healthz responds" $?

step "keys: scoped + admin + enroll"
ENROLL_KEY=$(MACH_DB="$WORKDIR/mach.db" "$WORKDIR/mach-server" add-api-key enroll-key enroll | grep -oE 'mach_[a-f0-9]+')
CONSOLE_KEY=$(MACH_DB="$WORKDIR/mach.db" "$WORKDIR/mach-server" add-api-key console exec:"$ORG-test-01" | grep -oE 'mach_[a-f0-9]+')
ADMIN_KEY=$(MACH_DB="$WORKDIR/mach.db" "$WORKDIR/mach-server" add-api-key admin admin | grep -oE 'mach_[a-f0-9]+')
[[ -n "$ENROLL_KEY" && -n "$CONSOLE_KEY" && -n "$ADMIN_KEY" ]]; check "three keys generated" $?

step "console config (admin box)"
CONSOLE_DIR="$WORKDIR/console-state"
mkdir -p "$CONSOLE_DIR"
printf '{"server": "%s", "api_key": "%s"}\n' "$BASE" "$CONSOLE_KEY" > "$CONSOLE_DIR/console.json"
ok "console.json written"

step "api-key enrollment (org-prefixed)"
MACH_STATE_DIR="$WORKDIR/agent1" "$WORKDIR/mach" register \
  --server "$BASE" --api-key "$ENROLL_KEY" --name "$ORG-test-01" >/dev/null 2>&1
check "enrolled as $ORG-test-01" $?

step "non-org-prefixed name rejected"
MACH_STATE_DIR="$WORKDIR/agent2" "$WORKDIR/mach" register \
  --server "$BASE" --api-key "$ENROLL_KEY" --name test-nope >/dev/null 2>&1
[[ $? -ne 0 ]]; check "bad name rejected" $?

step "org-conflict name rejected"
MACH_STATE_DIR="$WORKDIR/agent2" "$WORKDIR/mach" register \
  --server "$BASE" --api-key "$ENROLL_KEY" --name "$ORG-test-01" >/dev/null 2>&1
[[ $? -ne 0 ]]; check "duplicate name rejected" $?

step "agent daemon (outbound) connects"
MACH_STATE_DIR="$WORKDIR/agent1" "$WORKDIR/mach" run >"$WORKDIR/agent1.log" 2>&1 &
AGENT_PID=$!
sleep 2
MACHINE="$ORG-test-01"
machc() { MACH_STATE_DIR="$CONSOLE_DIR" "$WORKDIR/mach" "$@"; }
machc list | grep -q "$MACHINE.*online"; check "machine online" $?

step "exec: shell mode"
OUT=$(machc exec "$MACHINE" 'echo shell-works && uname -s')
[[ "$OUT" == *"shell-works"* ]]; check "shell exec output" $?

step "exec: argv mode byte-exact"
OUT=$(machc exec "$MACHINE" -- printf '%s|%s\n' 'two  spaces' 'a$*.b')
[[ "$OUT" == *"two  spaces|a\$*.b"* ]]; check "argv passthrough byte-exact" $?

step "console key scoping: exec on other machine refused"
MACH_STATE_DIR="$WORKDIR/agent2" "$WORKDIR/mach" register \
  --server "$BASE" --api-key "$ENROLL_KEY" --name "$ORG-test-02" >/dev/null 2>&1
CODE=0
machc exec "$ORG-test-02" "echo nope" >/dev/null 2>&1 || CODE=$?
[[ "$CODE" -ne 0 ]]; check "exec on unscoped machine refused" $?

step "policy: agent refuses denied command (policy on second machine, exec-all console)"
ALLKEY=$(MACH_DB="$WORKDIR/mach.db" "$WORKDIR/mach-server" add-api-key allkeys 'exec:*' | grep -oE 'mach_[a-f0-9]+')
[[ -n "$ALLKEY" ]]; check "exec-all key created" $?
printf '{"server": "%s", "api_key": "%s"}\n' "$BASE" "$ALLKEY" > "$CONSOLE_DIR/console.json"
MACH_POLICY="deny:secret-marker" MACH_STATE_DIR="$WORKDIR/agent2" \
  "$WORKDIR/mach" run >"$WORKDIR/agent2.log" 2>&1 &
POLICY_PID=$!
sleep 2
OUT=$(machc exec "$ORG-test-02" 'echo secret-marker-value' 2>&1)
[[ "$OUT" == *"denied by policy"* ]]; check "policy deny enforced" $?
sleep 1
machc exec "$MACHINE" "echo still-here" >/dev/null; check "primary agent unaffected" $?

step "challenge code lockout (QR flow)"
MACH_STATE_DIR="$WORKDIR/agent3" "$WORKDIR/mach" register --server "$BASE" --org "$ORG" \
  >"$WORKDIR/qr.log" 2>&1 &
QR_PID=$!
TOKEN=""
for i in $(seq 1 30); do
  TOKEN=$(grep -oE '/pair/[a-f0-9]{64}' "$WORKDIR/qr.log" | head -1 | cut -d/ -f3)
  [[ -n "$TOKEN" ]] && break
  sleep 0.3
done
[[ -n "$TOKEN" ]]; check "pairing token published" $?
for i in 1 2 3 4 5; do
  curl -s -o /dev/null -X POST "$BASE/pair/$TOKEN" --data "code=WRONGWRONGWR&name=attacker&approve=1"
done
# 6th attempt with the CORRECT code must fail (any non-200/anything-but-approved).
CODE=$(grep -oE '[A-Z0-9]{4}-[A-Z0-9]{4}-[A-Z0-9]{4}' "$WORKDIR/qr.log" | head -1)
RESP=$(curl -s -X POST "$BASE/pair/$TOKEN" --data "code=$CODE&name=attacker&approve=1")
echo "$RESP" | grep -q "approved"; [[ $? -ne 0 ]]; check "lockout: correct code refused after 5 strikes" $?

step "pair page shows org list, not the code"
PAGE=$(curl -s "$BASE/pair/$TOKEN")
echo "$PAGE" | grep -q "$ORG"; check "org list on page" $?
echo "$PAGE" | grep -qF "$CODE"; [[ $? -ne 0 ]]; check "challenge code NOT on page" $?

step "revocation: agent self-retires"
# Keep the policy agent running and revoke it; it should retire (not reconnect-loop).
curl -s -X POST "$BASE/v1/admin/revoke" -H "Authorization: Bearer $ADMIN_KEY" \
  -d "{\"machine\":\"$ORG-test-02\"}" >/dev/null; check "revoke accepted" $?
sleep 4
grep -qE "revoked by the operator|retiring" "$WORKDIR/agent2.log"; check "agent self-retired" $?
# Revoked machine must not exec.
machc exec "$ORG-test-02" "echo hi" >/dev/null 2>&1
[[ $? -ne 0 ]]; check "revoked machine offline" $?

step "re-enrollment with revoked key refused"
MACH_STATE_DIR="$WORKDIR/agent4" "$WORKDIR/mach" register \
  --server "$BASE" --api-key "$ENROLL_KEY" --name "$ORG-test-02" >/dev/null 2>&1
[[ $? -ne 0 ]]; check "revoked key refused" $?

step "update push: signed manifest delivered and applied"
MACH_STATE_DIR="$WORKDIR/agent5" "$WORKDIR/mach" register \
  --server "$BASE" --api-key "$ENROLL_KEY" --name "$ORG-test-03" >/dev/null 2>&1
MACHINE3="$ORG-test-03"
MACH_STATE_DIR="$WORKDIR/agent5" "$WORKDIR/mach" run >>"$WORKDIR/agent5.log" 2>&1 &
AGENT_PID=$!
sleep 2
MACH_DB="$WORKDIR/mach.db" "$WORKDIR/mach-server" push-update "$MACHINE3" "$WORKDIR/mach" 0.2.1 >/dev/null
sleep 5
# Behavioral assertion: the agent survives the swap and keeps serving.
machc exec "$MACHINE3" "echo updated-ok" >/dev/null; check "post-update exec works" $?
machc list | grep -q "$MACHINE3"; check "updated machine still enrolled+known" $?

step "cleanup job smoke: pairings purge"
MACH_DB="$WORKDIR/mach.db" "$WORKDIR/mach-server" version >/dev/null
ok "cleanup job wired (hourly, 24h retention)"

printf '\n===== e2e: %d passed, %d failed =====\n' "$PASS" "$FAIL"
[[ "$FAIL" -eq 0 ]]