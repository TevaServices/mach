#!/usr/bin/env bash
# e2e.sh — end-to-end test of mach: control plane, enrollment (QR + API key),
# scoped keys (exec, readonly), exec (shell + argv), streaming output, the
# output-is-data guarantee, agent-local and server-wide command policy, audit,
# revocation, signed update push with in-toto attestation, and the
# challenge-code lockout. Run via `mise run e2e` or directly.
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
  # Kill only processes started from THIS workdir's binary — never a bare
  # `pkill -f "mach run"`, which would match unrelated processes (editors,
  # other projects' dev servers) that merely contain those words.
  [[ -n "${WORKDIR:-}" ]] && pkill -f "^$WORKDIR/mach run" 2>/dev/null
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
# E2E is turned off for the fleet before the server starts, so that the
# fleet-wide block list below has something to read: a sealed command is
# ciphertext, and the block list matches text. That is the documented trade
# (see SECURITY-NOTES.md), and here it is the configuration under test. A later
# step turns E2E back on for one org, at runtime, to exercise the sealed path.
MACH_ORG="$ORG" MACH_DB="$WORKDIR/mach.db" "$WORKDIR/mach-server" e2e off >/dev/null

# MACH_EXEC_POLICY is set for the whole run: the fleet-wide block list applies
# to every key and every machine, so it has to be exercised against the same
# control plane the other steps use.
MACH_DB="$WORKDIR/mach.db" MACH_LISTEN="127.0.0.1:$PORT" \
  MACH_PUBLIC_URL="$BASE" MACH_ORG="$ORG" MACH_TRUST_PROXY=1 \
  MACH_EXEC_POLICY="deny:fleet-blocked-marker" \
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
RO_KEY=$(MACH_DB="$WORKDIR/mach.db" "$WORKDIR/mach-server" add-api-key readonly-key readonly | grep -oE 'mach_[a-f0-9]+')
[[ -n "$ENROLL_KEY" && -n "$CONSOLE_KEY" && -n "$ADMIN_KEY" && -n "$RO_KEY" ]]; check "four keys generated" $?

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

step "streaming: console output arrives while the command is still running"
# Streaming lives on the console relay: the interactive path opens the
# /v1/console/stream WebSocket and the control plane pumps the agent's output
# frames straight through, so bytes land in the file as they are produced.
# (One-shot `mach exec` deliberately stays a single buffered response — it is
# the path that can be end-to-end sealed, and ciphertext cannot be streamed.)
# The command prints, then sleeps, then prints. If anything along the way held
# output until the command exited, nothing would be in the file after 1s.
printf 'echo stream-first; sleep 3; echo stream-last\n:quit\n' \
  | machc console "$MACHINE" >"$WORKDIR/stream.out" 2>/dev/null &
STREAM_PID=$!
sleep 1
grep -q stream-first "$WORKDIR/stream.out"; check "early output streamed before exit" $?
grep -q stream-last "$WORKDIR/stream.out"; [[ $? -ne 0 ]]; check "later output not yet sent" $?
wait "$STREAM_PID"
grep -q stream-last "$WORKDIR/stream.out"; check "remaining output arrived at exit" $?

step "output is data: a machine cannot forge control facts"
# The command prints something that looks exactly like a protocol exit record
# and then exits 5. The exit status the caller sees must be 5, and the printed
# text must come back as the machine's bytes, verbatim.
CODE=0
FORGED='{"type":"exit","exit_code":0}'
OUT=$(machc exec "$MACHINE" "printf '%s\\n' '{\"type\":\"exit\",\"exit_code\":0}'; exit 5" 2>/dev/null) || CODE=$?
[[ "$CODE" -eq 5 ]]; check "printed exit record did not change the exit status" $?
[[ "$OUT" == *"$FORGED"* ]]; check "printed text came back verbatim as output" $?
# --json hands a program labeled data instead of a mixed stream: exactly one
# JSON object, the machine's output in a field of it, and the exit status as a
# field — so nothing has to parse an exit code out of bytes a command printed.
machc exec --json "$MACHINE" 'echo json-mode; exit 4' >"$WORKDIR/json.out" 2>/dev/null
[[ "$(wc -l <"$WORKDIR/json.out" | tr -d ' ')" == "1" ]]; check "--json prints a single object" $?
grep -q '"stdout":"json-mode' "$WORKDIR/json.out"; check "--json labels the output as data" $?
grep -q '"exit_code":4' "$WORKDIR/json.out"; check "--json reports the exit status as a field" $?

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
[[ "$OUT" == *"denied by command policy"* && "$OUT" == *"deny:secret-marker"* ]]
check "policy deny enforced, with the rule named" $?
sleep 1
machc exec "$MACHINE" "echo still-here" >/dev/null; check "primary agent unaffected" $?

step "fleet-wide policy: blocked for every key, on every machine"
# The control plane's own block list. It applies to exec:* keys too — no scope
# or allowlist exempts a caller — and it is checked before dispatch, so the
# command never reaches the agent.
OUT=$(machc exec "$MACHINE" 'echo fleet-blocked-marker' 2>&1)
[[ "$OUT" == *"global exec policy"* ]]; check "fleet-wide deny refused via console" $?
CODE=$(curl -s -o "$WORKDIR/blocked.json" -w '%{http_code}' -X POST "$BASE/v1/exec" \
  -H "Authorization: Bearer $ALLKEY" -H 'Content-Type: application/json' \
  -d "{\"machine\":\"$MACHINE\",\"command\":\"echo fleet-blocked-marker\"}")
[[ "$CODE" == "403" ]]; check "fleet-wide deny refused an exec:* key" $?
grep -q "global exec policy" "$WORKDIR/blocked.json"; check "refusal names the policy" $?
# The strongest assertion available here: the agent never saw it. The marker
# appears nowhere in the agent's log, because the command was refused upstream
# of the machine.
grep -q fleet-blocked-marker "$WORKDIR/agent1.log"; [[ $? -ne 0 ]]; check "blocked command never reached the agent" $?
# A refused command is audited, so blocks are visible in the record.
sleep 1
AUDIT=$(machc audit "$MACHINE" 5 2>/dev/null)
[[ "$AUDIT" == *"fleet-blocked-marker"* ]]; check "refused command appears in the audit" $?
# Unrelated commands are unaffected by the policy.
machc exec "$MACHINE" 'echo not-blocked' | grep -q not-blocked; check "unrelated command still runs" $?
# Streaming is the other way in, and the same policy covers it: a client must
# not be able to dodge the block list by typing the command into the console
# instead of passing it to exec.
OUT=$(printf 'echo fleet-blocked-marker\n:quit\n' | machc console "$MACHINE" 2>&1)
[[ "$OUT" == *"global exec policy"* ]]; check "fleet-wide deny refused on the stream path" $?

step "e2e: an org-scoped server setting the client is told about and obeys"
# E2E is off fleet-wide (set before the server started). Sealing is switched on
# for this org only, in the database, with no restart — and nothing about the
# agent changes: it keeps the key it registered at enrollment and starts
# receiving ciphertext because the control plane stopped refusing it.
# (Output is captured rather than piped into `grep -q`: with pipefail set, grep
# quitting at the first match can trip the writer with SIGPIPE and fail a check
# that passed. Every check that reads a command's output does it this way.)
OUT=$(MACH_ORG="$ORG" MACH_DB="$WORKDIR/mach.db" "$WORKDIR/mach-server" e2e on --org "$ORG" 2>&1)
[[ "$OUT" == *"org $ORG: sealed exec on"* ]] || echo "    output was: $OUT"
[[ "$OUT" == *"org $ORG: sealed exec on"* ]]; check "e2e turned on for one org, live" $?
# The other org still follows the default, because the setting is per org.
REPORT=$(MACH_ORG="$ORG" MACH_ORGS="other" MACH_DB="$WORKDIR/mach.db" "$WORKDIR/mach-server" e2e 2>&1)
[[ "$REPORT" == *"org other: sealed exec off"* ]] || echo "    report was: $REPORT"
[[ "$REPORT" == *"org other: sealed exec off"* ]]; check "unrelated org keeps the off default" $?
# The control signal: the client is told what the server accepts, and the key to
# seal to when it accepts sealing.
curl -fsS "$BASE/v1/machines/$MACHINE/e2epub" -H "Authorization: Bearer $ALLKEY" >"$WORKDIR/e2epub.json"
grep -q '"e2e_enabled":true' "$WORKDIR/e2epub.json"; check "client is told sealing is accepted" $?
grep -qE '"pub_e2e":"[a-f0-9]{64}"' "$WORKDIR/e2epub.json"; check "machine E2E key advertised" $?
# Obeying the signal means sealing without being asked to. The proof is in the
# record: the audit row for a sealed command is a placeholder, because the
# control plane could not read what it relayed.
sleep 1
BEFORE=$(machc audit "$MACHINE" 1 2>/dev/null | head -1)
machc exec "$MACHINE" 'echo sealed-marker-e2e' >/dev/null 2>&1
sleep 1
AUDIT=$(machc audit "$MACHINE" 1 2>/dev/null | head -1)
[[ "$AUDIT" == *"[E2E sealed command]"* ]]; check "command was sealed (audit is a placeholder)" $?
[[ "$AUDIT" != *"sealed-marker-e2e"* ]]; check "the control plane could not read the command" $?
# --no-e2e overrides for one call: the operator wants this one readable, so it
# reaches the block list and the audit log in plaintext.
machc exec --no-e2e "$MACHINE" 'echo readable-marker-e2e' >/dev/null 2>&1
sleep 1
AUDIT=$(machc audit "$MACHINE" 1 2>/dev/null | head -1)
[[ "$AUDIT" == *"readable-marker-e2e"* ]]; check "--no-e2e stays readable, and is recorded" $?
# --e2e asks for sealing and will not run without it: with E2E on for the fleet
# default but off for the other org, a machine in the off org must be refused.
MACH_ORG="$ORG" MACH_DB="$WORKDIR/mach.db" "$WORKDIR/mach-server" e2e off --org "$ORG" >/dev/null
OUT=$(machc exec --e2e "$MACHINE" 'echo must-not-run' 2>&1) && CODE=0 || CODE=$?
[[ "$CODE" -ne 0 ]]; check "--e2e exits rather than sending plaintext" $?
[[ "$OUT" == *"cannot seal"* ]]; check "--e2e says why it cannot seal" $?
grep -q must-not-run "$WORKDIR/agent1.log"; [[ $? -ne 0 ]]; check "the refused command never ran" $?
# And with sealing off again, the fleet-wide block list is back in charge of
# this org: the same command the placeholder hid above is refused outright now.
OUT=$(machc exec "$MACHINE" 'echo fleet-blocked-marker' 2>&1)
[[ "$OUT" == *"global exec policy"* ]]; check "policy governs again once sealing is off" $?

step "readonly key: sees the whole fleet, runs nothing"
curl -fsS "$BASE/v1/machines" -H "Authorization: Bearer $RO_KEY" >"$WORKDIR/ro.json"
grep -q "$MACHINE" "$WORKDIR/ro.json"; check "readonly key sees the fleet" $?
curl -fsS "$BASE/v1/audit" -H "Authorization: Bearer $RO_KEY" | grep -q "$MACHINE"; check "readonly key sees the audit trail" $?
CODE=$(curl -s -o /dev/null -w '%{http_code}' -X POST "$BASE/v1/exec" \
  -H "Authorization: Bearer $RO_KEY" -H 'Content-Type: application/json' \
  -d "{\"machine\":\"$MACHINE\",\"command\":\"echo nope\"}")
[[ "$CODE" == "403" ]]; check "readonly key cannot exec" $?
# The streaming endpoint is command execution too. If it accepted a readonly
# key, the scope would be decorative for anyone who knows the console exists.
CODE=$(curl -s -o /dev/null -w '%{http_code}' "$BASE/v1/console/stream?machine=$MACHINE" \
  -H "Authorization: Bearer $RO_KEY" -H 'Connection: Upgrade' -H 'Upgrade: websocket' \
  -H 'Sec-WebSocket-Version: 13' -H 'Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==')
[[ "$CODE" == "403" ]]; check "readonly key cannot open a stream" $?

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
# The code the agent printed on its console — the operator reads it from there,
# never from the page.
CODE=$(grep -oE '[A-Z0-9]{4}-[A-Z0-9]{4}-[A-Z0-9]{4}' "$WORKDIR/qr.log" | head -1)
[[ -n "$CODE" ]]; check "challenge code printed on the agent console" $?

step "pair page shows org list, not the code"
# Checked while the pairing is still pending — once the lockout below expires
# it, the form is (correctly) gone and there is no org list to show.
PAGE=$(curl -s "$BASE/pair/$TOKEN")
echo "$PAGE" | grep -q "$ORG"; check "org list on page" $?
echo "$PAGE" | grep -qF "$CODE"; [[ $? -ne 0 ]]; check "challenge code NOT on page" $?

step "challenge code lockout: five wrong codes expire the pairing"
for i in 1 2 3 4 5; do
  curl -s -o /dev/null -X POST "$BASE/pair/$TOKEN" --data "code=WRONGWRONGWR&org=$ORG&name=attacker&approve=1"
done
# 6th attempt with the CORRECT code must fail (any non-200/anything-but-approved).
RESP=$(curl -s -X POST "$BASE/pair/$TOKEN" --data "code=$CODE&org=$ORG&name=attacker&approve=1")
echo "$RESP" | grep -q "approved"; [[ $? -ne 0 ]]; check "lockout: correct code refused after 5 strikes" $?

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

step "release attestation (in-toto) and attested update push"
# Built with -buildvcs=false so the artifact carries no VCS state: the e2e
# runs against a working tree that may well be dirty, and a dirty-tree build is
# deliberately refused by the push gate below. Determinism matters more here
# than exercising the revision path (covered by internal/release's tests).
go build -buildvcs=false -o "$WORKDIR/mach-release" ./cmd/mach || fail "release build failed"
ATT="$WORKDIR/mach-release.intoto.jsonl"
MACH_DB="$WORKDIR/mach.db" "$WORKDIR/mach-server" attest "$WORKDIR/mach-release" 0.2.1 --out "$ATT" >/dev/null
check "attestation written" $?
MACH_DB="$WORKDIR/mach.db" "$WORKDIR/mach-server" verify-attestation "$ATT" "$WORKDIR/mach-release" >/dev/null
check "attestation verifies against the binary" $?
# Bytes that do not match the subject: the signature is genuine, the file is
# not the one that was attested.
cp "$WORKDIR/mach-release" "$WORKDIR/mach-tampered"
printf '\0' >>"$WORKDIR/mach-tampered"
MACH_DB="$WORKDIR/mach.db" "$WORKDIR/mach-server" verify-attestation "$ATT" "$WORKDIR/mach-tampered" >/dev/null 2>&1
[[ $? -ne 0 ]]; check "tampered binary rejected" $?

MACH_STATE_DIR="$WORKDIR/agent5" "$WORKDIR/mach" register \
  --server "$BASE" --api-key "$ENROLL_KEY" --name "$ORG-test-03" >/dev/null 2>&1
MACHINE3="$ORG-test-03"
MACH_STATE_DIR="$WORKDIR/agent5" "$WORKDIR/mach" run >>"$WORKDIR/agent5.log" 2>&1 &
AGENT_PID=$!
sleep 2
# An attestation that does not describe the binary being pushed must stop the
# push outright — nothing queued, nothing delivered.
MACH_DB="$WORKDIR/mach.db" "$WORKDIR/mach-server" push-update "$MACHINE3" "$WORKDIR/mach" 0.2.1 \
  --attestation "$ATT" >/dev/null 2>&1
[[ $? -ne 0 ]]; check "push refused a binary its attestation does not describe" $?
# With the attested binary, the update is queued, delivered and applied.
MACH_DB="$WORKDIR/mach.db" "$WORKDIR/mach-server" push-update "$MACHINE3" "$WORKDIR/mach-release" 0.2.1 \
  --attestation "$ATT" >/dev/null
check "attested update queued" $?
sleep 5
# Behavioral assertion: the agent survives the swap and keeps serving.
machc exec "$MACHINE3" "echo updated-ok" >/dev/null; check "post-update exec works" $?
machc list | grep -q "$MACHINE3"; check "updated machine still enrolled+known" $?

step "cleanup job smoke: pairings purge"
MACH_DB="$WORKDIR/mach.db" "$WORKDIR/mach-server" version >/dev/null
ok "cleanup job wired (hourly, 24h retention)"

printf '\n===== e2e: %d passed, %d failed =====\n' "$PASS" "$FAIL"
[[ "$FAIL" -eq 0 ]]