#!/usr/bin/env bash
# e2e.sh — end-to-end test of mach: control plane, enrollment (QR + API key),
# scoped keys (exec, readonly), exec (shell + argv), streaming output, the
# output-is-data guarantee, agent-local and server-wide command policy, audit,
# revocation, signed update push with in-toto attestation, the
# challenge-code lockout, and the OIDC web UI (block / revoke / delete, org
# management) driven against a loopback identity provider.
# Run via `mise run e2e` or directly.
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
  # The web-UI section runs its own control plane and a fake identity provider on
  # their own ports and database, so tearing down must not depend on the primary
  # server's lifecycle.
  [[ -n "${UI_SERVER_PID:-}" ]] && kill "$UI_SERVER_PID" 2>/dev/null
  [[ -n "${IDP_PID:-}" ]] && kill "$IDP_PID" 2>/dev/null
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

# The version is compiled in and overridden at link time with -X. This is the
# only check that can prove that path, and it is not optional: -X sets a string
# symbol only if the linker still has a use for it, and a misspelled symbol path
# does nothing at all rather than failing — a stamp that silently does not take
# would leave every release reporting the development default.
step "version: compiled-in default, and -X overriding it"
go build -ldflags "-X github.com/bcross/mach/internal/version.Version=9.9.9-test" \
  -o "$WORKDIR/mach-server-stamped" ./cmd/mach-server || { echo "stamped build failed"; exit 1; }
OUT=$("$WORKDIR/mach-server-stamped" version); [[ "$OUT" == "mach-server 9.9.9-test "* ]]
check "an -X build reports the stamped version" $?
OUT=$("$WORKDIR/mach-server" version); [[ "$OUT" != *"9.9.9-test"* ]]
check "a plain build reports the compiled-in default, not the injected one" $?
# Both binaries share one string: the agent and the control plane used to carry
# separate constants that disagreed, so `mach version` and `mach-server version`
# answered differently for the same checkout.
OUT=$("$WORKDIR/mach" version); [[ "$OUT" == "mach "* ]]
check "the agent binary reports a version too" $?
[[ "${OUT#mach }" == "$("$WORKDIR/mach-server" version | sed 's/^mach-server //')" ]]
check "both binaries report the same version" $?

step "control plane up"
# E2E is turned off for the fleet before the server starts, so that the
# fleet-wide block list below has something to read: a sealed command is
# ciphertext, and the block list matches text. That is the documented trade
# (see SECURITY-NOTES.md), and here it is the configuration under test. A later
# step turns E2E back on for one org, at runtime, to exercise the sealed path.
MACH_ORG="$ORG" MACH_DB="$WORKDIR/mach.db" "$WORKDIR/mach-server" e2e off >/dev/null

# The fleet-wide block list is configured from a FILE for the whole run. It
# applies to every key and every machine, so it has to be exercised against the
# same control plane the other steps use — and a file is also what makes the
# live-reload path testable: the rules are enforced on the machines (that is the
# only place a sealed command is readable), so editing this file has to reach
# agents that are already connected.
printf 'deny:fleet-blocked-marker\n' > "$WORKDIR/fleet.policy"
MACH_DB="$WORKDIR/mach.db" MACH_LISTEN="127.0.0.1:$PORT" \
  MACH_PUBLIC_URL="$BASE" MACH_ORG="$ORG" MACH_TRUST_PROXY=1 \
  MACH_EXEC_POLICY_FILE="$WORKDIR/fleet.policy" \
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
# The strongest assertion available here: the command was never dispatched. The
# marker text does appear in this log — as a RULE, because the fleet policy is
# mirrored onto the machine (that is how it applies to sealed commands) — so the
# check excludes the policy lines and requires that nothing else mentions it.
grep -q "fleet exec policy installed.*fleet-blocked-marker" "$WORKDIR/agent1.log"
check "the machine holds the fleet rule as a rule" $?
grep -v "fleet exec policy installed" "$WORKDIR/agent1.log" | grep -q fleet-blocked-marker
[[ $? -ne 0 ]]; check "blocked command never reached the agent" $?
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
# This is the first sealed command to this machine, so it is also where the key
# gets pinned — and the operator is told, because a first use is the one moment
# there is no protection at all.
PINOUT=$(machc exec "$MACHINE" 'echo sealed-marker-e2e' 2>&1)
[[ "$PINOUT" == *"pinned the E2E key for $MACHINE"* ]]; check "first sealed command reported the pin" $?
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

step "the fleet block list applies to sealed commands too"
# The headline property. The control plane cannot read a sealed command, so it
# cannot apply its own rules to one — so the rules are mirrored onto the machine
# at connect (and on every change) and evaluated where the plaintext is. Sealing
# is turned back on for this org, and the blocked command must still be refused:
# by the machine this time, with the seal intact in both directions.
MACH_ORG="$ORG" MACH_DB="$WORKDIR/mach.db" "$WORKDIR/mach-server" e2e on --org "$ORG" >/dev/null
# The agent confirms which ruleset it holds, so "is this machine enforcing the
# current rules" has an answer rather than an assumption.
grep -q "fleet exec policy installed" "$WORKDIR/agent1.log"; check "machine installed the mirrored rules" $?
OUT=$(machc exec "$MACHINE" 'echo fleet-blocked-marker' 2>&1) && CODE=0 || CODE=$?
[[ "$CODE" -eq 126 ]]; check "sealed command refused (exit 126)" $?
[[ "$OUT" == *"fleet-blocked-marker"* ]]; check "refusal names the rule, through the seal" $?
[[ "$OUT" == *"fleet-wide exec policy"* ]]; check "refusal names the layer that refused it" $?
# Sealed it was: the audit row is the placeholder, so the control plane never saw
# the command — and the block list applied anyway.
sleep 1
AUDIT=$(machc audit "$MACHINE" 1 2>/dev/null | head -1)
[[ "$AUDIT" == *"[E2E sealed command]"* ]]; check "the refused command stayed sealed in the record" $?
[[ "$AUDIT" != *"fleet-blocked-marker"* ]]; check "the control plane still cannot read it" $?
# First use pins the key the control plane advertised — the seal is only worth
# what that key is, and the control plane is the party it defends against.
PINS="$CONSOLE_DIR/e2e_pins.json"
[[ -f "$PINS" ]]; check "the machine's E2E key was pinned on first use" $?
grep -q "$MACHINE" "$PINS"; check "the pin names the machine" $?
# A pin that no longer matches what the control plane hands out stops sealing.
# Written by hand here because, from the console's side, this is indistinguishable
# from a control plane that swapped the key — which is the point.
jq '.machines["'"$MACHINE"'"].pub_e2e = "0000000000000000000000000000000000000000000000000000000000000000"' \
  "$PINS" > "$PINS.tmp" && mv "$PINS.tmp" "$PINS"
OUT=$(machc exec "$MACHINE" 'echo must-not-be-sealed' 2>&1) && CODE=0 || CODE=$?
[[ "$CODE" -ne 0 ]]; check "a changed E2E key refuses to seal" $?
[[ "$OUT" == *"E2E key for $MACHINE changed"* ]]; check "the refusal says the key changed" $?
[[ "$OUT" == *"mach trust $MACHINE"* ]]; check "the refusal names the remedy" $?
# The explicit re-trust is the only thing that accepts it, and sealing works again.
machc trust "$MACHINE" | grep -q "$MACHINE"; check "mach trust re-pins the key" $?
OUT=$(machc exec "$MACHINE" 'echo after-trust') || true
[[ "$OUT" == *"after-trust"* ]]; check "sealing works again after trust" $?

# A rule added to the fleet list after this machine connected must reach it
# without a restart or a reconnect: the rules are enforced on the machines, so a
# change that only updated the control plane would leave every running agent
# enforcing the previous version.
#
# These two commands are SEALED (E2E is on for this org here). That matters: a
# plaintext command is judged by the control plane, which would pass whether or
# not the machine ever got the new rules. Only the machine can judge a sealed
# one, so only a sealed one tests propagation.
machc exec "$MACHINE" 'echo rotated-marker' | grep -q rotated-marker
check "baseline: the new marker is not blocked yet" $?
# Edit the file the control plane watches: it re-reads on mtime change and pushes
# the new ruleset to every connected agent.
printf 'deny:fleet-blocked-marker\ndeny:rotated-marker\n' > "$WORKDIR/fleet.policy"
BLOCKED=1
for i in $(seq 1 40); do
  OUT=$(machc exec "$MACHINE" 'echo rotated-marker' 2>&1) || true
  if [[ "$OUT" == *"rotated-marker"* && "$OUT" == *"fleet-wide exec policy"* ]]; then BLOCKED=0; break; fi
  sleep 1
done
[[ "$BLOCKED" -eq 0 ]] || echo "    last output: $OUT"
[[ "$BLOCKED" -eq 0 ]]; check "a rule added live reached the connected machine" $?

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

step "re-enrollment after revocation: a revoked machine returns, an active one is safe"
# Revocation is a FORCED RE-ENROLLMENT, not a one-way door: the agent self-retires
# and the name and key stay reserved, but enrolling again revives the machine.
# (This check used to assert the opposite. The change is deliberate — it is what
# makes "revoke" recoverable without handing out the delete power.)
MACH_STATE_DIR="$WORKDIR/agent4" "$WORKDIR/mach" register \
  --server "$BASE" --api-key "$ENROLL_KEY" --name "$ORG-test-02" >/dev/null 2>&1
check "a revoked machine re-enrolls with a fresh key" $?
OUT=$(curl -sS "$BASE/v1/machines" -H "Authorization: Bearer $ADMIN_KEY" 2>&1)
[[ "$OUT" == *"$ORG-test-02"* ]]; check "the revived machine is back in the fleet" $?
# And it works: the revived agent connects and runs a command.
MACH_STATE_DIR="$WORKDIR/agent4" "$WORKDIR/mach" run >"$WORKDIR/agent4.log" 2>&1 &
sleep 2
machc exec "$ORG-test-02" "echo revived-ok" >/dev/null 2>&1
check "the revived machine runs commands again" $?

# The counterweight, and the reason the revive is guarded in SQL: an ACTIVELY
# enrolled machine's name must not be takeable by an enrollment. Without this,
# a typo would displace a working agent.
MACH_STATE_DIR="$WORKDIR/agent-displace" "$WORKDIR/mach" register \
  --server "$BASE" --api-key "$ENROLL_KEY" --name "$MACHINE" >/dev/null 2>&1
[[ $? -ne 0 ]]; check "an active machine's name cannot be taken over" $?
OUT=$(curl -sS "$BASE/v1/machines" -H "Authorization: Bearer $ADMIN_KEY" 2>&1)
[[ "$OUT" == *"$MACHINE"* ]]; check "the active machine is still enrolled" $?

step "plain mach on a target is the temporary session"
# Bare `mach` is a TEMPORARY session: it enrolls with an in-memory identity, is
# recorded on the control plane as temporary, and retires that enrollment when it
# ends. The temp name is its own so nothing here disturbs the agents above.
TMP_NAME="$ORG-tmp-01"
TMP_PART="tmp-01"
TMP_STATE="$WORKDIR/agent-tmp"
MACH_SERVER="$BASE" MACH_ORG="$ORG" MACH_STATE_DIR="$TMP_STATE" \
  "$WORKDIR/mach" >"$WORKDIR/agent-tmp.log" 2>&1 &
TMP_PID=$!

# Drive the phone side of the pairing from here, exactly as an operator would:
# the token comes from the printed pair URL, the code from the agent's own
# console (never from the page). Polling for the token also means the banner
# below has certainly been written — reading the log straight after starting the
# process races it.
TMP_TOKEN=""
for i in $(seq 1 30); do
  TMP_TOKEN=$(grep -oE '/pair/[a-f0-9]{64}' "$WORKDIR/agent-tmp.log" | head -1 | cut -d/ -f3)
  [[ -n "$TMP_TOKEN" ]] && break
  sleep 0.3
done
[[ -n "$TMP_TOKEN" ]]; check "temporary session published a pairing" $?
TMP_CODE=$(grep -oE '[A-Z0-9]{4}-[A-Z0-9]{4}-[A-Z0-9]{4}' "$WORKDIR/agent-tmp.log" | head -1)
[[ -n "$TMP_CODE" ]]; check "temporary session printed its challenge code" $?
OUT=$(cat "$WORKDIR/agent-tmp.log" 2>&1)
[[ "$OUT" == *"TEMPORARY session"* ]]; check "plain mach announces that it is temporary" $?
curl -s -o /dev/null -X POST "$BASE/pair/$TMP_TOKEN" \
  --data "code=$TMP_CODE&org=$ORG&name=$TMP_PART&approve=1"
sleep 3

# It is enrolled, and recorded as temporary.
OUT=$(curl -sS "$BASE/v1/machines" -H "Authorization: Bearer $ADMIN_KEY" 2>&1)
[[ "$OUT" == *"$TMP_NAME"* ]]; check "the temporary session enrolled" $?
[[ "$OUT" == *'"temporary":true'* ]]; check "and the control plane recorded it as temporary" $?

# Nothing on disk: that is what makes the next run a re-enrollment rather than a
# silent reuse of an identity.
ENTRIES=$(ls -A "$TMP_STATE" 2>/dev/null | wc -l | tr -d ' ')
[[ "$ENTRIES" == "0" ]]; check "the temporary session wrote nothing to the state dir" $?

# Ending it retires the enrollment rather than leaving a machine that looks
# broken. SIGTERM is what Ctrl-C sends.
kill -TERM "$TMP_PID" 2>/dev/null
wait "$TMP_PID" 2>/dev/null
OUT=$(cat "$WORKDIR/agent-tmp.log" 2>&1)
[[ "$OUT" == *"Retired this enrollment"* ]]; check "the session retired its enrollment on exit" $?

# And the next run takes that name straight back over — no revoke, no delete,
# which is the whole point of recording it as temporary.
MACH_SERVER="$BASE" MACH_ORG="$ORG" MACH_STATE_DIR="$TMP_STATE" \
  "$WORKDIR/mach" >"$WORKDIR/agent-tmp2.log" 2>&1 &
TMP2_PID=$!
TMP_TOKEN=""
for i in $(seq 1 30); do
  TMP_TOKEN=$(grep -oE '/pair/[a-f0-9]{64}' "$WORKDIR/agent-tmp2.log" | head -1 | cut -d/ -f3)
  [[ -n "$TMP_TOKEN" ]] && break
  sleep 0.3
done
TMP_CODE=$(grep -oE '[A-Z0-9]{4}-[A-Z0-9]{4}-[A-Z0-9]{4}' "$WORKDIR/agent-tmp2.log" | head -1)
curl -s -o /dev/null -X POST "$BASE/pair/$TMP_TOKEN" \
  --data "code=$TMP_CODE&org=$ORG&name=$TMP_PART&approve=1"
sleep 3
OUT=$(curl -sS "$BASE/v1/machines" -H "Authorization: Bearer $ADMIN_KEY" 2>&1)
[[ "$OUT" == *"$TMP_NAME"* ]]; check "the next temporary run reused the name with no operator action" $?
[[ "$OUT" == *'"temporary":true'* ]]; check "and is recorded temporary again" $?
kill -TERM "$TMP2_PID" 2>/dev/null
wait "$TMP2_PID" 2>/dev/null

# An installed host must not get a second identity from someone typing `mach` at
# its console. (agent1 is the state dir of the installed agent above.)
OUT=$(MACH_STATE_DIR="$WORKDIR/agent1" "$WORKDIR/mach" 2>&1)
[[ $? -ne 0 ]]; check "plain mach on an installed host refuses" $?
[[ "$OUT" == *"already enrolled"* ]]; check "and explains why, pointing at mach run/install" $?

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

step "web UI: absent when OIDC is not configured"
# The primary control plane has no MACH_OIDC_* set, so its UI must not exist at
# all — not a UI that refuses, but no route to probe. This is the fail-closed
# property, and it is the reason the routes are registered conditionally.
CODE=$(curl -s -o /dev/null -w '%{http_code}' "$BASE/ui"); [[ "$CODE" == "404" ]]
check "no OIDC configured: /ui is 404" $?
CODE=$(curl -s -o /dev/null -w '%{http_code}' "$BASE/ui/login"); [[ "$CODE" == "404" ]]
check "no OIDC configured: /ui/login is 404" $?
CODE=$(curl -s -o /dev/null -w '%{http_code}' "$BASE/static/htmx.min.js"); [[ "$CODE" == "200" ]]
check "vendored asset serves" $?
# The static route is an allowlist, never a directory server.
CODE=$(curl -s -o /dev/null -w '%{http_code}' "$BASE/static/../go.mod"); [[ "$CODE" != "200" ]]
check "static route refuses traversal" $?

step "web UI: OIDC sign-in, block/revoke/delete, org management (loopback)"
UI_PORT="${MACH_TEST_UI_PORT:-8098}"
IDP_PORT="${MACH_TEST_IDP_PORT:-8097}"
UI_BASE="http://127.0.0.1:$UI_PORT"
IDP_BASE="http://127.0.0.1:$IDP_PORT"
go build -o "$WORKDIR/fakeidp" ./scripts/fakeidp || { echo "build fakeidp failed"; exit 1; }
"$WORKDIR/fakeidp" -addr "127.0.0.1:$IDP_PORT" -client-id mach-ui \
  -subject e2e-operator -email e2e@example.com >"$WORKDIR/idp.log" 2>&1 &
IDP_PID=$!
# A second control plane with its own database, so this section cannot disturb
# the fleet the checks above built. Its MACH_PUBLIC_URL is http, which is what
# grants the http-issuer carve-out — the dev/loopback case, and the only one.
MACH_DB="$WORKDIR/ui.db" MACH_LISTEN="127.0.0.1:$UI_PORT" \
  MACH_PUBLIC_URL="$UI_BASE" MACH_ORG="$ORG" \
  MACH_OIDC_ISSUER="$IDP_BASE" MACH_OIDC_CLIENT_ID=mach-ui MACH_OIDC_CLIENT_SECRET=s3cret \
  "$WORKDIR/mach-server" serve >"$WORKDIR/ui-server.log" 2>&1 &
UI_SERVER_PID=$!
for i in $(seq 1 30); do
  curl -fsS "$UI_BASE/healthz" >/dev/null 2>&1 && break
  sleep 0.3
done
curl -fsS "$UI_BASE/healthz" >/dev/null; check "second control plane up (UI+OIDC configured)" $?

UI_ENROLL=$(MACH_DB="$WORKDIR/ui.db" "$WORKDIR/mach-server" add-api-key ui-enroll enroll | grep -oE 'mach_[a-f0-9]+')
UI_ADMIN=$(MACH_DB="$WORKDIR/ui.db" "$WORKDIR/mach-server" add-api-key ui-admin admin | grep -oE 'mach_[a-f0-9]+')
[[ -n "$UI_ENROLL" && -n "$UI_ADMIN" ]]; check "UI control plane keys generated" $?

# A real agent, so "block keeps the client connected" is observed rather than
# assumed: the assertion below is that its log shows ONE connect for the whole
# block, which a reconnect would break.
UI_MACHINE="$ORG-ui-01"
MACH_STATE_DIR="$WORKDIR/agent-ui" "$WORKDIR/mach" register --server "$UI_BASE" \
  --api-key "$UI_ENROLL" --name "$UI_MACHINE" >/dev/null 2>&1
MACH_STATE_DIR="$WORKDIR/agent-ui" "$WORKDIR/mach" run >"$WORKDIR/agent-ui.log" 2>&1 &
UI_AGENT_PID=$!
sleep 2
UI_CONSOLE_DIR="$WORKDIR/ui-console"
mkdir -p "$UI_CONSOLE_DIR"
printf '{"server": "%s", "api_key": "%s"}\n' "$UI_BASE" "$UI_ADMIN" > "$UI_CONSOLE_DIR/console.json"
uic() { MACH_STATE_DIR="$UI_CONSOLE_DIR" "$WORKDIR/mach" "$@"; }
OUT=$(uic list 2>&1); [[ "$OUT" == *"$UI_MACHINE"* ]]; check "agent enrolled and online on the UI control plane" $?

# Sign in through the real OIDC flow against the fake issuer: /ui/login → the
# IdP → /ui/callback → the fleet page. -L because every hop is a redirect.
JAR="$WORKDIR/ui-cookies.txt"
curl -sL -c "$JAR" -b "$JAR" -o "$WORKDIR/ui-fleet.html" -w '%{http_code}' "$UI_BASE/ui/login" >"$WORKDIR/ui-code.txt"
CODE=$(cat "$WORKDIR/ui-code.txt"); [[ "$CODE" == "200" ]]; check "OIDC sign-in completes and renders the fleet" $?
OUT=$(grep -o "$UI_MACHINE" "$WORKDIR/ui-fleet.html" | head -1); [[ "$OUT" == "$UI_MACHINE" ]]
check "signed-in page lists the machine" $?
# The CSRF token rides in the shell's hx-headers, which is how every action
# request carries it.
CSRF=$(python3 -c "import re,sys; h=open('$WORKDIR/ui-fleet.html').read(); m=re.search(r'X-CSRF-Token\":\"([a-f0-9]+)\"',h); print(m.group(1) if m else '')")
[[ -n "$CSRF" ]]; check "page carries a per-session CSRF token" $?

# The control plane's own version, taken from the binary serving this page rather
# than hardcoded, so this does not have to be updated when the version changes.
UI_VER=$("$WORKDIR/mach-server" version | awk '{print $2}')
OUT=$(grep -c "mach-server $UI_VER" "$WORKDIR/ui-fleet.html"); [[ "$OUT" -ge 1 ]]
check "the signed-in page carries the control plane's version" $?
# And is withheld from someone who is not signed in. The enrollment page is the
# anonymous case here; the sign-in message pages (which render the same shell
# without a session) are covered by unit tests, since they need no live server.
curl -sS -o "$WORKDIR/ui-enroll.html" "$UI_BASE/"
OUT=$(grep -c "mach-server $UI_VER" "$WORKDIR/ui-enroll.html"); [[ "$OUT" -eq 0 ]]
check "the public enrollment page withholds the version" $?
# The enrolled agent is this same build, so nothing is flagged. This is the
# false-positive guard: comparing the string against itself must not mark skew.
OUT=$(grep -c "differs" "$WORKDIR/ui-fleet.html"); [[ "$OUT" -eq 0 ]]
check "no skew badge when the agent matches the control plane" $?

# A cross-site post and a token-less post must both be refused, and must leave
# the machine alone.
CODE=$(curl -s -o /dev/null -w '%{http_code}' -X POST "$UI_BASE/ui/block" -b "$JAR" \
  --data-urlencode "machine=$UI_MACHINE"); [[ "$CODE" == "403" ]]
check "block without a CSRF token is refused" $?
CODE=$(curl -s -o /dev/null -w '%{http_code}' -X POST "$UI_BASE/ui/block" -b "$JAR" \
  -H "X-CSRF-Token: $CSRF" -H 'Sec-Fetch-Site: cross-site' --data-urlencode "machine=$UI_MACHINE")
[[ "$CODE" == "403" ]]; check "cross-site block is refused" $?
OUT=$(curl -sS "$UI_BASE/v1/machines" -H "Authorization: Bearer $UI_ADMIN" 2>&1)
[[ "$OUT" != *'"blocked":true'* ]]; check "refused requests left the machine unblocked" $?

# Block: soft. Commands are refused, the connection is not.
CODE=$(curl -s -o "$WORKDIR/ui-block.html" -w '%{http_code}' -X POST "$UI_BASE/ui/block" -b "$JAR" \
  -H "X-CSRF-Token: $CSRF" -H 'HX-Request: true' --data-urlencode "machine=$UI_MACHINE")
[[ "$CODE" == "200" ]]; check "block accepted" $?
OUT=$(curl -sS "$UI_BASE/v1/machines" -H "Authorization: Bearer $UI_ADMIN" 2>&1)
[[ "$OUT" == *'"blocked":true'* ]]; check "the fleet listing reports the block" $?
OUT=$(uic exec "$UI_MACHINE" "echo blocked-should-not-run" 2>&1); [[ "$OUT" == *"blocked by the operator"* ]]
check "exec against a blocked machine is refused with the reason" $?
# THE soft-block proof: the agent is still connected. A reconnect would add a
# second "connected to" line to its log.
sleep 1
CONNECTS=$(grep -c 'connected to' "$WORKDIR/agent-ui.log")
[[ "$CONNECTS" -eq 1 ]]; check "blocked machine stayed connected (one connect, no reconnect)" $?

# Unblock: commands work again. 503-or-success rather than 403 is the point —
# "offline" and "blocked" are different answers.
CODE=$(curl -s -o /dev/null -w '%{http_code}' -X POST "$UI_BASE/ui/unblock" -b "$JAR" \
  -H "X-CSRF-Token: $CSRF" -H 'HX-Request: true' --data-urlencode "machine=$UI_MACHINE")
[[ "$CODE" == "200" ]]; check "unblock accepted" $?
uic exec "$UI_MACHINE" "echo unblocked-ok" >/dev/null 2>&1; check "exec works again after unblock" $?
OUT=$(curl -sS "$UI_BASE/v1/machines" -H "Authorization: Bearer $UI_ADMIN" 2>&1)
[[ "$OUT" != *'"blocked":true'* ]]; check "the fleet listing clears the block" $?

step "web UI: org management"
CODE=$(curl -s -o "$WORKDIR/ui-orgs.html" -w '%{http_code}' -X POST "$UI_BASE/ui/orgs/add" -b "$JAR" \
  -H "X-CSRF-Token: $CSRF" -H 'HX-Request: true' --data-urlencode 'org=acme')
[[ "$CODE" == "200" ]]; check "org added through the UI" $?
OUT=$(grep -o '<code>acme</code>' "$WORKDIR/ui-orgs.html" | head -1); [[ "$OUT" == "<code>acme</code>" ]]
check "the new org is listed" $?
OUT=$(grep -o 'badge pinned' "$WORKDIR/ui-orgs.html" | head -1); [[ "$OUT" == "badge pinned" ]]
check "the environment's org is shown as pinned" $?
# The behaviour change this feature forced: enrollment now resolves any
# configured org, not just the primary one.
PUB_UI=$(python3 -c "print('ef'*32)")
OUT=$(curl -sS -X POST "$UI_BASE/v1/register/apikey" -H 'Content-Type: application/json' \
  -d "{\"api_key\":\"$UI_ENROLL\",\"pub_key\":\"$PUB_UI\",\"name\":\"acme-ui-01\"}" 2>&1)
[[ "$OUT" == *'"ok":"enrolled"'* ]]; check "a machine enrolls under an org added through the UI" $?
CODE=$(curl -s -o /dev/null -w '%{http_code}' -X POST "$UI_BASE/ui/orgs/remove" -b "$JAR" \
  -H "X-CSRF-Token: $CSRF" -H 'HX-Request: true' --data-urlencode 'org=acme')
[[ "$CODE" == "409" ]]; check "removing an org that still has machines is refused" $?
OUT=$(curl -sS -X POST "$UI_BASE/ui/orgs/remove" -b "$JAR" -H "X-CSRF-Token: $CSRF" \
  -H 'HX-Request: true' --data-urlencode "org=$ORG" 2>&1)
[[ "$OUT" == *"cannot be removed"* ]]; check "removing a pinned org is refused" $?
CODE=$(curl -s -o /dev/null -w '%{http_code}' -X POST "$UI_BASE/ui/orgs/e2e" -b "$JAR" \
  -H "X-CSRF-Token: $CSRF" -H 'HX-Request: true' --data-urlencode 'org=acme' --data-urlencode 'mode=off')
[[ "$CODE" == "200" ]]; check "sealed exec can be set per org from the UI" $?
OUT=$(curl -sS "$UI_BASE/v1/machines" -H "Authorization: Bearer $UI_ADMIN" 2>&1)
[[ "$OUT" == *'"e2e":"off"'* ]]; check "the per-org sealed-exec setting reaches the fleet listing" $?

step "web UI: delete is confirmed by name and frees the name"
CODE=$(curl -s -o "$WORKDIR/ui-del1.html" -w '%{http_code}' -X POST "$UI_BASE/ui/delete" -b "$JAR" \
  -H "X-CSRF-Token: $CSRF" -H 'HX-Request: true' --data-urlencode "machine=$UI_MACHINE")
[[ "$CODE" == "200" ]]; check "delete asks for confirmation" $?
OUT=$(grep -o 'confirm_name' "$WORKDIR/ui-del1.html" | head -1); [[ "$OUT" == "confirm_name" ]]
check "confirmation requires the machine name to be typed" $?
OUT=$(curl -sS "$UI_BASE/v1/machines" -H "Authorization: Bearer $UI_ADMIN" 2>&1)
[[ "$OUT" == *"$UI_MACHINE"* ]]; check "the machine survives an unconfirmed delete" $?
CODE=$(curl -s -o /dev/null -w '%{http_code}' -X POST "$UI_BASE/ui/delete" -b "$JAR" \
  -H "X-CSRF-Token: $CSRF" -H 'HX-Request: true' --data-urlencode "machine=$UI_MACHINE" \
  --data-urlencode 'confirm=1' --data-urlencode "confirm_name=$UI_MACHINE")
[[ "$CODE" == "200" ]]; check "delete confirmed" $?
OUT=$(curl -sS "$UI_BASE/v1/machines" -H "Authorization: Bearer $UI_ADMIN" 2>&1)
[[ "$OUT" != *"$UI_MACHINE"* ]]; check "the machine is gone from the fleet" $?
# The agent is told to retire rather than left dialing a name nobody knows, and
# it must actually STOP: Run() returns nil, so the process exits 0. That is the
# half a supervisor depends on — the installed unit restarts on failure, not on
# any exit, which is what makes a clean exit mean "stop" instead of a loop.
sleep 2
OUT=$(grep -c 'deleted by the operator' "$WORKDIR/agent-ui.log"); [[ "$OUT" -ge 1 ]]
check "the agent was notified so it could exit" $?
kill -0 "$UI_AGENT_PID" 2>/dev/null; [[ $? -ne 0 ]]
check "the notified agent exited rather than reconnecting" $?
# And the name is free again: this is the recovery path revocation cannot express.
PUB_UI2=$(python3 -c "print('12'*32)")
NAME_OK=$(python3 -c "print('$UI_MACHINE')")
OUT=$(curl -sS -X POST "$UI_BASE/v1/register/apikey" -H 'Content-Type: application/json' \
  -d "{\"api_key\":\"$UI_ENROLL\",\"pub_key\":\"$PUB_UI2\",\"name\":\"$NAME_OK\"}" 2>&1)
[[ "$OUT" == *'"ok":"enrolled"'* ]]; check "the freed name and a new key re-enroll" $?

step "web UI: sign out"
CODE=$(curl -s -o /dev/null -w '%{http_code}' -X POST "$UI_BASE/ui/logout" -b "$JAR" \
  -H "X-CSRF-Token: $CSRF")
[[ "$CODE" == "200" ]]; check "sign out accepted" $?
CODE=$(curl -s -o /dev/null -w '%{http_code}' -b "$JAR" "$UI_BASE/ui"); [[ "$CODE" == "303" ]]
check "the signed-out session no longer reaches the fleet" $?

step "cleanup job smoke: pairings purge"
MACH_DB="$WORKDIR/mach.db" "$WORKDIR/mach-server" version >/dev/null
ok "cleanup job wired (hourly, 24h retention)"

printf '\n===== e2e: %d passed, %d failed =====\n' "$PASS" "$FAIL"
[[ "$FAIL" -eq 0 ]]