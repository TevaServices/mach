#!/bin/sh
# localdev.sh — a full mach deployment on this one host: a control plane, and
# this machine enrolled as an agent of it.
#
# Everything it creates lives under data/local/, which the repo's `/data/`
# gitignore rule already excludes. That isolation is the point: this cannot
# touch a real deployment's database, and it cannot touch your own ~/.mach,
# because both sides are given a state dir inside the playground.
#
# Nothing here installs anything. `mach install` would register launchd/systemd
# so the agent survives a reboot; this runs the agent as a plain background
# process instead, which is the right shape for something you will start and
# stop while working on the code.
#
#   scripts/localdev.sh up         build, start the control plane, enroll this host, start the agent
#   scripts/localdev.sh server     build and start the control plane alone — nothing enrolled
#   scripts/localdev.sh enroll     enroll this host by hand, through the QR / challenge-code flow
#   scripts/localdev.sh temp       run a TEMPORARY agent against the playground (bare mach, in-memory)
#   scripts/localdev.sh reset      stop everything and wipe the playground back to a fresh install
#   scripts/localdev.sh down       stop the agent, the control plane and the identity provider
#   scripts/localdev.sh status     the fleet listing, through the console CLI
#   scripts/localdev.sh logs       follow the control plane's, the agent's and the provider's logs
#   scripts/localdev.sh env        print the exports that point the CLI at the playground
#   scripts/localdev.sh mach …     run the mach CLI against the playground
#   scripts/localdev.sh foreground run the control plane in the foreground
#
# Tuning: MACH_LOCAL_PORT (default 8181), MACH_LOCAL_DIR, MACH_LOCAL_ORG,
# MACH_LOCAL_HOST (the address your phone uses — see below), MACH_LOCAL_IDP_PORT.
#
# The host, and why it is one variable
# ------------------------------------
# MACH_LOCAL_HOST is the address a PHONE should use to reach the control plane.
# It defaults to `auto`: the IPv4 address of the interface carrying the default
# route, which is what a phone on the same network reaches. Everything else is
# derived from it — the server binds all interfaces so that address is actually
# reachable, and the public URL is built from it — so the two can never disagree.
#
#   MACH_LOCAL_HOST=auto                 the LAN address (default)
#   MACH_LOCAL_HOST=127.0.0.1            loopback only, on purpose
#   MACH_LOCAL_HOST=bryans-mac.local     a name, if mDNS resolves it for you
#
# The QR is the reason this is one variable and not two. The URL it encodes is
# built by the CLIENT from the server URL it was given (agent/register.go), not
# by the control plane from MACH_PUBLIC_URL — so whichever command runs `mach
# register` decides what the phone will be told. `local:server` and `local:enroll`
# are separate invocations, so the host each resolved is recorded in
# data/local/host and reused: `local:enroll` with no environment at all uses the
# address `local:server` was started with, and the two are compared rather than
# assumed to agree.
#
# `mach` is the interesting subcommand — everything else exists to make it work:
#
#   scripts/localdev.sh mach list
#   scripts/localdev.sh mach exec local-<host> 'uname -a'
#   scripts/localdev.sh mach console local-<host>
#
# Enrolling by hand
# -----------------
# `server` deliberately mints no keys and enrolls nothing, so the pair page is
# the only way in and the QR flow is what you actually exercise:
#
#   mise run local:server     # control plane only
#   mise run local:enroll     # prints the QR and the challenge code, then waits
#
# The QR encodes the address a phone should use, which by default is this
# machine's LAN address — so scanning it with a phone just works, with no flags.
# To keep the control plane on this machine instead, say so on the command that
# STARTS it (and note that `local:enroll` then reuses that answer):
#
#   MACH_LOCAL_HOST=127.0.0.1 mise run local:server
#   MACH_LOCAL_HOST=127.0.0.1 mise run local:enroll
#
# Either way the challenge code is printed on this console and typed on the
# page — the QR alone grants nothing. Once enrolled, `mise run local:up` sees
# the enrollment and finishes the job (start the agent, configure the console).
#
# The web UI is on here, which a real control plane needs MACH_OIDC_* for. This
# script supplies it by running scripts/fakeidp — the same test-only identity
# provider the e2e suite uses. That provider is bound to LOOPBACK, deliberately:
# it authenticates nobody, so widening it to the network would let anyone on it
# sign in and manage the fleet. The consequence is that the UI answers on the
# LAN (the control plane is bound to all interfaces) but only a browser on this
# machine can complete a sign-in. That is the intended trade, not a fault.
#
# mise cannot forward arguments to a task (its `arg()` helpers are deprecated in
# the version this repo pins, and extra args are appended to the task script's
# last line, where a trailing comment swallows them), so the mise tasks are the
# argument-free verbs and this script is the one that takes arguments.

set -eu

ROOT=$(cd "$(dirname "$0")/.." && pwd)

DIR=${MACH_LOCAL_DIR:-$ROOT/data/local}
PORT=${MACH_LOCAL_PORT:-8181}
ORG=${MACH_LOCAL_ORG:-local}
# A relative MACH_LOCAL_DIR would slip past reset's guard below, which decides
# whether a path is inside the repo by matching on its prefix, so it is made
# absolute once, here.
case "$DIR" in
/*) : ;;
*) DIR="$PWD/$DIR" ;;
esac
# BASE is how this machine reaches the playground, and it stays loopback on
# purpose: the health checks, the console's own config and the agent all want an
# address that works whatever the server is bound to. HOST, LISTEN and PUBLIC_URL
# — what the phone is told, what the server binds, and what the UI's redirects
# are built from — are derived together by resolve_host below, so they cannot
# drift apart or be half-set.
BASE="http://127.0.0.1:$PORT"
HOST_REQ=${MACH_LOCAL_HOST:-}
HOST=""
LISTEN=""
PUBLIC_URL=""

# The fake identity provider the UI needs (see the header). Bound to loopback,
# and the OIDC values below are what it mints — a fixed, well-known set of test
# credentials, which is the point: nothing here is a secret and nothing here
# should ever be pointed at a real deployment.
IDP_PORT=${MACH_LOCAL_IDP_PORT:-8190}
IDP_BASE="http://127.0.0.1:$IDP_PORT"
OIDC_CLIENT_ID=mach-ui
OIDC_CLIENT_SECRET=mach-local-dev-secret
OIDC_SUBJECT=local-operator
OIDC_EMAIL=operator@local.test
OIDC_DOMAIN=local.test

SERVER_DIR="$DIR/server"
AGENT_DIR="$DIR/agent"
CONSOLE_DIR="$DIR/console"
KEYS_DIR="$DIR/keys"
BIN_MACH="$ROOT/bin/mach"
BIN_SERVER="$ROOT/bin/mach-server"

log() { printf '[local] %s\n' "$*"; }
warn() { printf '[local] %s\n' "$*" >&2; }
die() { printf '[local] %s\n' "$*" >&2; exit 1; }

# is_loopback reports whether the resolved host is this machine only. It is a
# whole-word match, not the `[ "$PUBLIC_URL" = "$BASE" ]` string compare this
# used to be: `localhost`, `::1` and a trailing slash are all loopback too, and
# the old test quietly missed them.
is_loopback() {
	case "$HOST" in
	127.0.0.1 | localhost | ::1 | "[::1]") return 0 ;;
	esac
	return 1
}

# detect_host finds the address a phone on this network would use: the IPv4 of
# the interface carrying the default route. Deliberately the default route and
# not the first non-loopback address found, because a machine with a VPN or a
# Tailscale interface has several and enumeration would as happily hand back the
# wrong one. Prints nothing when it cannot tell, and the caller says so.
detect_host() {
	ifc=""
	ip=""
	if command -v route >/dev/null 2>&1 && command -v ipconfig >/dev/null 2>&1; then
		ifc=$(route -n get default 2>/dev/null | awk '/interface:/{print $2; exit}')
		[ -n "$ifc" ] && ip=$(ipconfig getifaddr "$ifc" 2>/dev/null || true)
	fi
	if [ -z "$ip" ] && command -v ip >/dev/null 2>&1; then
		ifc=$(ip route show default 2>/dev/null | awk '/^default/{print $5; exit}')
		[ -n "$ifc" ] && ip=$(ip -4 addr show dev "$ifc" 2>/dev/null | awk '/inet /{print $2; exit}' | cut -d/ -f1)
	fi
	printf '%s' "$ip"
}

# resolve_host fills in HOST, LISTEN and PUBLIC_URL. The order is the fix for the
# bug this replaced: what the caller asked for, else what the running control
# plane was actually started with, else detect. Asking for something different
# from a control plane that is already up is an error rather than a silent
# override, because the QR and the bind would otherwise disagree.
resolve_host() {
	[ -n "$HOST" ] && return 0
	if [ -n "$HOST_REQ" ]; then
		HOST=$HOST_REQ
	elif [ -f "$DIR/host" ] && pid_alive "$DIR/server.pid"; then
		# The record is believed only while it describes something running, so a
		# control plane that died without `down` cannot pin a stale address.
		HOST=$(cat "$DIR/host")
	else
		HOST=$(detect_host)
		if [ -z "$HOST" ]; then
			die "could not work out this machine's LAN address. Set it yourself: MACH_LOCAL_HOST=<your address>, or MACH_LOCAL_HOST=127.0.0.1 to keep the playground on this machine."
		fi
	fi
	# Bind all interfaces so that HOST is actually reachable; a loopback HOST is
	# the one case where binding everything would expose it for nothing.
	if is_loopback; then
		LISTEN="127.0.0.1:$PORT"
	else
		LISTEN="0.0.0.0:$PORT"
	fi
	PUBLIC_URL="http://$HOST:$PORT"
}

# refuse_host_change is the guard both verbs share: a control plane already
# running for one address, and a command asking for another, is the mismatch that
# used to produce a QR for an address nothing was listening on.
refuse_host_change() {
	[ -f "$DIR/host" ] || return 0
	recorded=$(cat "$DIR/host")
	[ "$recorded" = "$HOST" ] && return 0
	die "the control plane here was started for $recorded, but this command is for $HOST. Run 'mise run local:down' first and start it again with the same MACH_LOCAL_HOST."
}

# machine_name is this host's fleet name, org-prefixed as every mach name must
# be. store.ValidOrgName allows only [A-Za-z0-9-] in the label after the prefix,
# and a hostname is full of characters that are not that, so it is normalized
# rather than passed through.
machine_name() {
	name=$(hostname -s 2>/dev/null || hostname)
	name=$(printf '%s' "$name" | tr '[:upper:]' '[:lower:]' | sed 's/[^a-z0-9]/-/g; s/--*/-/g; s/^-//; s/-$//' | cut -c1-40)
	[ -n "$name" ] || name=host
	printf '%s-%s' "$ORG" "$name"
}

pid_alive() {
	[ -f "$1" ] && kill -0 "$(cat "$1")" 2>/dev/null
}

# phys canonicalizes a path that need not exist yet: resolve the deepest
# ancestor that does with `cd`/`pwd -P` (which also follows symlinks) and
# re-append the part that does not. reset's guard compares canonical paths
# because a textual prefix match is not containment — "$ROOT/../elsewhere"
# starts with "$ROOT/" and is not inside it.
phys() {
	p=$1
	tail=""
	while [ ! -d "$p" ] && [ "$p" != "/" ] && [ "$p" != "." ]; do
		tail=$(basename "$p")${tail:+/$tail}
		p=$(dirname "$p")
	done
	printf '%s%s\n' "$(cd "$p" 2>/dev/null && pwd -P)" "${tail:+/$tail}"
}

# ensure_playground creates the playground directory and stamps it. The marker
# is what lets reset tell this directory apart from any other path a typo
# produced: containment alone is not enough, because a mistyped MACH_LOCAL_DIR
# can be perfectly inside the repo and still be a source directory.
ensure_playground() {
	mkdir -p "$DIR"
	: >"$DIR/.playground"
}

# need_bins builds unless bin/ is already newer than every source file. Testing
# "does the binary exist" instead would be wrong in exactly the case that
# matters: you edit a file, run `up`, and get the previous build back.
need_bins() {
	if [ -x "$BIN_MACH" ] && [ -x "$BIN_SERVER" ]; then
		newer=$(find "$ROOT/cmd" "$ROOT/internal" "$ROOT/go.mod" "$ROOT/go.sum" \
			-newer "$BIN_MACH" 2>/dev/null || true)
		[ -z "$newer" ] && return 0
	fi
	log "building bin/mach and bin/mach-server"
	(cd "$ROOT" && mise run build)
}

# need_idp_bin builds scripts/fakeidp into the playground, by the same staleness
# rule. It is not part of `mise run build` because it is not a shipped binary.
need_idp_bin() {
	mkdir -p "$DIR"
	if [ -x "$DIR/fakeidp" ]; then
		newer=$(find "$ROOT/scripts/fakeidp" -name '*.go' -newer "$DIR/fakeidp" 2>/dev/null || true)
		[ -z "$newer" ] && return 0
	fi
	log "building the fake identity provider (scripts/fakeidp)"
	(cd "$ROOT" && CGO_ENABLED=0 go build -o "$DIR/fakeidp" ./scripts/fakeidp) ||
		die "could not build scripts/fakeidp"
}

# stop_idp is shared by down and the foreground verb's trap.
stop_idp() {
	if pid_alive "$DIR/idp.pid"; then
		kill "$(cat "$DIR/idp.pid")" 2>/dev/null || true
		rm -f "$DIR/idp.pid"
	fi
}

# start_idp runs the test-only identity provider the UI needs. It is bound to
# loopback on purpose and the banner says so: it authenticates nobody, so
# widening it would let anyone who can reach the port sign in and manage the
# fleet. Loopback is also what makes the UI safe to expose on the LAN — a remote
# browser is redirected to 127.0.0.1, which is its own machine, and any code it
# gets there means nothing to this control plane, whose /ui/callback exchanges
# against THIS provider and only mints a token for a code it issued itself.
start_idp() {
	need_idp_bin
	if pid_alive "$DIR/idp.pid"; then
		return 0
	fi
	# Same reasoning as the control plane's check below: answering with no
	# pidfile behind it means a stranger owns the port, and starting a second one
	# would fail to bind while the health check passed against the stranger.
	if curl -fsS "$IDP_BASE/.well-known/openid-configuration" >/dev/null 2>&1; then
		die "$IDP_BASE is already served by a process that is not $DIR/idp.pid — find it with: lsof -nP -iTCP:$IDP_PORT -sTCP:LISTEN"
	fi
	log "starting the fake identity provider on $IDP_BASE (FOR TESTS ONLY — it authenticates nobody)"
	rm -f "$DIR/idp.pid"
	# A direct command with no shell in between, so $! is the provider's own pid.
	nohup "$DIR/fakeidp" -addr "127.0.0.1:$IDP_PORT" -client-id "$OIDC_CLIENT_ID" \
		-subject "$OIDC_SUBJECT" -email "$OIDC_EMAIL" >>"$DIR/idp.log" 2>&1 &
	echo $! >"$DIR/idp.pid"
}

# server_run applies the control plane's environment to whatever it is given, so
# the background and foreground paths below cannot drift apart. Passing it as a
# prefix command rather than exporting keeps the playground's settings out of
# the caller's shell.
#
# The MACH_OIDC_* set is the whole of what turns the UI on: issuer, client id and
# client secret together, which is exactly the configuration a real deployment
# provides and exactly what loadUIConfig requires — no gate is bypassed and a
# production control plane with none of these still serves no /ui route. The
# issuer is http and so is MACH_PUBLIC_URL, which is what grants the loopback
# issuer its carve-out; MACH_OIDC_REDIRECT_URL is left unset so it derives to
# PUBLIC_URL + /ui/callback.
server_run() {
	MACH_DB="$SERVER_DIR/mach.db" \
	MACH_SERVER_KEY="$SERVER_DIR/mach.db.key" \
	MACH_LISTEN="$LISTEN" \
	MACH_PUBLIC_URL="$PUBLIC_URL" \
	MACH_ORG="$ORG" \
	MACH_OIDC_ISSUER="$IDP_BASE" \
	MACH_OIDC_CLIENT_ID="$OIDC_CLIENT_ID" \
	MACH_OIDC_CLIENT_SECRET="$OIDC_CLIENT_SECRET" \
	MACH_OIDC_ALLOWED_DOMAINS="$OIDC_DOMAIN" \
		"$@"
}

start_server() {
	mkdir -p "$DIR"
	resolve_host
	if pid_alive "$DIR/server.pid"; then
		refuse_host_change
		log "control plane already running (pid $(cat "$DIR/server.pid"))"
		# Started in both branches, so re-running `up` against a live control
		# plane also heals a provider that is not up.
		start_idp
		return 0
	fi
	start_idp
	# A healthz that answers with no live pidfile behind it means something else
	# owns the port: another playground, or a stray server from a run whose
	# pidfile was lost. Starting a second one would fail to bind, and the health
	# check below would then pass against the stranger — a playground that looks
	# up while silently running the wrong server. Refuse instead.
	if curl -fsS "$BASE/healthz" >/dev/null 2>&1; then
		die "$BASE is already served by a process that is not $DIR/server.pid — find it with: lsof -nP -iTCP:$PORT -sTCP:LISTEN"
	fi
	log "starting the control plane on $BASE (org $ORG, bound to $LISTEN)"
	# The record of what this control plane was started for. `local:enroll` reads
	# it so the QR cannot name a different address than the one bound here — the
	# whole reason the phone path used to encode 127.0.0.1.
	printf '%s\n' "$HOST" >"$DIR/host"
	# The pid must be written by the process that goes on to serve, and written
	# before the exec that turns it into the server. Backgrounding server_run
	# itself does not achieve that: a shell function runs in a subshell, so $!
	# is the subshell's pid, which is already gone by the time you try to kill
	# it. The real server is left orphaned and holding the port while the
	# pidfile points at nothing, and every later `up` fails to bind while the
	# health check passes against the stray.
	rm -f "$DIR/server.pid"
	server_run nohup sh -c 'echo $$ >"$1"; shift; exec "$@"' localdev "$DIR/server.pid" "$BIN_SERVER" serve >>"$DIR/server.log" 2>&1 &
}

wait_health() {
	i=0
	while [ "$i" -lt 100 ]; do
		if curl -fsS "$BASE/healthz" >/dev/null 2>&1; then return 0; fi
		# A dead process will never become healthy, so say why now instead of
		# waiting out the full ten seconds. The pidfile is written by the server
		# itself a moment after the fork, so there is nothing to judge until it
		# exists.
		if [ -f "$DIR/server.pid" ] && ! pid_alive "$DIR/server.pid"; then
			die "the control plane exited — see $DIR/server.log"
		fi
		sleep 0.1
		i=$((i + 1))
	done
	die "the control plane never became healthy — see $DIR/server.log"
}

# mint_keys writes two keys with the least scope each job can work with: the
# agent needs only `enroll`, and the console needs `exec:*`. Re-running `up`
# reuses what is on disk rather than piling up keys in the database.
mint_keys() {
	if [ -s "$KEYS_DIR/agent.key" ] && [ -s "$KEYS_DIR/console.key" ]; then return 0; fi
	mkdir -p "$KEYS_DIR"
	log "minting API keys (enroll for the agent, exec:* for the console)"
	a=$(MACH_DB="$SERVER_DIR/mach.db" "$BIN_SERVER" add-api-key local-agent-enroll enroll | grep -oE 'mach_[a-f0-9]+' || true)
	c=$(MACH_DB="$SERVER_DIR/mach.db" "$BIN_SERVER" add-api-key local-console 'exec:*' | grep -oE 'mach_[a-f0-9]+' || true)
	[ -n "$a" ] && [ -n "$c" ] || die "could not mint API keys"
	printf '%s\n' "$a" >"$KEYS_DIR/agent.key"
	printf '%s\n' "$c" >"$KEYS_DIR/console.key"
	chmod 600 "$KEYS_DIR/agent.key" "$KEYS_DIR/console.key"
}

enroll_agent() {
	[ -f "$AGENT_DIR/config.json" ] && { log "this host is already enrolled"; return 0; }
	log "enrolling this host as $(machine_name)"
	if ! MACH_STATE_DIR="$AGENT_DIR" "$BIN_MACH" register \
		--server "$BASE" --api-key "$(cat "$KEYS_DIR/agent.key")" \
		--org "$ORG" --name "$(machine_name)" >>"$DIR/enroll.log" 2>&1; then
		cat "$DIR/enroll.log" >&2
		die "enrollment failed"
	fi
}

start_agent() {
	if pid_alive "$DIR/agent.pid"; then
		log "agent already running (pid $(cat "$DIR/agent.pid"))"
		return 0
	fi
	log "starting the agent"
	# This one needs no sh -c trick: it is a direct command with an environment
	# prefix, so $! is already the agent's own pid (nohup execs into it).
	rm -f "$DIR/agent.pid"
	MACH_STATE_DIR="$AGENT_DIR" nohup "$BIN_MACH" run >>"$DIR/agent.log" 2>&1 &
	echo $! >"$DIR/agent.pid"
}

write_console() {
	mkdir -p "$CONSOLE_DIR"
	printf '{"server": "%s", "api_key": "%s"}\n' "$BASE" "$(cat "$KEYS_DIR/console.key")" >"$CONSOLE_DIR/console.json"
	chmod 600 "$CONSOLE_DIR/console.json"
}

write_env() {
	cat >"$DIR/env.sh" <<EOF
# Written by scripts/localdev.sh — source it to point the mach CLI at the
# playground, e.g.:
#
#   . data/local/env.sh && bin/mach exec $(machine_name) 'uname -a'
#
# MACH_STATE_DIR is the console's state dir, not the agent's: it is where
# console.json (and the E2E key pins) live. Pointing it at the agent's would
# make the CLI try to be an agent.
export MACH_STATE_DIR="$CONSOLE_DIR"
# MACH_SERVER is the AGENT side's default server URL, so it is the public one:
# a 'mach register' run from a shell that sourced this file should print a QR a
# phone can scan. The console ignores it — it reads console.json, which points
# at loopback because that is what this machine uses.
export MACH_SERVER="$PUBLIC_URL"
EOF
}

wait_online() {
	i=0
	while [ "$i" -lt 150 ]; do
		# Captured rather than piped into `grep -q`: an early-exiting grep closes
		# the pipe, and under a pipefail caller that reports the writer's SIGPIPE
		# as a failure. AGENTS.md records this trap.
		out=$(MACH_STATE_DIR="$CONSOLE_DIR" "$BIN_MACH" list 2>/dev/null || true)
		case "$out" in *online*) return 0 ;; esac
		sleep 0.1
		i=$((i + 1))
	done
	die "the agent never came online — see $DIR/agent.log"
}

# log_endpoints prints the addresses that matter once the control plane is up.
# The UI's sign-in redirect and its session cookie are both built from
# MACH_PUBLIC_URL, so the UI has to be opened there and not at loopback — which
# is a thing the reader would otherwise have to work out from the source.
log_endpoints() {
	echo
	if is_loopback; then
		warn "the control plane is bound to loopback only, so a phone cannot reach it."
		warn "  for a phone:  MACH_LOCAL_HOST=auto mise run local:down && mise run local:server"
		log "web UI:   $PUBLIC_URL/ui"
	else
		# The redirect and the session cookie are both built from the public URL, so
		# opening the loopback address would land the browser on the LAN host the
		# moment the callback sets the cookie. Name the URL that works throughout.
		log "reachable from your phone at $PUBLIC_URL (bound to all interfaces, not loopback)"
		log "  keep it on this machine:  MACH_LOCAL_HOST=127.0.0.1"
		log "web UI:   $PUBLIC_URL/ui   (open this URL, not 127.0.0.1 — the sign-in redirect and the session cookie are built from it)"
	fi
	log "fake idp: $IDP_BASE  (FOR TESTS ONLY — it authenticates nobody)"
	log "  signing in works from this machine only: the provider is on loopback, so a"
	log "  browser anywhere else has nothing to complete the token exchange against."
}

# cmd_server starts the control plane and stops there. It mints no key and
# enrolls nothing on purpose: those would make the pair page look optional, and
# the whole point of this mode is to exercise enrollment as the only way in.
cmd_server() {
	need_bins
	ensure_playground
	mkdir -p "$SERVER_DIR"
	start_server
	wait_health
	log_endpoints
	echo
	log "nothing is enrolled yet. enroll this host:  mise run local:enroll"
	log "  follow the log:    tail -f $DIR/server.log"
	log "  stop:              mise run local:down"
}

# cmd_enroll runs the QR / challenge-code flow in the foreground, because the
# QR and the challenge code have to be readable while it waits for approval.
cmd_enroll() {
	curl -fsS "$BASE/healthz" >/dev/null 2>&1 ||
		die "nothing is serving $BASE — start one with: mise run local:server"
	if [ -f "$AGENT_DIR/config.json" ]; then
		die "$AGENT_DIR is already enrolled — 'mise run local:reset' gives you a fresh install to enroll into"
	fi
	ensure_playground
	mkdir -p "$AGENT_DIR"
	# The host comes from the running control plane's own record, so this cannot
	# describe a different address than the one actually bound. Saying so before
	# the QR is printed keeps the two together at the moment they matter.
	resolve_host
	refuse_host_change
	echo
	if is_loopback; then
		warn "the QR will encode $PUBLIC_URL, which is loopback — open it in a browser on this machine, not on a phone."
	else
		log "the QR will encode $PUBLIC_URL — the address this control plane is bound to, and one a phone on this network can reach."
	fi
	echo
	MACH_STATE_DIR="$AGENT_DIR" "$BIN_MACH" register --server "$PUBLIC_URL" --org "$ORG"
	echo
	log "enrolled. finish the setup — start the agent and configure the console — with:"
	log "  mise run local:up    (it sees this enrollment and skips straight to running)"
}

# cmd_temp runs a TEMPORARY agent session in the foreground — bare `mach`, the
# mode whose identity exists only in memory. It pairs through the same QR /
# challenge-code flow as `enroll` (approval is operator-gated by design: the
# code is printed here and typed on the pair page), is recorded on the control
# plane as temporary, traces every command it is asked to run onto this console,
# and retires its enrollment when it ends. Ctrl-C is a real shutdown, and
# running it again takes the same machine name straight back over.
cmd_temp() {
	need_bins
	curl -fsS "$BASE/healthz" >/dev/null 2>&1 ||
		die "nothing is serving $BASE — start one with: mise run local:server"
	ensure_playground
	# Its own state dir, deliberately not the enrolled agent's. A temporary
	# session writes nothing to its state dir, but bare `mach` refuses on a
	# state dir that IS enrolled — so pointing this at AGENT_DIR would turn the
	# whole verb into that refusal the moment `local:up` has run.
	TEMP_STATE="$DIR/temp-agent"
	mkdir -p "$TEMP_STATE"
	# The host comes from the running control plane's own record, as in enroll:
	# the QR's URL is built by the client from the server URL it was handed, so
	# this is the moment the two are kept together.
	resolve_host
	refuse_host_change
	echo
	if is_loopback; then
		warn "the QR will encode $PUBLIC_URL, which is loopback — open it in a browser on this machine, not on a phone."
	else
		log "the QR will encode $PUBLIC_URL — the address this control plane is bound to, and one a phone on this network can reach."
	fi
	log "approve on the pair page with the challenge code printed below. The page"
	log "suggests a name from this hostname — if 'local:up' has run here it is taken"
	log "($(machine_name)); pick another one on the page."
	echo
	# stdin from /dev/null answers the two bracketed prompts with their
	# environment defaults (MACH_SERVER / MACH_ORG) instead of pausing on an
	# Enter the flow does not need: the challenge code is typed on the pair
	# page, never on this console.
	MACH_STATE_DIR="$TEMP_STATE" MACH_SERVER="$PUBLIC_URL" MACH_ORG="$ORG" \
		"$BIN_MACH" </dev/null
	echo
	log "temporary session ended. If it exited cleanly it retired its enrollment;"
	log "either way the next run re-enrolls under the same name with no operator action."
}

cmd_reset() {
	# Both guards run before anything is stopped or deleted, because
	# MACH_LOCAL_DIR is caller-controlled and the next step is `rm -rf`.
	#
	# Containment first, on canonical paths — a prefix match on the raw string
	# would accept "$ROOT/../elsewhere". This catches a path that is outside the
	# repo; the marker below catches one that is inside it but is not ours.
	dirp=$(phys "$DIR")
	case "$dirp" in
	"$(phys "$ROOT")"/*) : ;;
	*) die "refusing to reset $DIR — it resolves to $dirp, which is not inside $ROOT. Remove it yourself if that is what you meant." ;;
	esac
	if [ -e "$DIR" ] && [ ! -f "$DIR/.playground" ]; then
		die "refusing to reset $DIR — it exists but carries no .playground marker, so it was not created by this script"
	fi
	cmd_down
	log "removing $DIR (database, server identity key, agent identity, console config, logs)"
	rm -rf "$DIR"
	log "reset: fresh install. bin/ is kept — 'up' rebuilds it if the tree is newer."
}

cmd_up() {
	need_bins
	ensure_playground
	mkdir -p "$SERVER_DIR" "$AGENT_DIR"
	start_server
	wait_health
	mint_keys
	enroll_agent
	start_agent
	write_console
	write_env
	wait_online
	echo
	log "up: $(machine_name) is enrolled and online at $BASE"
	log_endpoints
	echo
	MACH_STATE_DIR="$CONSOLE_DIR" "$BIN_MACH" list
	echo
	log "run commands with:  scripts/localdev.sh mach exec $(machine_name) 'uname -a'"
	log "or in your shell:   . $DIR/env.sh"
}

cmd_down() {
	# The agent first, so the control plane is still up to notice it leave.
	for p in agent server; do
		if pid_alive "$DIR/$p.pid"; then
			log "stopping $p (pid $(cat "$DIR/$p.pid"))"
			kill "$(cat "$DIR/$p.pid")" 2>/dev/null || true
			rm -f "$DIR/$p.pid"
		fi
	done
	stop_idp
	# The record is dropped with the process it described, so a later start
	# detects afresh rather than inheriting an address from a run that is over.
	rm -f "$DIR/host"
	# Killing the process named in the pidfile is not the same thing as the port
	# being free, so wait for it and then say so if it never came free. The
	# failure this guards against is a stray server that outlives its pidfile
	# and silently serves every later `up`.
	i=0
	while [ "$i" -lt 30 ] && curl -fsS "$BASE/healthz" >/dev/null 2>&1; do
		sleep 0.1
		i=$((i + 1))
	done
	if curl -fsS "$BASE/healthz" >/dev/null 2>&1; then
		printf '[local] warning: %s still answers — a server outside this playground owns the port\n' "$BASE" >&2
	fi
	log "down (data kept in $DIR; 'up' resumes it)"
}

cmd_status() {
	[ -f "$CONSOLE_DIR/console.json" ] || die "not set up yet — run: mise run local:up"
	MACH_STATE_DIR="$CONSOLE_DIR" "$BIN_MACH" list
}

cmd_logs() {
	[ -f "$DIR/server.log" ] || die "no logs yet — run: mise run local:up"
	files="$DIR/server.log $DIR/agent.log"
	[ -f "$DIR/idp.log" ] && files="$files $DIR/idp.log"
	# Deliberately unquoted: this is a list of files to tail, not one filename.
	# shellcheck disable=SC2086
	tail -f $files
}

cmd_env() {
	[ -f "$DIR/env.sh" ] || die "not set up yet — run: mise run local:up"
	cat "$DIR/env.sh"
}

cmd_mach() {
	[ -f "$CONSOLE_DIR/console.json" ] || die "not set up yet — run: mise run local:up"
	MACH_STATE_DIR="$CONSOLE_DIR" exec "$BIN_MACH" "$@"
}

# The usage text is the header comment itself, printed up to the first line that
# is not one. Slicing it by line number would mean renumbering this every time
# the header grew.
usage() {
	awk 'NR > 1 && /^#/ { sub(/^# ?/, ""); print; next } NR > 1 { exit }' "$0"
}

sub=${1:-}
[ $# -gt 0 ] && shift
case "$sub" in
up) cmd_up "$@" ;;
server) cmd_server "$@" ;;
enroll) cmd_enroll "$@" ;;
temp) cmd_temp "$@" ;;
reset) cmd_reset "$@" ;;
down) cmd_down "$@" ;;
status) cmd_status "$@" ;;
logs) cmd_logs "$@" ;;
env) cmd_env "$@" ;;
mach) cmd_mach "$@" ;;
foreground)
	need_bins
	ensure_playground
	mkdir -p "$SERVER_DIR"
	resolve_host
	start_idp
	# The provider is a background process this verb would otherwise leave behind
	# when ctrl-c ends the control plane in front of it.
	trap 'stop_idp' INT TERM EXIT
	log "control plane in the foreground on $BASE (org $ORG, bound to $LISTEN) — ctrl-c to stop"
	log "web UI: $PUBLIC_URL/ui"
	server_run "$BIN_SERVER" serve
	;;
*) usage; exit 2 ;;
esac
