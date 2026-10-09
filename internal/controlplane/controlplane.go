// Package controlplane runs the mach server and admin commands for the
// mach-server container binary (deliberately separate from the mach
// remote-connection binary).
package controlplane

import (
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/TevaServices/mach/internal/broker"
	"github.com/TevaServices/mach/internal/server"
	"github.com/TevaServices/mach/internal/store"
)

func dbPath() string {
	if v := os.Getenv("MACH_DB"); v != "" {
		return v
	}
	return "/data/mach.db"
}

func openStore() (*store.Store, error) {
	return store.Open(dbPath())
}

// Org returns the configured org prefix for machine names.
func Org() string {
	if v := os.Getenv("MACH_ORG"); v != "" {
		return v
	}
	return "mach"
}

// serverKeyPath is where the control plane's identity key lives: MACH_SERVER_KEY
// when set, else the database path with ".key" appended.
//
// The database path only means something as a FILE. With MACH_DB set to a
// Postgres DSN, appending ".key" produced a path that is not a path — it kept the
// scheme, the host and the password — so every admin command that needs the key
// failed with "open postgres://user:s3cret@host:5432/mach.key: no such file or
// directory": the DSN, password included, printed into whatever collected the
// error, and a Postgres deployment with no explicit MACH_SERVER_KEY could not
// use attest or verify-attestation at all. There is nowhere near a
// DSN to put a key, so the answer is to ask rather than to guess.
func serverKeyPath() string {
	if v := os.Getenv("MACH_SERVER_KEY"); v != "" {
		return v
	}
	return dbPath() + ".key"
}

// requireServerKeyPath is serverKeyPath for the paths that cannot proceed
// without a real answer: a DSN and no MACH_SERVER_KEY is a configuration error,
// not a path to invent.
func requireServerKeyPath() (string, error) {
	db := dbPath()
	if strings.HasPrefix(db, "postgres://") || strings.HasPrefix(db, "postgresql://") {
		if os.Getenv("MACH_SERVER_KEY") == "" {
			return "", errors.New("MACH_DB is a Postgres DSN, so the identity key has no path to default to — set MACH_SERVER_KEY to a file on a persistent volume (agents pin the key it holds, and a key that moves breaks every agent's enrollment)")
		}
	}
	return serverKeyPath(), nil
}

func newServer(st *store.Store, br *broker.Broker, keyPath string) *server.Server {
	srv := server.New(st, br, Org(), keyPath)
	if os.Getenv("MACH_TRUST_PROXY") == "1" {
		// Only behind the known TLS reverse proxy (Caddy/nginx) — enables
		// X-Forwarded-For for rate limiting. Off by default.
		srv.SetTrustProxy(true)
	}
	return srv
}

// Serve runs the control plane (container entrypoint / `mach-server serve`).
func Serve() {
	listen := os.Getenv("MACH_LISTEN")
	if listen == "" {
		listen = ":8080"
	}
	pubURL := os.Getenv("MACH_PUBLIC_URL")
	if pubURL == "" {
		log.Fatal("mach-server: MACH_PUBLIC_URL is required (e.g. https://mach.example.com)")
	}
	st, err := openStore()
	if err != nil {
		log.Fatalf("mach-server: open store: %v", err)
	}
	defer st.Close()
	// Tenancy backfill, before anything serves: machines enrolled before orgs
	// were stored get their org stamped from the name prefixes (the same
	// resolution enrollment always used), and keys minted before bindings get
	// the primary org. Idempotent — a restart with nothing to do costs one
	// indexed query — and what it could not resolve is logged, not guessed.
	orgs := Orgs()
	if dbOrgs, derr := st.ListOrgsDB(); derr == nil {
		for _, o := range dbOrgs {
			orgs = append(orgs, o.Name)
		}
	} else {
		log.Printf("mach-server: could not read stored orgs for backfill: %v", derr)
	}
	st.BackfillTenancy(Org(), orgs)
	// Resolved before anything binds: a DSN with no MACH_SERVER_KEY must fail
	// here, at startup, rather than creating a directory named after the
	// database password and a key that will not survive a restart.
	keyPath, err := requireServerKeyPath()
	if err != nil {
		log.Fatalf("mach-server: %v", err)
	}
	srv := newServer(st, broker.New(), keyPath)
	log.Printf("mach control plane listening on %s (public URL %s, org %q, trust-proxy %v)",
		listen, pubURL, Org(), os.Getenv("MACH_TRUST_PROXY") == "1")
	// Explicit timeouts: without a ReadHeaderTimeout the public listener is
	// trivially slowloris'd.
	//
	// ReadTimeout bounds reading a request (headers plus body — every endpoint
	// takes a small JSON or form body, so 30s is generous even on a phone).
	// WriteTimeout stays UNSET on purpose: a streamed exec response can
	// legitimately last as long as the command's timeout. What bounds a slow
	// or stalled reader instead is a per-write deadline on the streaming
	// handler (relayExec, execWriteTimeout), which is strictly better than a
	// whole-response timeout — it lets a slow-but-alive console finish, and
	// drops one that has stopped reading.
	srvHTTP := &http.Server{
		Addr:              listen,
		Handler:           srv.Routes(),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		IdleTimeout:       120 * time.Second,
	}
	// The server owns background work (the housekeeping goroutine), so stopping it
	// is part of shutting down rather than something to leave to process exit.
	// Closed explicitly rather than by defer: this blocks for the process's
	// lifetime, and log.Fatal below exits without running deferred calls.
	err = srvHTTP.ListenAndServe()
	srv.Close()
	if err != nil {
		log.Fatal(err)
	}
}

// AddAPIKey creates a key with a server-generated high-entropy secret.
// Returns the generated key (shown ONCE) plus the name and scopes it actually
// stored, because that output is the operator's only record of what was minted:
// printing the arguments instead made it wrong whenever they were normalized —
// `add-api-key AuditKey admin` reported "admin" while the row held the exec:*
// that "admin" is an alias for, under the lowercased name the store keeps.
func AddAPIKey(name, scopes, org string) (key, storedName, storedScopes, storedOrg string, err error) {
	st, err := openStore()
	if err != nil {
		return "", "", "", "", err
	}
	defer st.Close()
	switch strings.TrimSpace(scopes) {
	case "enroll":
		scopes = "enroll"
	case "readonly":
		scopes = "readonly"
	case "*", "all", "admin", "exec":
		scopes = "exec:*"
	default:
		// allowlist form: exec:m1|m2|m3 (per-machine)
		if !strings.HasPrefix(scopes, "exec:") {
			return "", "", "", "", fmt.Errorf("scopes must be one of: enroll | readonly | exec:* | exec:<m1>|<m2>")
		}
		// An empty allowlist would create a key that can never exec; that
		// is always a mistake (usually a truncated machine list).
		if strings.TrimSpace(strings.TrimPrefix(scopes, "exec:")) == "" {
			return "", "", "", "", fmt.Errorf("exec: allowlist is empty — list machines (exec:<m1>|<m2>) or use exec:*")
		}
		// A literal `*` *among* machine names is refused rather than stored.
		// `exec:web|*` is always a typo for `exec:*`: no machine is named `*`,
		// so the key could exec on nothing real — while the control plane's
		// admin check read the entry as "all machines" and handed it
		// block/revoke/delete over the fleet. `exec:*` on its own is the way to
		// say every machine, and it is not affected by this.
		if allow := strings.TrimSpace(strings.TrimPrefix(scopes, "exec:")); allow != "*" {
			for _, m := range strings.Split(allow, "|") {
				if strings.TrimSpace(m) == "*" {
					return "", "", "", "", fmt.Errorf("`*` is not a machine name — use exec:* for every machine, or list real names (exec:<m1>|<m2>)")
				}
			}
		}
	}
	// Tenancy: a key belongs to one org — the tenant it can see and act
	// within. An omitted --org binds to the primary org, which is what every
	// key minted before tenancy was backfilled to; the printed line records
	// the binding either way, so the operator sees what was stored rather
	// than guessing from what was typed.
	org = strings.ToLower(strings.TrimSpace(org))
	if org == "" {
		org = strings.ToLower(Org())
	}
	if !store.ValidOrgLabel(org) {
		return "", "", "", "", fmt.Errorf("%q is not a valid org label", org)
	}
	storedName = strings.ToLower(strings.TrimSpace(name))
	key = "mach_" + store.RandToken(24) // 192-bit server-generated secret
	if err := st.CreateAPIKey(storedName, key, scopes, org); err != nil {
		return "", "", "", "", err
	}
	return key, storedName, scopes, org, nil
}

// AddOrg creates a tenant. The CLI is where org creation lives because the
// UI's authorization is per-org by definition — someone has to exist outside
// every org to create the first one, and that someone is the operator on the
// control-plane host. Names are lowercased like every other org consumer.
func AddOrg(name string) error {
	org := strings.ToLower(strings.TrimSpace(name))
	if !store.ValidOrgLabel(org) {
		return fmt.Errorf("%q is not a valid org label (2-20 chars: letters, digits, hyphen)", org)
	}
	st, err := openStore()
	if err != nil {
		return err
	}
	defer st.Close()
	if err := st.CreateOrg(org, "cli"); err != nil {
		if errors.Is(err, store.ErrOrgExists) {
			return fmt.Errorf("org %q already exists", org)
		}
		return err
	}
	fmt.Printf("org %q created — machines may enroll as %s-<machine>, members can now be added with add-member\n", org, org)
	return nil
}

// AddMember records a UI identity's binding to one org (or, with the
// superadmin role, to all of them). The first member of a fresh control
// plane must be created here: the UI grants nothing to an identity without
// a membership row, so nobody can self-serve their way in.
func AddMember(org, email, role string) error {
	st, err := openStore()
	if err != nil {
		return err
	}
	defer st.Close()
	if err := st.AddMember(org, email, "", role, "cli"); err != nil {
		return err
	}
	if role == store.RoleSuperadmin {
		fmt.Printf("member %q is a superadmin: may manage orgs and act within every org\n", email)
	} else {
		fmt.Printf("member %q added to org %q as %q\n", email, org, role)
	}
	return nil
}

// RemoveMember deletes one membership binding. An unknown binding is an
// error, not a silent success — same rule as revoke-api-key.
func RemoveMember(org, email string) error {
	st, err := openStore()
	if err != nil {
		return err
	}
	defer st.Close()
	if err := st.RemoveMember(org, email); err != nil {
		return err
	}
	fmt.Printf("member %q removed from org %q\n", email, org)
	return nil
}

// ListMembers prints membership rows, optionally scoped to one org.
func ListMembers(org string) error {
	st, err := openStore()
	if err != nil {
		return err
	}
	defer st.Close()
	members, err := st.ListMembers(strings.ToLower(strings.TrimSpace(org)))
	if err != nil {
		return err
	}
	if len(members) == 0 {
		fmt.Println("no members")
		return nil
	}
	for _, m := range members {
		fmt.Printf("%s\t%s\t%s\n", m.Org, m.Role, m.Email)
	}
	return nil
}

// RevokeAPIKey marks a stored API key revoked so it stops authenticating.
//
// An unknown name is an error rather than a silent success — the same rule
// RevokeMachine states: revoking is a security action typed by name, and a
// typo that prints "revoked" and exits 0 leaves the operator reporting a
// retirement that never happened. Revoking an already-revoked key is a
// success: the command asks for an end state, and that is the end state.
func RevokeAPIKey(name string) error {
	// Fold here, not in the store: add-api-key stores the lowercased name
	// (AddAPIKey's doc), so the revoke side must match what was stored.
	name = strings.ToLower(strings.TrimSpace(name))
	st, err := openStore()
	if err != nil {
		return err
	}
	defer st.Close()
	ok, err := st.RevokeAPIKey(name)
	if err != nil {
		return err
	}
	if !ok {
		return fmt.Errorf("unknown API key %q", name)
	}
	fmt.Printf("api key %q revoked (it stops authenticating immediately; the row is kept)\n", name)
	return nil
}

// E2E reports or changes the control plane'slane's end-to-end-encryption setting:
// whether it accepts sealed (E2E) exec commands, per org.
//
//	set is "" (report only), "on", "off", or "inherit" (drop an org's override
//	so it follows the default again). org is "" for the default row.
//
// It writes the same rows the running server reads, and reports the same
// effective values the server will use, so the command cannot describe a
// posture the control plane does not actually hold — including when MACH_E2E is
// set and therefore overrides whatever was just written.
func E2E(set, org string) error {
	st, err := openStore()
	if err != nil {
		return err
	}
	defer st.Close()

	if org != "" && !validOrgLabel(org) {
		return fmt.Errorf("%q is not a valid org label", org)
	}
	if set != "" && set != "inherit" && org == "" &&
		(strings.ToLower(strings.TrimSpace(set)) == "on" || strings.ToLower(strings.TrimSpace(set)) == "off") {
		fmt.Println("note: no --org given: this sets the default for every org without its own setting")
	}

	switch strings.ToLower(strings.TrimSpace(set)) {
	case "":
	case "inherit":
		if org == "" {
			return fmt.Errorf("inherit needs --org: there is nothing to inherit from for the default")
		}
		if err := server.ClearE2E(st, org); err != nil {
			return err
		}
		fmt.Printf("org %s: override removed; it follows the default again\n", org)
	case "on", "off":
		on := strings.ToLower(strings.TrimSpace(set)) == "on"
		if err := server.SetE2E(st, org, on); err != nil {
			return err
		}
		if org == "" {
			fmt.Printf("stored: sealed exec %s for every org without its own setting\n", set)
		} else {
			fmt.Printf("stored: sealed exec %s for org %s\n", set, org)
		}
	default:
		return fmt.Errorf("usage: mach-server e2e [on|off|inherit] [--org ORG] (got %q)", set)
	}

	printE2EReport(st, org)
	return nil
}

// printE2EReport prints the effective setting and where it came from. With an
// org, only that org; otherwise the default plus every org this shell knows
// about (MACH_ORG / MACH_ORGS) and every org with a stored override.
func printE2EReport(st *store.Store, org string) {
	if org != "" {
		mode, source := server.E2EMode(st, org)
		fmt.Printf("org %s: sealed exec %s (%s)\n", org, mode, source)
		explainE2E(mode)
		warnE2EOverride()
		return
	}

	defMode, defSource := server.E2EMode(st, "")
	fmt.Printf("default: sealed exec %s (%s)\n", defMode, defSource)
	// The explanation belongs directly under the line it explains. Printed after
	// the org list it read as a comment on the LAST org, and contradicted it:
	// an operator with `default off` and `org acme on` saw "org acme: sealed
	// exec on" followed by a paragraph beginning "sealed exec is refused". The
	// per-org lines carry their own mode in the same line, so they need no
	// trailing paragraph.
	explainE2E(defMode)
	warnE2EOverride()

	// Configured orgs first, then any org with a stored override that this
	// shell's MACH_ORG/MACH_ORGS does not mention (the server may run with a
	// different environment than this command).
	seen := map[string]bool{}
	for _, o := range Orgs() {
		seen[o] = true
		mode, source := server.E2EMode(st, o)
		note := ""
		if mode == defMode {
			note = " (follows the default)"
		}
		fmt.Printf("org %s: sealed exec %s%s [%s]\n", o, mode, note, source)
	}
	if stored, err := server.StoredE2EOrgs(st); err == nil {
		for _, o := range stored {
			if seen[o] {
				continue
			}
			mode, _ := server.E2EMode(st, o)
			fmt.Printf("org %s: sealed exec %s (stored override; not in this shell's MACH_ORG/MACH_ORGS)\n", o, mode)
		}
	}
}

func explainE2E(mode string) {
	if mode == "off" {
		fmt.Println("  sealed exec is refused (403, audited); commands run in plaintext, where")
		fmt.Println("  the fleet-wide block list can read them. Agent E2E keys are untouched, so")
		fmt.Println("  turning it back on restores sealing with no re-enrollment.")
		return
	}
	fmt.Println("  sealed exec is accepted; commands may be ciphertext the fleet-wide block")
	fmt.Println("  list cannot inspect. Turning it off stops sealing immediately.")
}

func warnE2EOverride() {
	if override := strings.TrimSpace(os.Getenv("MACH_E2E")); override != "" {
		fmt.Printf("  note: MACH_E2E=%s is set in this environment and overrides every org\n", override)
	}
}

// validOrgLabel mirrors the org half of store.ValidOrgName (2-20 label chars):
// the CLI should reject a typo before it writes a row nothing will ever read.
func validOrgLabel(org string) bool {
	if len(org) < 2 || len(org) > 20 {
		return false
	}
	for _, c := range org {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-') {
			return false
		}
	}
	return true
}

// Orgs returns the org prefixes this environment configures: MACH_ORG first,
// then the comma-separated MACH_ORGS.
func Orgs() []string {
	var out []string
	seen := map[string]bool{}
	for _, v := range []string{Org(), os.Getenv("MACH_ORGS")} {
		for _, o := range strings.Split(v, ",") {
			o = strings.ToLower(strings.TrimSpace(o))
			if o == "" || seen[o] {
				continue
			}
			seen[o] = true
			out = append(out, o)
		}
	}
	return out
}

// RevokeMachine marks a machine revoked so its agent self-retires.
//
// An unknown name is an error rather than a silent success. Revoking is a
// security action an operator takes by typing a name, and a typo used to print
// the success line and exit 0 while nothing was revoked — leaving an active
// machine the operator believes is retired. DeleteMachine already refuses an
// unknown name for the same reason.
func RevokeMachine(name string, purgeAudit bool) error {
	st, err := openStore()
	if err != nil {
		return err
	}
	defer st.Close()
	if m, err := st.MachineByName(name); err != nil {
		return err
	} else if m == nil {
		return fmt.Errorf("unknown machine %q", name)
	}
	if err := st.RevokeMachine(name); err != nil {
		return err
	}
	if purgeAudit {
		_ = st.RemoveMachineAudit(name)
	}
	fmt.Printf("machine %q revoked (its agent will retire on next connect attempt)\n", name)
	return nil
}

// DeleteMachine removes a machine row so its name and agent key can be used
// again. This is the recovery path for a revoked machine that has to
// re-enroll — the agent on that host must be stopped first, or it will keep
// retrying with a key the control plane no longer knows.
//
// The audit trail is kept unless purgeAudit is set: erasing a machine's
// command history is a separate decision from retiring the machine.
func DeleteMachine(name string, purgeAudit bool) error {
	st, err := openStore()
	if err != nil {
		return err
	}
	defer st.Close()
	if m, err := st.MachineByName(name); err != nil {
		return err
	} else if m == nil {
		return fmt.Errorf("unknown machine %q", name)
	}
	if err := st.DeleteMachine(name); err != nil {
		return err
	}
	if purgeAudit {
		_ = st.RemoveMachineAudit(name)
		fmt.Printf("machine %q deleted, and its audit history purged\n", name)
	} else {
		fmt.Printf("machine %q deleted (audit history kept — use --purge-audit to erase it)\n", name)
	}
	fmt.Printf("its agent key is no longer known here; stop the agent on that host before re-enrolling\n")
	return nil
}

// PushUpdate was removed: the control plane no longer signs and queues
// agent-binary updates. Agents are updated through their distribution points
// (apt/rpm/apk packages and their package repositories for Linux, winget/MSI
// for Windows, Homebrew for macOS), each of whose supervisors restarts the
// agent on failure only — the "exit 0 means stop" contract, unchanged. What
// the removal takes with it: the signed-manifest control (wire integrity,
// subsumed by TLS + the pinned server key) and the anti-rollback residue it
// never had. attest/verify-attestation survive as the release pipeline's
// provenance record for shipped artifacts.
// loadServerPriv returns the control plane's identity private key (for
// signing attestation envelopes). Reads the persisted key file; errors surface
// as a normal CLI error, not a panic.
func loadServerPriv() (ed25519.PrivateKey, error) {
	path, perr := requireServerKeyPath()
	if perr != nil {
		return nil, perr
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("control plane key missing — run serve once first: %v", err)
	}
	b, derr := hex.DecodeString(strings.TrimSpace(string(raw)))
	if derr != nil || len(b) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("corrupt control plane key at %s", path)
	}
	return ed25519.PrivateKey(b), nil
}
