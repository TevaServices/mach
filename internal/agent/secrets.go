// Agent-side secrets: values live only on this machine.
//
// A secret's value is stored in <state dir>/secrets.json (mode 0600) and
// never crosses any wire. Only NAMES travel: the control plane pushes a value
// sealed to this machine's E2E key (protocol.SealedSecretPush, opened here
// with the same e2e.Open path a sealed command uses), lists names, and hears
// announcements of names. Injection resolves names against this store at exec
// time — protocol.ExecCommand.InjectEnv / StreamStart.InjectEnv carry names —
// and every byte this agent sends back is scrubbed against the union of all
// locally stored values, so `cat secrets.json` is protected too, not just the
// commands a secret was injected into.
//
// THE SCRUBBING IS BEST-EFFORT, and that is stated rather than claimed away:
// it catches a value that appears literally in the bytes the agent sends. A
// value that the command encodes before printing — hex, base64, ROT13, a
// checksum, one byte per line — is not caught, and a value split across two
// streamed chunks is not caught (each chunk is scrubbed independently). It is
// a guard against the ordinary case, not a confinement boundary.
//
// Failure posture, mirroring policy.txt: a store file that exists but cannot
// be read or parsed is an ERROR that refuses commands, never silently "no
// secrets" — the difference between "no secrets stored" and "the secrets I
// stored are unreadable" is exactly what a scrubbing layer cannot be silent
// about. An absent file is the normal case and is no error.

package agent

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/TevaServices/mach/internal/e2e"
	"github.com/TevaServices/mach/internal/protocol"
)

// Secret value bounds. The minimum is not pedantry: a value too short to be
// a secret would also make scrubbing meaningless (a 3-byte value appears by
// accident in ordinary output, and the replacement would corrupt it). The
// maximum bounds one entry of a file the agent re-reads on every exec.
const (
	MinSecretValueBytes = 8
	MaxSecretValueBytes = 4096
)

// redactedMarker is what a scrubbed value becomes: [REDACTED:<NAME>], so a
// reader can tell which secret was here without ever seeing it.
const redactedMarker = "[REDACTED:"

// secretsRefusalPrefix marks every refusal the secrets layer produces, so a
// frame handler can tell "refused by secrets" from the other 126-class
// refusals and re-announce (the store may have changed).
const secretsRefusalPrefix = "secrets: "

// errSecretStoreUnreadable marks a secrets.json that exists but cannot be
// read or parsed. Everything built on a store read fails closed on it: an
// injected exec is refused, and so is any exec whose output we could not
// promise to scrub.
var errSecretStoreUnreadable = errors.New("secrets store unreadable")

// ValidSecretName enforces the name grammar and the reserved list. A secret
// name becomes an environment variable, so it must be a legal identifier, and
// it must not collide with the variables that decide where a command runs:
// MACH_* (the agent's own control variables, which filteredEnv already strips
// from every command's environment), PATH (a secret named PATH is not a
// guard, it is a hijack), and LD_*/DYLD_* (the loader's own namespace).
// ValidSecretName is the wire package's rule, re-exported for the agent's
// callers; the rule itself lives in protocol/secrets.go so the control plane
// and the agent cannot disagree about what a name is.
func ValidSecretName(name string) error { return protocol.ValidSecretName(name) }

// ValidSecretValue enforces the value length bounds.
func ValidSecretValue(value string) error {
	if n := len(value); n < MinSecretValueBytes {
		return fmt.Errorf("secret value is %d bytes; the minimum is %d — a value too short to be a secret makes scrubbing meaningless", n, MinSecretValueBytes)
	} else if n > MaxSecretValueBytes {
		return fmt.Errorf("secret value is %d bytes; the maximum is %d", n, MaxSecretValueBytes)
	}
	return nil
}

// secretEntry is one stored secret. Org is the org the entry was provisioned
// under, which is what makes a name resolvable: an entry whose org is not
// this machine's own org is unknown here, however tempting its name.
type secretEntry struct {
	Value     string `json:"value"`
	Org       string `json:"org"`
	CreatedAt string `json:"created_at,omitempty"`
	UpdatedAt string `json:"updated_at,omitempty"`
}

// secretsData is the on-disk shape. Org is this machine's own org (from
// config.json); each entry carries the org it was provisioned under.
type secretsData struct {
	Org     string                  `json:"org"`
	Secrets map[string]*secretEntry `json:"secrets"`
}

// secretStore is what the exec, push and announce paths read. The exec path
// uses it on demand — every call re-reads the store, so a second process
// adding a secret is picked up by a running daemon without a restart.
type secretStore interface {
	// ownOrg is this machine's own org; "" means unknown, and every
	// secrets feature refuses rather than guessing (never from the
	// machine name's prefix).
	ownOrg() string
	// resolve returns the value of an own-org secret. ok=false is simply
	// "unknown name"; err is a store failure (fail closed).
	resolve(name string) (value string, ok bool, err error)
	// names lists the own-org entries, sorted.
	names() ([]string, error)
	// scrubValues maps every stored entry — ANY org's — name→value. The
	// scrubber covers the whole file because its job is to protect the
	// file's contents, and `cat secrets.json` prints all of it.
	scrubValues() (map[string]string, error)
	// put stores an entry pushed from the control plane. The caller has
	// already validated name/value/org against this machine's own org.
	put(name, value, org string) error
}

// ---- the file store (installed agent) ----

// fileSecretStore is the persistent store: <state dir>/secrets.json, 0600.
// The org comes from config.json at construction; the data is re-read on
// every call.
type fileSecretStore struct {
	path string
	org  string
}

func newFileSecretStore(stateDir, org string) *fileSecretStore {
	return &fileSecretStore{path: filepath.Join(stateDir, "secrets.json"), org: org}
}

func (s *fileSecretStore) ownOrg() string { return s.org }

// load reads the store, tightening the file's mode on every open — the same
// rule agent.key, e2e.key and the e2e pin file follow: first-run creation
// makes it 0600, but a restore or manual copy can leave it loose, and a file
// this sensitive must not stay that way because nobody happened to notice.
func (s *fileSecretStore) load() (*secretsData, error) {
	raw, err := os.ReadFile(s.path)
	if errors.Is(err, fs.ErrNotExist) {
		// Absent is the default: an empty store, not a fault.
		return &secretsData{Org: s.org, Secrets: map[string]*secretEntry{}}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("%w: %s: %v", errSecretStoreUnreadable, s.path, err)
	}
	if st, serr := os.Stat(s.path); serr == nil && st.Mode().Perm() != 0o600 {
		_ = os.Chmod(s.path, 0o600)
	}
	var d secretsData
	if err := json.Unmarshal(raw, &d); err != nil {
		return nil, fmt.Errorf("%w: %s: %v", errSecretStoreUnreadable, s.path, err)
	}
	return &d, nil
}

func (s *fileSecretStore) resolve(name string) (string, bool, error) {
	d, err := s.load()
	if err != nil {
		return "", false, err
	}
	e, ok := d.Secrets[name]
	if !ok || e == nil {
		return "", false, nil
	}
	if e.Org != s.org {
		// Another org's entry is unknown on this machine: names are only
		// unique within an org, and resolving across orgs would hand one
		// tenant's secret to another's command.
		return "", false, nil
	}
	return e.Value, true, nil
}

func (s *fileSecretStore) names() ([]string, error) {
	d, err := s.load()
	if err != nil {
		return nil, err
	}
	var out []string
	for name, e := range d.Secrets {
		if e != nil && e.Org == s.org {
			out = append(out, name)
		}
	}
	sort.Strings(out)
	return out, nil
}

func (s *fileSecretStore) scrubValues() (map[string]string, error) {
	d, err := s.load()
	if err != nil {
		return nil, err
	}
	out := make(map[string]string, len(d.Secrets))
	for name, e := range d.Secrets {
		if e != nil {
			out[name] = e.Value
		}
	}
	return out, nil
}

// put validates and writes. UpdatedAt moves; CreatedAt is kept from the
// entry it replaces, so a re-push of the same name reads as an update.
func (s *fileSecretStore) put(name, value, org string) error {
	if err := ValidSecretName(name); err != nil {
		return err
	}
	if err := ValidSecretValue(value); err != nil {
		return err
	}
	d, err := s.load()
	if err != nil {
		return err
	}
	now := time.Now().UTC().Format(time.RFC3339)
	e := d.Secrets[name]
	if e == nil {
		e = &secretEntry{CreatedAt: now}
	}
	e.Value, e.Org, e.UpdatedAt = value, org, now
	if d.Secrets == nil {
		d.Secrets = map[string]*secretEntry{}
	}
	d.Secrets[name] = e
	return s.write(d)
}

// remove deletes an entry (the local CLI's `mach secrets remove`). Any org's
// entry may be removed: this is the machine owner's hygiene, not a
// cross-org capability.
func (s *fileSecretStore) remove(name string) error {
	d, err := s.load()
	if err != nil {
		return err
	}
	if _, ok := d.Secrets[name]; !ok {
		return fmt.Errorf("no secret named %s", name)
	}
	delete(d.Secrets, name)
	return s.write(d)
}

// write replaces the store atomically: temp file in the same directory,
// 0600 from birth, fsync-free rename. A reader mid-exec either sees the old
// file or the new one, never a partial one.
func (s *fileSecretStore) write(d *secretsData) error {
	raw, err := json.MarshalIndent(d, "", "  ")
	if err != nil {
		return err
	}
	dir := filepath.Dir(s.path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".secrets-*.tmp")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	// A successful rename makes this a no-op; every failure path below
	// leaves nothing behind.
	defer os.Remove(tmpName)
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(raw); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpName, s.path)
}

// ---- the memory store (temporary session, invariant 23) ----

// memSecretStore is the temporary session's store: memory only, dies with the
// process, and it never touches the state directory — plain `mach` holds
// nothing on disk, and a secrets file would be exactly the kind of state its
// whole design refuses to leave behind. Injection works (a session can hold
// values in memory), but a control-plane push is refused: a temporary
// session has no persistent home for what it is handed.
type memSecretStore struct {
	mu      sync.Mutex
	org     string
	entries map[string]*secretEntry
}

func newMemSecretStore(org string) *memSecretStore {
	return &memSecretStore{org: org, entries: map[string]*secretEntry{}}
}

func (m *memSecretStore) ownOrg() string { return m.org }

// add stores a value locally. Only the machine itself uses this (and the
// tests); the push path goes through put, which refuses.
func (m *memSecretStore) add(name, value string) error {
	if err := ValidSecretName(name); err != nil {
		return err
	}
	if err := ValidSecretValue(value); err != nil {
		return err
	}
	now := time.Now().UTC().Format(time.RFC3339)
	m.mu.Lock()
	defer m.mu.Unlock()
	e := m.entries[name]
	if e == nil {
		e = &secretEntry{CreatedAt: now}
	}
	e.Value, e.Org, e.UpdatedAt = value, m.org, now
	m.entries[name] = e
	return nil
}

func (m *memSecretStore) put(name, value, org string) error {
	return errors.New("temporary session holds no persistent secrets")
}

func (m *memSecretStore) resolve(name string) (string, bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	e, ok := m.entries[name]
	if !ok || e == nil || e.Org != m.org {
		return "", false, nil
	}
	return e.Value, true, nil
}

func (m *memSecretStore) names() ([]string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []string
	for name, e := range m.entries {
		if e != nil && e.Org == m.org {
			out = append(out, name)
		}
	}
	sort.Strings(out)
	return out, nil
}

func (m *memSecretStore) scrubValues() (map[string]string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make(map[string]string, len(m.entries))
	for name, e := range m.entries {
		if e != nil {
			out[name] = e.Value
		}
	}
	return out, nil
}

// ---- the process-wide store ----

// machineSecrets is the store this process enforces. The permanent agent
// installs a file store at startup (runDaemon, before the privilege drop, so
// the state dir it names is the one it can still read); a temporary session
// installs a memory store. Until something is installed, noSecretStore is in
// force: an agent that has never re-enrolled learns no org, and the honest
// answer to everything secrets is "re-enroll".
//
// Guarded by a mutex rather than read directly: the install happens at
// startup, but tests swap stores, and a swapped-in store must not race a
// handler goroutine still running from a previous test.
var (
	machineSecretsMu sync.RWMutex
	machineSecrets   secretStore = noSecretStore{}
)

// installSecrets replaces the process-wide store. Startup calls it once;
// tests call it with a restore.
func installSecrets(s secretStore) {
	machineSecretsMu.Lock()
	machineSecrets = s
	machineSecretsMu.Unlock()
}

// activeSecrets returns the store in force.
func activeSecrets() secretStore {
	machineSecretsMu.RLock()
	defer machineSecretsMu.RUnlock()
	return machineSecrets
}

// noSecretStore is the un-configured state: no org known, nothing stored,
// every secrets feature refused. Injected commands fail closed; ordinary
// commands are untouched (an empty scrub map is a no-op).
type noSecretStore struct{}

func (noSecretStore) ownOrg() string                       { return "" }
func (noSecretStore) resolve(string) (string, bool, error) { return "", false, nil }
func (noSecretStore) names() ([]string, error)             { return nil, nil }
func (noSecretStore) scrubValues() (map[string]string, error) {
	return nil, nil
}
func (noSecretStore) put(name, value, org string) error {
	return errors.New("machine has no org; re-enroll")
}

// ---- injection ----

// resolveInjection resolves a command's InjectEnv names against the machine's
// store, returning K=V pairs to append to the command's environment — or a
// refusal reason in the same class as the policy guardrails' (exit 126, and
// the control plane audits it as a refusal). The refusal names the missing
// NAME and never a value, because the reply it travels in may be logged.
//
// A name that is stored but tagged for another org is unknown here, exactly
// like a missing one: silently running without a secret the caller asked for
// would be worse than refusing.
func resolveInjection(store secretStore, inject []string) ([]string, string) {
	if len(inject) == 0 {
		return nil, ""
	}
	if store.ownOrg() == "" {
		return nil, secretsRefusalPrefix + "this machine's org is unknown — re-enroll to learn your machine's org"
	}
	var env []string
	for _, name := range inject {
		if err := ValidSecretName(name); err != nil {
			return nil, secretsRefusalPrefix + "refusing to inject " + name + ": " + err.Error()
		}
		value, ok, err := store.resolve(name)
		if err != nil {
			return nil, secretsRefusalPrefix + "store unreadable, refusing this injected exec: " + err.Error()
		}
		if !ok {
			return nil, secretsRefusalPrefix + "unknown secret name " + name + " for this machine's org"
		}
		env = append(env, name+"="+value)
	}
	return env, ""
}

// appendEnvValues adds K=V pairs to a base environment, with any existing
// entry for the same key dropped first so the injected value wins. Go's
// os/exec passes the slice through to execve, where a duplicated key's
// winner is libc's lookup order, not ours — deduplicating is what makes
// "later entries win" a property instead of an accident.
func appendEnvValues(base []string, pairs []string) []string {
	if len(pairs) == 0 {
		return base
	}
	keys := make(map[string]bool, len(pairs))
	for _, p := range pairs {
		if i := strings.IndexByte(p, '='); i > 0 {
			keys[p[:i]] = true
		}
	}
	out := make([]string, 0, len(base)+len(pairs))
	for _, kv := range base {
		if i := strings.IndexByte(kv, '='); i > 0 && keys[kv[:i]] {
			continue
		}
		out = append(out, kv)
	}
	return append(out, pairs...)
}

// isSecretsRefusal reports whether an exec result was refused by the secrets
// layer, so the frame handler can re-announce (the store may have changed —
// a name that was missing a moment ago may have been added since).
func isSecretsRefusal(res protocol.ExecResult) bool {
	return res.ExitCode == 126 && strings.HasPrefix(res.Error, secretsRefusalPrefix)
}

// ---- scrubbing ----

// scrubOutput replaces every occurrence of a stored value in b with
// [REDACTED:<NAME>], longest value first (so a value that is a prefix of
// another is not half-replaced), plain string replacement — values are
// arbitrary bytes and must not be interpreted as a pattern. Empty values and
// values shorter than 4 bytes are skipped: both are refused at write time,
// and this is the belt-and-braces against a hand-edited file. Best-effort by
// design — see the package comment for what that admits.
func scrubOutput(values map[string]string, b []byte) []byte {
	if len(b) == 0 || len(values) == 0 {
		return b
	}
	pairs := buildScrubPairs(values)
	return pairs.apply(b)
}

type scrubPair struct{ name, value string }

// scrubPairs is the ordered replacement list: longest value first.
type scrubPairs []scrubPair

func buildScrubPairs(values map[string]string) scrubPairs {
	pairs := make(scrubPairs, 0, len(values))
	for name, value := range values {
		if value == "" || len(value) < 4 {
			continue
		}
		pairs = append(pairs, scrubPair{name: name, value: value})
	}
	sort.Slice(pairs, func(i, j int) bool {
		if len(pairs[i].value) != len(pairs[j].value) {
			return len(pairs[i].value) > len(pairs[j].value)
		}
		return pairs[i].name < pairs[j].name
	})
	return pairs
}

func (pairs scrubPairs) apply(b []byte) []byte {
	if len(pairs) == 0 || len(b) == 0 {
		return b
	}
	s := string(b)
	for _, p := range pairs {
		if strings.Contains(s, p.value) {
			s = strings.ReplaceAll(s, p.value, redactedMarker+p.name+"]")
		}
	}
	return []byte(s)
}

// secretScrubber is a scrubber built once from one store read, for the
// duration of one command: every outgoing byte of that command goes through
// the same pairs.
type secretScrubber struct{ pairs scrubPairs }

// newSecretScrubber builds one from name→value pairs. An empty map (no
// secrets, or none readable) is a scrubber that changes nothing.
func newSecretScrubber(values map[string]string) secretScrubber {
	return secretScrubber{buildScrubPairs(values)}
}

// Scrub replaces stored values in raw command output.
func (s secretScrubber) Scrub(b []byte) []byte { return s.pairs.apply(b) }

// ScrubText is Scrub for a string that is about to be logged or traced.
func (s secretScrubber) ScrubText(t string) string {
	return string(s.pairs.apply([]byte(t)))
}

// commandScrubber builds the scrubber for one command's output from the
// process-wide store. It refuses (a 126-class reason) when the store exists
// but cannot be read: sending unscrubbed output because the store was
// unreadable is the one failure this feature exists to prevent, so it is
// fail-closed — the same posture policy.txt takes.
func commandScrubber(store secretStore) (secretScrubber, string) {
	values, err := store.scrubValues()
	if err != nil {
		return secretScrubber{}, secretsRefusalPrefix +
			"store unreadable, refusing to run rather than send unscrubbed output: " + err.Error()
	}
	return newSecretScrubber(values), ""
}

// scrubTrace scrubs a temporary session's console trace line. The command
// text arrives from the control plane and cannot contain a stored value
// (values travel env-only, never argv), but the trace is the one place this
// agent prints command text at a human, so it is scrubbed against everything
// stored anyway.
func scrubTrace(store secretStore, text string) string {
	values, err := store.scrubValues()
	if err != nil {
		return "(secrets store unreadable)"
	}
	return string(scrubOutput(values, []byte(text)))
}

// ---- frames: push, list, announce ----

// handleSecretPush opens a sealed secret_push frame with this machine's E2E
// key, validates what it finds, stores it, and answers on the same
// connection. The reply carries name and status only — the value never
// returns to the control plane, and neither does an error that quotes one.
func handleSecretPush(conn *protocol.WSConn, env protocol.Envelope, e2eKey *E2EKeyPair, store secretStore) {
	res, announce := secretPushOutcome(e2eKey, store, env.Payload)
	payload, err := json.Marshal(res)
	if err != nil {
		log.Printf("agent: failed to encode secret_push_result: %v", err)
		return
	}
	if err := conn.WriteEnvelope(protocol.Envelope{Type: "secret_push_result", ReqID: env.ReqID, Payload: payload}); err != nil {
		log.Printf("agent: failed to send secret_push_result: %v", err)
	}
	if announce {
		announceSecrets(conn, store)
	}
}

// secretPushOutcome is handleSecretPush's decision, split from the writing so
// a test can drive the whole thing without a socket. The bool is "a push was
// accepted", which is the case that announces.
func secretPushOutcome(e2eKey *E2EKeyPair, store secretStore, payload []byte) (protocol.SecretPushResult, bool) {
	var push protocol.SealedSecretPush
	if err := json.Unmarshal(payload, &push); err != nil || push.SealedB64 == "" {
		return protocol.SecretPushResult{Error: "bad secret_push payload"}, false
	}
	opened, err := openSealedSecret(e2eKey, push)
	if err != nil {
		// Envelope-level failure: say why (wrong machine, format version),
		// never what was inside — we could not read it either.
		return protocol.SecretPushResult{Error: "e2e: sealed secret failed to open: " + err.Error()}, false
	}
	var sp protocol.SecretPayload
	if err := json.Unmarshal(opened, &sp); err != nil {
		return protocol.SecretPushResult{Error: "sealed secret payload is not a SecretPayload"}, false
	}
	if err := validateSecretPush(store, sp); err != nil {
		return protocol.SecretPushResult{Name: sp.Name, Error: err.Error()}, false
	}
	if err := store.put(sp.Name, sp.Value, sp.Org); err != nil {
		return protocol.SecretPushResult{Name: sp.Name, Error: err.Error()}, false
	}
	return protocol.SecretPushResult{Name: sp.Name, OK: true}, true
}

// validateSecretPush is the gate every pushed value passes before it is
// stored: name grammar and reserved list, value bounds, and the org tag
// matching this machine's own org. None of the refusals can quote the value —
// they are built from the name and the rules, and the value is not read into
// any of them.
func validateSecretPush(store secretStore, sp protocol.SecretPayload) error {
	if store.ownOrg() == "" {
		return errors.New("machine has no org; re-enroll")
	}
	if err := ValidSecretName(sp.Name); err != nil {
		return err
	}
	if err := ValidSecretValue(sp.Value); err != nil {
		return err
	}
	if sp.Org != store.ownOrg() {
		return errors.New("secret is for another org")
	}
	return nil
}

// openSealedSecret opens SealedSecretPush.SealedB64 with the agent's E2E
// private key — the same e2e.Open a sealed command goes through (HKDF-derived
// key, AAD = the sender's ephemeral pubkey, format version checked), reused
// rather than copied.
func openSealedSecret(e2eKey *E2EKeyPair, push protocol.SealedSecretPush) ([]byte, error) {
	if e2eKey == nil {
		return nil, errors.New("this agent has no E2E key loaded")
	}
	body, err := base64.StdEncoding.DecodeString(push.SealedB64)
	if err != nil {
		return nil, err
	}
	return e2e.Open(&e2eKey.Private, body)
}

// handleSecretList answers a secret_list with names only: this machine's own
// org and the names tagged with it. A store read failure answers with an
// empty list (and a log line) rather than an error frame — the reply has no
// error field to carry one, and inventing an error channel for names would
// be the wrong shape; the control plane reading "no names" for an unreadable
// store is the same answer it would get for an empty one, which is safe
// (names are not dispatch-affecting facts).
func handleSecretList(conn *protocol.WSConn, env protocol.Envelope, store secretStore) {
	res := secretListResult(store)
	payload, err := json.Marshal(res)
	if err != nil {
		log.Printf("agent: failed to encode secret_list_result: %v", err)
		return
	}
	if err := conn.WriteEnvelope(protocol.Envelope{Type: "secret_list_result", ReqID: env.ReqID, Payload: payload}); err != nil {
		log.Printf("agent: failed to send secret_list_result: %v", err)
	}
}

// secretListResult is handleSecretList's decision, split out for tests.
func secretListResult(store secretStore) protocol.SecretListResult {
	res := protocol.SecretListResult{Org: store.ownOrg()}
	names, err := store.names()
	if err != nil {
		log.Printf("agent: could not read the secrets store for a listing: %v", err)
		return res
	}
	res.Names = names
	return res
}

// announceSecrets tells the control plane which secret NAMES this machine
// holds for its own org. Sent at connect and after a successful push (and
// after a refused-because-missing exec, since the store may have changed).
// It is silent for a machine with no org — that machine refuses every
// secrets feature, and announcing nothing would be the honest answer.
func announceSecrets(conn *protocol.WSConn, store secretStore) {
	env := announceEnvelope(store)
	if env == nil {
		return
	}
	if err := conn.WriteEnvelope(*env); err != nil {
		log.Printf("agent: could not send secrets_announce: %v", err)
	}
}

// announceEnvelope is the announce frame, or nil when there is nothing to
// announce (no org, or a store read failure — which is logged).
func announceEnvelope(store secretStore) *protocol.Envelope {
	if store.ownOrg() == "" {
		return nil
	}
	names, err := store.names()
	if err != nil {
		log.Printf("agent: could not read the secrets store for an announcement: %v", err)
		return nil
	}
	payload, err := json.Marshal(protocol.SecretsAnnounce{Org: store.ownOrg(), Names: names})
	if err != nil {
		return nil
	}
	return &protocol.Envelope{Type: "secrets_announce", Payload: payload}
}

// handleSecretsAnnounceAck records the control plane's ack. The count is the
// only content: a name is not sensitive (the control plane already knows
// it), but there is no reason to log the list either.
func handleSecretsAnnounceAck(env protocol.Envelope) {
	var ack protocol.SecretsAnnounceAck
	if err := json.Unmarshal(env.Payload, &ack); err != nil {
		log.Printf("agent: malformed secrets_announce_ack")
		return
	}
	log.Printf("agent: control plane acknowledged %d secret name(s)", ack.Count)
}
