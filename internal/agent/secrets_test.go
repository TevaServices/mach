package agent

// The agent side of secrets: the store file, the name/value rules, the
// scrubber, injection fail-closed, the push/list handlers, and the memory
// store a temporary session runs on. Values never leave this package in a
// test assertion either — the point of several of these tests is that a
// refusal or a result frame carries the NAME and never the value.

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/TevaServices/mach/internal/e2e"
	"github.com/TevaServices/mach/internal/protocol"
)

// withSecretStore installs s for the test and restores whatever was in force.
func withSecretStore(t *testing.T, s secretStore) {
	t.Helper()
	old := activeSecrets()
	installSecrets(s)
	t.Cleanup(func() { installSecrets(old) })
}

func TestSecretNameValidation(t *testing.T) {
	cases := []struct {
		name  string
		valid bool
	}{
		{"DB_PASSWORD", true},
		{"MY_SECRET_2", true},
		{"_LEADING", true},
		{"", false},
		{"db_password", false}, // lowercase refused
		{"DbPassword", false},  // mixed case refused
		{"9KEY", false},        // may not start with a digit
		{"DB-PASSWORD", false}, // not an identifier
		{"MACH_TOKEN", false},  // reserved: MACH_* is the agent's own namespace
		{"PATH", false},        // reserved outright
		{"LD_PRELOAD", false},  // reserved: loader namespace
		{"DYLD_LIBRARY_PATH", false},
		{"LD_LIBRARY_PATH", false},
	}
	for _, c := range cases {
		err := ValidSecretName(c.name)
		if c.valid && err != nil {
			t.Errorf("%q refused: %v", c.name, err)
		}
		if !c.valid && err == nil {
			t.Errorf("%q accepted", c.name)
		}
	}
}

func TestSecretValueBounds(t *testing.T) {
	if err := ValidSecretValue(strings.Repeat("x", 7)); err == nil {
		t.Error("a 7-byte value was accepted (minimum is 8)")
	}
	if err := ValidSecretValue(strings.Repeat("x", 8)); err != nil {
		t.Errorf("an 8-byte value refused: %v", err)
	}
	if err := ValidSecretValue(strings.Repeat("x", MaxSecretValueBytes)); err != nil {
		t.Errorf("a %d-byte value refused: %v", MaxSecretValueBytes, err)
	}
	if err := ValidSecretValue(strings.Repeat("x", MaxSecretValueBytes+1)); err == nil {
		t.Error("an over-long value was accepted")
	}
}

func TestSecretsStoreFileModesAndAtomicWrite(t *testing.T) {
	dir := t.TempDir()
	s := newFileSecretStore(dir, "orgA")
	if err := s.put("DB_PASSWORD", "s3cr3tvalue", "orgA"); err != nil {
		t.Fatalf("put: %v", err)
	}
	storePath := filepath.Join(dir, "secrets.json")
	st, err := os.Stat(storePath)
	if err != nil {
		t.Fatalf("store file missing: %v", err)
	}
	if st.Mode().Perm() != 0o600 {
		t.Errorf("secrets.json mode = %o, want 600", st.Mode().Perm())
	}
	// A loose file is tightened on the next open, the way agent.key and the
	// e2e pin file are.
	if err := os.Chmod(storePath, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.resolve("DB_PASSWORD"); err != nil {
		t.Fatalf("resolve: %v", err)
	}
	st, err = os.Stat(storePath)
	if err != nil {
		t.Fatal(err)
	}
	if st.Mode().Perm() != 0o600 {
		t.Errorf("loose secrets.json not tightened: mode = %o", st.Mode().Perm())
	}
	// Atomic write: no temp file left behind.
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), ".secrets-") {
			t.Errorf("temp file left behind: %s", e.Name())
		}
	}
	// An empty store is fine, and absent is the default.
	empty := newFileSecretStore(t.TempDir(), "orgA")
	if names, err := empty.names(); err != nil || len(names) != 0 {
		t.Errorf("absent store = %v (%v)", names, err)
	}
}

// A store that exists but cannot be parsed is an ERROR that fails closed,
// never silently "no secrets" — the same rule policy.txt follows.
func TestSecretsStoreUnreadableFailsClosed(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "secrets.json"), []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	s := newFileSecretStore(dir, "orgA")
	if _, _, err := s.resolve("DB_PASSWORD"); err == nil {
		t.Fatal("a corrupt store resolved a name without error")
	}
	if _, err := s.names(); err == nil {
		t.Fatal("a corrupt store listed names without error")
	}
	if _, err := s.scrubValues(); err == nil {
		t.Fatal("a corrupt store produced a scrub map without error")
	}
	// And the exec-facing wrappers refuse rather than run.
	if _, refusal := commandScrubber(s); refusal == "" {
		t.Fatal("a corrupt store produced no scrub refusal")
	}
	if _, refusal := resolveInjection(s, []string{"DB_PASSWORD"}); refusal == "" {
		t.Fatal("a corrupt store produced no injection refusal")
	}
	// An unreadable (not merely unparsable) file fails the same way. A
	// directory stands in for the unreadable file, so the failure does not
	// depend on which user the test runs as.
	dir2 := t.TempDir()
	if err := os.Mkdir(filepath.Join(dir2, "secrets.json"), 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := newFileSecretStore(dir2, "orgA").scrubValues(); err == nil {
		t.Fatal("an unreadable store was treated as no secrets")
	}
}

func TestScrubOutput(t *testing.T) {
	cases := []struct {
		note   string
		values map[string]string
		in     string
		want   string
	}{
		{
			note:   "multiple occurrences",
			values: map[string]string{"DB_PASSWORD": "s3cr3tvalue"},
			in:     "pass=s3cr3tvalue and again s3cr3tvalue end",
			want:   "pass=[REDACTED:DB_PASSWORD] and again [REDACTED:DB_PASSWORD] end",
		},
		{
			note:   "longest value first (one is a prefix of another)",
			values: map[string]string{"SMALL": "secretkey", "BIG": "supersecretkey"},
			in:     "supersecretkey secretkey",
			want:   "[REDACTED:BIG] [REDACTED:SMALL]",
		},
		{
			note:   "regex metacharacters are literal",
			values: map[string]string{"WEIRD": ".*$&()[]"},
			in:     "a .*$&()[] b",
			want:   "a [REDACTED:WEIRD] b",
		},
		{
			note:   "binary-ish bytes",
			values: map[string]string{"BIN": "\x00\x01\x02\x03"},
			in:     "x\x00\x01\x02\x03y",
			want:   "x[REDACTED:BIN]y",
		},
		{
			note:   "short values are skipped in scrubbing",
			values: map[string]string{"TINY": "abc"},
			in:     "has abc inside",
			want:   "has abc inside",
		},
		{
			note:   "empty map is a no-op",
			values: map[string]string{},
			in:     "unchanged",
			want:   "unchanged",
		},
	}
	for _, c := range cases {
		if got := string(scrubOutput(c.values, []byte(c.in))); got != c.want {
			t.Errorf("%s: got %q, want %q", c.note, got, c.want)
		}
	}
}

// Injection fails closed: a missing name refuses, and an entry tagged with
// another org is unknown on this machine — same refusal class as the policy
// guardrails (the message names the missing NAME, never a value).
func TestResolveInjectionFailsClosed(t *testing.T) {
	dir := t.TempDir()
	s := newFileSecretStore(dir, "orgA")
	if err := s.put("DB_PASSWORD", "s3cr3tvalue", "orgA"); err != nil {
		t.Fatal(err)
	}
	if err := s.put("OTHER_ORG_SECRET", "s3cr3tvalue", "orgB"); err != nil {
		t.Fatal(err)
	}

	if pairs, refusal := resolveInjection(s, nil); refusal != "" || pairs != nil {
		t.Errorf("no injection names produced %v / %q", pairs, refusal)
	}
	pairs, refusal := resolveInjection(s, []string{"DB_PASSWORD"})
	if refusal != "" {
		t.Fatalf("own-org name refused: %s", refusal)
	}
	if len(pairs) != 1 || pairs[0] != "DB_PASSWORD=s3cr3tvalue" {
		t.Errorf("pairs = %v", pairs)
	}
	// Another org's entry is unknown here.
	_, refusal = resolveInjection(s, []string{"OTHER_ORG_SECRET"})
	if refusal == "" || !strings.Contains(refusal, "OTHER_ORG_SECRET") {
		t.Errorf("foreign-org entry: refusal = %q", refusal)
	}
	if strings.Contains(refusal, "s3cr3tvalue") {
		t.Errorf("refusal leaked a value: %q", refusal)
	}
	// A missing name refuses, naming the name.
	_, refusal = resolveInjection(s, []string{"MISSING_KEY"})
	if refusal == "" || !strings.Contains(refusal, "MISSING_KEY") {
		t.Errorf("missing name: refusal = %q", refusal)
	}
	// Reserved names cannot be stored, so they must not be injectable either.
	_, refusal = resolveInjection(s, []string{"MACH_TOKEN"})
	if refusal == "" {
		t.Error("a reserved name was accepted for injection")
	}
	// No org: everything refuses with the re-enroll message, never a guess.
	noOrg := newFileSecretStore(t.TempDir(), "")
	_, refusal = resolveInjection(noOrg, []string{"DB_PASSWORD"})
	if refusal == "" || !strings.Contains(refusal, "re-enroll") {
		t.Errorf("no-org injection refusal = %q", refusal)
	}
}

// End to end through runCommandResult: a resolved value reaches the command's
// environment and is scrubbed back out of the result; a missing name refuses
// with the policy refusal's exit-code convention.
func TestRunCommandResultInjectsAndScrubs(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shell quoting differs on windows")
	}
	globalPolicy.install("")
	withSecretStore(t, newMemSecretStore("orgA"))

	mem := activeSecrets().(*memSecretStore)
	if err := mem.add("DB_PASSWORD", "s3cr3tvalue"); err != nil {
		t.Fatal(err)
	}
	sem := make(chan struct{}, maxConcurrentExec)

	payload, _ := json.Marshal(protocol.ExecCommand{Command: "echo $DB_PASSWORD", InjectEnv: []string{"DB_PASSWORD"}})
	res := runCommandResult(payload, sem)
	if res.ExitCode != 0 {
		t.Fatalf("exit = %d (%s)", res.ExitCode, res.Error)
	}
	if strings.Contains(res.Stdout, "s3cr3tvalue") {
		t.Errorf("the value crossed the wire in the output: %q", res.Stdout)
	}
	if !strings.Contains(res.Stdout, "[REDACTED:DB_PASSWORD]") {
		t.Errorf("output was not scrubbed: %q", res.Stdout)
	}
	// The base64 exact-bytes form is scrubbed too — it is decoded and checked.
	if res.StdoutB64 != "" {
		raw, err := base64.StdEncoding.DecodeString(res.StdoutB64)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(raw), "s3cr3tvalue") || !strings.Contains(string(raw), "[REDACTED:DB_PASSWORD]") {
			t.Errorf("the exact-bytes form was not scrubbed: %q", raw)
		}
	}

	// A missing name refuses before the command runs, exit 126.
	payload, _ = json.Marshal(protocol.ExecCommand{Command: "echo hi", InjectEnv: []string{"MISSING_KEY"}})
	res = runCommandResult(payload, sem)
	if res.ExitCode != 126 {
		t.Errorf("missing secret exit = %d, want 126 (%s)", res.ExitCode, res.Error)
	}
	if !strings.Contains(res.Error, "MISSING_KEY") || strings.Contains(res.Error, "s3cr3tvalue") {
		t.Errorf("refusal = %q", res.Error)
	}
	if !isSecretsRefusal(res) {
		t.Error("the refusal was not recognized as a secrets refusal (no re-announce would happen)")
	}

	// A command with no injection is untouched — including the no-op scrub.
	payload, _ = json.Marshal(protocol.ExecCommand{Command: "echo plain"})
	res = runCommandResult(payload, sem)
	if res.ExitCode != 0 || strings.TrimSpace(res.Stdout) != "plain" {
		t.Errorf("plain command changed: exit %d, stdout %q (%s)", res.ExitCode, res.Stdout, res.Error)
	}
}

// Scrubbing covers every stored value, not just the injected ones: a command
// that cats the store file has its output scrubbed too.
func TestRunCommandResultScrubsTheStoreFileItself(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shell quoting differs on windows")
	}
	globalPolicy.install("")
	dir := t.TempDir()
	s := newFileSecretStore(dir, "orgA")
	if err := s.put("DB_PASSWORD", "s3cr3tvalue", "orgA"); err != nil {
		t.Fatal(err)
	}
	withSecretStore(t, s)

	payload, _ := json.Marshal(protocol.ExecCommand{Command: "cat " + filepath.Join(dir, "secrets.json")})
	res := runCommandResult(payload, make(chan struct{}, maxConcurrentExec))
	if res.ExitCode != 0 {
		t.Fatalf("exit = %d (%s)", res.ExitCode, res.Error)
	}
	if strings.Contains(res.Stdout, "s3cr3tvalue") {
		t.Errorf("`cat secrets.json` leaked the value: %q", res.Stdout)
	}
	if !strings.Contains(res.Stdout, "[REDACTED:DB_PASSWORD]") {
		t.Errorf("store contents were not scrubbed: %q", res.Stdout)
	}
}

func sealTestPush(t *testing.T, kp *E2EKeyPair, sp protocol.SecretPayload) []byte {
	t.Helper()
	inner, err := json.Marshal(sp)
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := e2e.Seal(kp.Public[:], inner)
	if err != nil {
		t.Fatal(err)
	}
	payload, err := json.Marshal(protocol.SealedSecretPush{SealedB64: base64.StdEncoding.EncodeToString(sealed)})
	if err != nil {
		t.Fatal(err)
	}
	return payload
}

func TestSecretPushOutcome(t *testing.T) {
	kp, err := NewE2EKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	const value = "s3cr3tvalue"

	t.Run("valid push writes and announces", func(t *testing.T) {
		dir := t.TempDir()
		s := newFileSecretStore(dir, "orgA")
		res, announce := secretPushOutcome(kp, s, sealTestPush(t, kp, protocol.SecretPayload{
			Name: "DB_PASSWORD", Org: "orgA", Value: value,
		}))
		if !res.OK || res.Name != "DB_PASSWORD" || res.Error != "" {
			t.Fatalf("result = %+v", res)
		}
		if !announce {
			t.Error("a successful push did not announce")
		}
		got, ok, err := s.resolve("DB_PASSWORD")
		if err != nil || !ok || got != value {
			t.Fatalf("stored = %q ok=%v err=%v", got, ok, err)
		}
		// CreatedAt/UpdatedAt recorded.
		d, err := s.load()
		if err != nil {
			t.Fatal(err)
		}
		if d.Secrets["DB_PASSWORD"].CreatedAt == "" || d.Secrets["DB_PASSWORD"].UpdatedAt == "" {
			t.Error("timestamps not recorded")
		}
	})

	t.Run("org mismatch refused and nothing written", func(t *testing.T) {
		dir := t.TempDir()
		s := newFileSecretStore(dir, "orgA")
		res, announce := secretPushOutcome(kp, s, sealTestPush(t, kp, protocol.SecretPayload{
			Name: "DB_PASSWORD", Org: "orgB", Value: value,
		}))
		if res.OK || announce {
			t.Fatalf("a foreign-org push was accepted: %+v", res)
		}
		if _, _, err := s.resolve("DB_PASSWORD"); err != nil {
			t.Fatalf("resolve: %v", err)
		}
		if names, _ := s.names(); len(names) != 0 {
			t.Errorf("a refused push wrote an entry: %v", names)
		}
		if strings.Contains(res.Error, value) {
			t.Errorf("the refusal leaked the value: %q", res.Error)
		}
	})

	t.Run("no-org machine refused", func(t *testing.T) {
		s := newFileSecretStore(t.TempDir(), "")
		res, _ := secretPushOutcome(kp, s, sealTestPush(t, kp, protocol.SecretPayload{
			Name: "DB_PASSWORD", Org: "", Value: value,
		}))
		if res.OK || !strings.Contains(res.Error, "re-enroll") {
			t.Errorf("no-org push = %+v (error %q)", res.OK, res.Error)
		}
	})

	t.Run("temporary session refused", func(t *testing.T) {
		dir := t.TempDir()
		s := newMemSecretStore("orgA")
		res, announce := secretPushOutcome(kp, s, sealTestPush(t, kp, protocol.SecretPayload{
			Name: "DB_PASSWORD", Org: "orgA", Value: value,
		}))
		if res.OK || announce {
			t.Fatalf("a push to a temporary session was accepted: %+v", res)
		}
		if !strings.Contains(res.Error, "temporary session holds no persistent secrets") {
			t.Errorf("refusal = %q", res.Error)
		}
		if strings.Contains(res.Error, value) {
			t.Errorf("the refusal leaked the value: %q", res.Error)
		}
		// And nothing was written to the state dir the session would use.
		if _, err := os.Stat(filepath.Join(dir, "secrets.json")); !os.IsNotExist(err) {
			t.Errorf("a temporary session wrote a secrets file: %v", err)
		}
	})

	t.Run("unopenable blob refused", func(t *testing.T) {
		s := newFileSecretStore(t.TempDir(), "orgA")
		payload, _ := json.Marshal(protocol.SealedSecretPush{SealedB64: "not base64!!"})
		res, _ := secretPushOutcome(kp, s, payload)
		if res.OK || res.Error == "" {
			t.Errorf("garbage blob = %+v", res)
		}
	})
}

func TestSecretListResultAndAnnounce(t *testing.T) {
	dir := t.TempDir()
	s := newFileSecretStore(dir, "orgA")
	for name, org := range map[string]string{
		"API_KEY":      "orgA",
		"DB_PASSWORD":  "orgA",
		"OTHER_ORG_S1": "orgB",
	} {
		if err := s.put(name, "s3cr3tvalue", org); err != nil {
			t.Fatal(err)
		}
	}

	res := secretListResult(s)
	if res.Org != "orgA" {
		t.Errorf("org = %q", res.Org)
	}
	// Sorted, org-filtered, names only.
	if len(res.Names) != 2 || res.Names[0] != "API_KEY" || res.Names[1] != "DB_PASSWORD" {
		t.Errorf("names = %v", res.Names)
	}
	for _, n := range res.Names {
		if n == "OTHER_ORG_S1" {
			t.Error("a foreign-org entry was listed")
		}
	}

	env := announceEnvelope(s)
	if env == nil || env.Type != "secrets_announce" {
		t.Fatalf("announce envelope = %+v", env)
	}
	var ann protocol.SecretsAnnounce
	if err := json.Unmarshal(env.Payload, &ann); err != nil {
		t.Fatal(err)
	}
	if ann.Org != "orgA" || len(ann.Names) != 2 {
		t.Errorf("announce = %+v", ann)
	}

	// No org: nothing to announce, nothing to list.
	noOrg := newFileSecretStore(t.TempDir(), "")
	if env := announceEnvelope(noOrg); env != nil {
		t.Errorf("a no-org machine announced: %+v", env)
	}
	if res := secretListResult(noOrg); res.Org != "" || len(res.Names) != 0 {
		t.Errorf("no-org list = %+v", res)
	}
}

// The temporary session's store: memory only. Injection works from memory, a
// push is refused (covered above), and nothing is ever written to the state
// directory — invariant 23.
func TestTemporarySessionMemoryStore(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("MACH_STATE_DIR", dir)
	s := newMemSecretStore("orgA")
	if err := s.add("DB_PASSWORD", "s3cr3tvalue"); err != nil {
		t.Fatal(err)
	}
	pairs, refusal := resolveInjection(s, []string{"DB_PASSWORD"})
	if refusal != "" || len(pairs) != 1 || pairs[0] != "DB_PASSWORD=s3cr3tvalue" {
		t.Fatalf("memory injection = %v / %q", pairs, refusal)
	}
	// A foreign-org entry in memory is as unknown as on disk.
	if err := s.add("OTHER_ORG_S1", "s3cr3tvalue"); err != nil {
		t.Fatal(err)
	}
	s.mu.Lock()
	s.entries["OTHER_ORG_S1"].Org = "orgB"
	s.mu.Unlock()
	if _, ok, _ := s.resolve("OTHER_ORG_S1"); ok {
		t.Error("a foreign-org memory entry resolved")
	}
	if _, err := os.Stat(filepath.Join(dir, "secrets.json")); !os.IsNotExist(err) {
		t.Errorf("a temporary session's store touched the state dir: %v", err)
	}
	// A memory store with no org refuses injection, like every other path.
	_, refusal = resolveInjection(newMemSecretStore(""), []string{"DB_PASSWORD"})
	if refusal == "" {
		t.Error("a no-org memory store injected a secret")
	}
}

// The scrubber built from a store read is what the exec paths use; the
// appendEnvValues helper is what makes "later entries win" hold on execve.
func TestAppendEnvValuesLaterEntriesWin(t *testing.T) {
	base := []string{"A=1", "DB_PASSWORD=stale", "B=2"}
	out := appendEnvValues(base, []string{"DB_PASSWORD=new", "C=3"})
	joined := strings.Join(out, "\n")
	if strings.Contains(joined, "stale") {
		t.Errorf("the stale value survived: %q", joined)
	}
	if !strings.Contains(joined, "DB_PASSWORD=new") || !strings.Contains(joined, "C=3") || !strings.Contains(joined, "A=1") {
		t.Errorf("appendEnvValues = %q", joined)
	}
}
