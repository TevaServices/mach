package console

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/TevaServices/mach/internal/e2e"
	"github.com/TevaServices/mach/internal/protocol"
	"github.com/gorilla/websocket"
)

// capture runs f with os.Stdout/os.Stderr redirected and returns what it wrote
// to each.
func capture(t *testing.T, f func()) (stdout, stderr string) {
	t.Helper()
	origOut, origErr := os.Stdout, os.Stderr
	outR, outW, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	errR, errW, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	os.Stdout, os.Stderr = outW, errW
	defer func() { os.Stdout, os.Stderr = origOut, origErr }()

	f()
	outW.Close()
	errW.Close()

	ob, _ := io.ReadAll(outR)
	eb, _ := io.ReadAll(errR)
	outR.Close()
	errR.Close()
	return string(ob), string(eb)
}

// fakeRelay stands in for the control plane's streaming endpoint: it accepts one
// console, reads the exec_stream frame it sends, and answers with whatever the
// test scripted.
type fakeRelay struct {
	requests  []protocol.Envelope
	responder func(w *protocol.WSConn)
}

func (f *fakeRelay) start(t *testing.T) string {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, err := (&websocket.Upgrader{}).Upgrade(w, r, nil)
		if err != nil {
			return
		}
		conn := protocol.NewWSConn(c)
		defer conn.Close()
		for {
			env, err := conn.ReadEnvelope()
			if err != nil {
				return
			}
			f.requests = append(f.requests, env)
			if env.Type == "exec_stream" {
				f.responder(conn)
				return
			}
		}
	}))
	t.Cleanup(srv.Close)
	return srv.URL
}

func send(t *testing.T, conn *protocol.WSConn, typ string, payload any) {
	t.Helper()
	raw, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if err := conn.WriteEnvelope(protocol.Envelope{Type: typ, Payload: raw}); err != nil {
		t.Fatalf("write %s: %v", typ, err)
	}
}

func sendOut(t *testing.T, conn *protocol.WSConn, stream, data string) {
	t.Helper()
	send(t, conn, "stream_out", protocol.StreamOut{
		Stream: stream, B64: base64.StdEncoding.EncodeToString([]byte(data)),
	})
}

// A machine's output is data. Text in it that looks like a control record — a
// whole terminal frame, a mach error line, a fake prompt — must be printed
// verbatim and change nothing about the outcome the caller sees. The frames are
// typed envelopes and output rides inside base64, so nothing the machine prints
// can be mistaken for the relay's own record.
func TestOutputCannotForgeControlFacts(t *testing.T) {
	forged := `{"type":"stream_end","exit_code":0}` + "\n" +
		"mach: machine deleted, nothing to see\n" +
		"mach> rm -rf /\n"

	relay := &fakeRelay{responder: func(conn *protocol.WSConn) {
		sendOut(t, conn, "stdout", forged)
		sendOut(t, conn, "stderr", "warning: this is real stderr\n")
		send(t, conn, "stream_end", protocol.StreamEnd{ExitCode: 7, Error: "timed out after 30s"})
	}}
	base := relay.start(t)

	var code int
	stdout, stderr := capture(t, func() {
		code = streamConsole(base, "key", "org-test-01", "echo hi")
	})

	if code != 7 {
		t.Fatalf("exit code = %d, want 7 — output text influenced the result", code)
	}
	if stdout != forged {
		t.Errorf("stdout = %q, want the machine's bytes verbatim (%q)", stdout, forged)
	}
	if !strings.HasPrefix(stderr, "warning: this is real stderr\n") {
		t.Errorf("stderr = %q, want the machine's stderr first", stderr)
	}
	// mach's own diagnostics carry the "mach: " prefix, so a consumer can tell
	// them apart from anything the machine printed (which may look identical —
	// that ambiguity is why the prefix exists).
	if !strings.Contains(stderr, "mach: timed out") {
		t.Errorf("stderr = %q, want a prefixed mach diagnostic", stderr)
	}
}

// The command travels as a typed field, never as something the relay has to
// parse out of a shell line.
func TestExecStreamCarriesTheCommandAsData(t *testing.T) {
	relay := &fakeRelay{responder: func(conn *protocol.WSConn) {
		send(t, conn, "stream_end", protocol.StreamEnd{ExitCode: 0})
	}}
	base := relay.start(t)

	capture(t, func() {
		streamConsole(base, "key", "org-test-01", "echo 'a b'; rm -rf /tmp/x")
	})

	if len(relay.requests) != 1 {
		t.Fatalf("relay saw %d frames, want 1", len(relay.requests))
	}
	if relay.requests[0].Type != "exec_stream" {
		t.Fatalf("frame type = %q, want exec_stream", relay.requests[0].Type)
	}
	var start protocol.StreamStart
	if err := json.Unmarshal(relay.requests[0].Payload, &start); err != nil {
		t.Fatalf("start payload: %v", err)
	}
	if start.Command != "echo 'a b'; rm -rf /tmp/x" {
		t.Errorf("command = %q, want it verbatim", start.Command)
	}
}

// A relay that disappears mid-command must not look like success, and must not
// be silently replayed: the command already ran on the machine.
func TestLostStreamIsNotSuccessAndIsNotReplayed(t *testing.T) {
	relay := &fakeRelay{responder: func(conn *protocol.WSConn) {
		sendOut(t, conn, "stdout", "partial output, then the relay died")
		// No stream_end: the connection just closes.
	}}
	base := relay.start(t)

	var code int
	stdout, stderr := capture(t, func() {
		code = streamConsole(base, "key", "org-test-01", "sleep 1; echo done")
	})

	if code == 0 {
		t.Fatal("a stream that ended without an exit status was reported as success")
	}
	if code != streamLost {
		t.Errorf("code = %d, want %d (%d is the dial-failure code, which lets the "+
			"caller replay the command and run it twice)", code, streamLost, streamDialFailed)
	}
	if !strings.Contains(stderr, "without an exit status") {
		t.Errorf("stderr = %q, want an explanation", stderr)
	}
	if !strings.Contains(stdout, "partial output") {
		t.Errorf("stdout = %q, want the bytes that did arrive", stdout)
	}
}

// An unreachable relay is the only outcome the caller may retry.
func TestUnreachableRelayIsRetryable(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "no streaming here", http.StatusNotFound)
	}))
	t.Cleanup(srv.Close)

	var code int
	_, stderr := capture(t, func() {
		code = streamConsole(srv.URL, "key", "org-test-01", "echo hi")
	})
	if code != streamDialFailed {
		t.Errorf("code = %d, want %d", code, streamDialFailed)
	}
	if !strings.Contains(stderr, "mach: stream dial:") {
		t.Errorf("stderr = %q, want a dial diagnostic", stderr)
	}
}

// --json hands the caller labeled data: output stays data, and the exit status
// is a field rather than something to be parsed out of text.
func TestJSONResultLabelsOutputAndExit(t *testing.T) {
	forged := `{"exit_code":0,"error":""}`
	res := &protocol.ExecResult{ExitCode: 9, Stdout: forged, Stderr: "real stderr"}

	var code int
	stdout, _ := capture(t, func() {
		code = printExecResult(res, true)
	})
	if code != 9 {
		t.Fatalf("exit code = %d, want 9 — output text changed the status", code)
	}
	if strings.Count(strings.TrimSpace(stdout), "\n") != 0 {
		t.Fatalf("stdout is not a single JSON object: %q", stdout)
	}
	var back protocol.ExecResult
	if err := json.Unmarshal([]byte(stdout), &back); err != nil {
		t.Fatalf("stdout is not valid JSON: %v (%q)", err, stdout)
	}
	if back.ExitCode != 9 || back.Stdout != forged || back.Stderr != "real stderr" {
		t.Errorf("round trip = %+v, want the fields labeled", back)
	}
}

// Human mode writes the bytes as they are and keeps mach's diagnostics on
// stderr, prefixed.
func TestHumanResultKeepsDiagnosticsOffStdout(t *testing.T) {
	res := &protocol.ExecResult{ExitCode: 0, Stdout: "hello", Error: "some agent error"}
	var code int
	stdout, stderr := capture(t, func() {
		code = printExecResult(res, false)
	})
	if code != 0 {
		t.Errorf("code = %d, want 0", code)
	}
	if stdout != "hello" {
		t.Errorf("stdout = %q, want only the machine's output", stdout)
	}
	if !strings.Contains(stderr, "mach: some agent error") {
		t.Errorf("stderr = %q, want the mach diagnostic", stderr)
	}
}

// fakeExecServer plays a control plane's one-shot exec surface: it publishes the
// E2E signal, then either answers a sealed command (opening it with a real X25519
// key and sealing the reply) or an error. What it records is exactly what went
// over the wire, which is the only thing that can prove a command was sealed.
type fakeExecServer struct {
	srv     *httptest.Server
	key     *e2e.KeyPair // the machine's E2E key, when it has one
	enabled bool         // what the control plane says it accepts

	mu       sync.Mutex
	requests [][]byte // bodies the server received
	pubCalls int
	// refuseSealed makes the server answer a sealed command the way it does when
	// the setting changed under the client: 403 with the reason.
	refuseSealed bool
	// sealedStatus answers a sealed command with that status instead of a
	// result. 504 is what the control plane returns when it dispatched the
	// command and the agent did not answer in time — the reply is lost, but the
	// command may well have run, which is the case the console must not retry.
	sealedStatus int
}

func newFakeExecServer(t *testing.T, enabled bool, withKey bool) *fakeExecServer {
	t.Helper()
	f := &fakeExecServer{enabled: enabled}
	if withKey {
		kp, err := e2e.GenerateKeyPair()
		if err != nil {
			t.Fatalf("keygen: %v", err)
		}
		f.key = kp
	}
	f.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/e2epub") {
			f.mu.Lock()
			f.pubCalls++
			f.mu.Unlock()
			resp := map[string]any{"machine": "org-test-01", "e2e": "off", "e2e_enabled": f.enabled}
			if f.enabled && f.key != nil {
				resp["e2e"] = "on"
				resp["pub_e2e"] = f.key.PublicKeyHex()
			} else if f.enabled {
				resp["e2e"] = "on"
				resp["note"] = "machine has no E2E key — re-enroll to enable E2E"
			} else {
				resp["e2e_reason"] = "sealed exec is disabled on this control plane; " +
					"commands run in plaintext, where the fleet-wide block list can read them " +
					"(turn E2E back on with `mach-server e2e on`)"
			}
			_ = json.NewEncoder(w).Encode(resp)
			return
		}
		body, _ := io.ReadAll(r.Body)
		f.mu.Lock()
		f.requests = append(f.requests, body)
		f.mu.Unlock()

		var req struct {
			Sealed string `json:"sealed"`
			E2EPub string `json:"e2e_pub"`
		}
		_ = json.Unmarshal(body, &req)
		if req.Sealed == "" {
			_ = json.NewEncoder(w).Encode(protocol.ExecResult{ExitCode: 0, Stdout: "plain\n"})
			return
		}
		if f.refuseSealed || !f.enabled {
			w.WriteHeader(http.StatusForbidden)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": "sealed exec is disabled on this control plane"})
			return
		}
		if f.sealedStatus != 0 {
			w.WriteHeader(f.sealedStatus)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": "timed out waiting for agent result"})
			return
		}
		// Open the sealed command with the machine's key: this is what an agent
		// does, and it is the only way to be sure the console sealed to the key
		// the control plane published rather than to something else.
		raw, err := base64.StdEncoding.DecodeString(req.Sealed)
		if err != nil {
			t.Errorf("sealed field is not base64: %v", err)
			return
		}
		inner, err := e2e.Open(&f.key.Private, raw)
		if err != nil {
			t.Errorf("machine could not open the sealed command: %v", err)
			return
		}
		var cmd struct {
			Command string   `json:"command"`
			Argv    []string `json:"argv"`
		}
		_ = json.Unmarshal(inner, &cmd)

		replyKey, err := hex.DecodeString(req.E2EPub)
		if err != nil || len(replyKey) != 32 {
			t.Errorf("e2e_pub is not a 32-byte hex key: %q", req.E2EPub)
			return
		}
		res, _ := json.Marshal(protocol.ExecResult{ExitCode: 0, Stdout: "sealed:" + cmd.Command + "\n"})
		sealedReply, err := e2e.Seal(replyKey, res)
		if err != nil {
			t.Errorf("seal reply: %v", err)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"exit_code": 0, "sealed_b64": base64.StdEncoding.EncodeToString(sealedReply),
		})
	}))
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeExecServer) client() *client {
	return New(&Config{Server: f.srv.URL, APIKey: "mach_test"})
}

func (f *fakeExecServer) bodies() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]string, 0, len(f.requests))
	for _, b := range f.requests {
		out = append(out, string(b))
	}
	return out
}

// When the control plane accepts sealed commands and the machine has a key, the
// console seals — and nothing in the request carries the command in the clear.
func TestExecSealsWhenTheServerAcceptsIt(t *testing.T) {
	pinState(t)
	f := newFakeExecServer(t, true, true)
	var code int
	stdout, stderr := capture(t, func() {
		code = f.client().Exec("org-test-01", "echo sealed-marker", 0, false, E2EObey)
	})
	if code != 0 {
		t.Fatalf("code = %d, want 0 (%s)", code, stderr)
	}
	if !strings.Contains(stdout, "sealed:echo sealed-marker") {
		t.Errorf("stdout = %q, want the reply, decrypted and printed", stdout)
	}
	bodies := f.bodies()
	if len(bodies) != 1 {
		t.Fatalf("server saw %d requests, want 1", len(bodies))
	}
	// The command must not appear anywhere in what the control plane received.
	if strings.Contains(bodies[0], "sealed-marker") {
		t.Errorf("the command went over the wire in the clear: %s", bodies[0])
	}
	// One line about pinning the key, and nothing else: the first sealed command
	// to a machine is the one moment there is no protection, so it is reported.
	if !strings.Contains(stderr, "pinned the E2E key") {
		t.Errorf("stderr = %q, want the pinning reported once", stderr)
	}
}

// E2E off is the server's decision: the console obeys it and runs the command in
// plaintext. It does not seal to a key the server would refuse, and it does not
// nag — the operator configured this.
func TestExecObeysTheServerWhenE2EIsOff(t *testing.T) {
	f := newFakeExecServer(t, false, true)
	var code int
	stdout, stderr := capture(t, func() {
		code = f.client().Exec("org-test-01", "echo plain-marker", 0, false, E2EObey)
	})
	if code != 0 {
		t.Fatalf("code = %d, want 0 (%s)", code, stderr)
	}
	if !strings.Contains(stdout, "plain") {
		t.Errorf("stdout = %q, want the plaintext result", stdout)
	}
	bodies := f.bodies()
	if len(bodies) != 1 {
		t.Fatalf("server saw %d requests, want 1", len(bodies))
	}
	if !strings.Contains(bodies[0], "plain-marker") {
		t.Errorf("the command was not sent as plaintext: %s", bodies[0])
	}
	if strings.Contains(bodies[0], "sealed") {
		t.Errorf("the console sealed a command the server said it would refuse: %s", bodies[0])
	}
}

// The control plane accepts sealing but this machine never registered a key.
// Obeying means plaintext — and saying so, because silence here is how an
// operator ends up believing a command was encrypted when it was not.
func TestExecWarnsWhenTheMachineHasNoKey(t *testing.T) {
	f := newFakeExecServer(t, true, false)
	var code int
	_, stderr := capture(t, func() {
		code = f.client().Exec("org-test-01", "echo hi", 0, false, E2EObey)
	})
	if code != 0 {
		t.Fatalf("code = %d, want 0", code)
	}
	if !strings.Contains(stderr, "has no E2E key") || !strings.Contains(stderr, "plaintext") {
		t.Errorf("stderr = %q, want a line saying it ran in plaintext and why", stderr)
	}
}

// --e2e means "seal it or do not run it". When the server will not accept a
// sealed command, the console exits with a message instead of quietly sending
// plaintext — the whole point of asking.
func TestExecRequireExitsWithAMessageWhenServerRefuses(t *testing.T) {
	f := newFakeExecServer(t, false, true)
	var code int
	stdout, stderr := capture(t, func() {
		code = f.client().Exec("org-test-01", "echo secret", 0, false, E2ERequire)
	})
	if code == 0 {
		t.Fatal("--e2e reported success without sealing anything")
	}
	if stdout != "" {
		t.Errorf("stdout = %q, want nothing: the command must not have run", stdout)
	}
	if !strings.Contains(stderr, "cannot seal") || !strings.Contains(stderr, "disabled") {
		t.Errorf("stderr = %q, want it to say sealing is unavailable and why", stderr)
	}
	if n := len(f.bodies()); n != 0 {
		t.Errorf("the console sent %d request(s) anyway: %v", n, f.bodies())
	}
}

// Same for a machine with no key: --e2e cannot be honoured, so it fails loudly.
func TestExecRequireFailsWhenTheMachineHasNoKey(t *testing.T) {
	f := newFakeExecServer(t, true, false)
	var code int
	_, stderr := capture(t, func() {
		code = f.client().Exec("org-test-01", "echo hi", 0, false, E2ERequire)
	})
	if code == 0 {
		t.Fatal("--e2e reported success for a machine that cannot be sealed to")
	}
	if !strings.Contains(stderr, "has no E2E key") {
		t.Errorf("stderr = %q, want it to name the reason", stderr)
	}
	if n := len(f.bodies()); n != 0 {
		t.Errorf("a command was sent anyway: %v", f.bodies())
	}
}

// --no-e2e: the operator wants this command readable (by the block list, by the
// audit log). The console does not even ask what the server accepts.
func TestExecForbidNeverSealsAndDoesNotAsk(t *testing.T) {
	f := newFakeExecServer(t, true, true)
	var code int
	stdout, _ := capture(t, func() {
		code = f.client().Exec("org-test-01", "echo readable", 0, false, E2EForbid)
	})
	if code != 0 {
		t.Fatalf("code = %d, want 0", code)
	}
	if !strings.Contains(stdout, "plain") {
		t.Errorf("stdout = %q, want the plaintext result", stdout)
	}
	f.mu.Lock()
	calls := f.pubCalls
	f.mu.Unlock()
	if calls != 0 {
		t.Errorf("the console asked for the E2E signal %d time(s) despite --no-e2e", calls)
	}
	bodies := f.bodies()
	if len(bodies) != 1 || !strings.Contains(bodies[0], "readable") {
		t.Errorf("bodies = %v, want one plaintext request", bodies)
	}
}

// A sealed command refused mid-flight (the setting changed between reading it
// and sending) is retried in plaintext — the command never ran, so that is not a
// second execution — and the downgrade is announced rather than silent.
func TestExecRetriesPlaintextWhenSealingIsRefusedMidFlight(t *testing.T) {
	pinState(t)
	f := newFakeExecServer(t, true, true)
	f.refuseSealed = true
	var code int
	stdout, stderr := capture(t, func() {
		code = f.client().Exec("org-test-01", "echo retry-marker", 0, false, E2EObey)
	})
	if code != 0 {
		t.Fatalf("code = %d, want 0 (%s)", code, stderr)
	}
	if !strings.Contains(stdout, "plain") {
		t.Errorf("stdout = %q, want the plaintext result after the retry", stdout)
	}
	if !strings.Contains(stderr, "retrying in plaintext") {
		t.Errorf("stderr = %q, want the downgrade announced", stderr)
	}
	bodies := f.bodies()
	if len(bodies) != 2 {
		t.Fatalf("bodies = %v, want a sealed attempt then a plaintext one", bodies)
	}
	if !strings.Contains(bodies[1], "retry-marker") {
		t.Errorf("the retry was not plaintext: %s", bodies[1])
	}
	// And --e2e does not retry: it reports the refusal instead.
	f2 := newFakeExecServer(t, true, true)
	f2.refuseSealed = true
	// The same machine, so the same key: two fake control planes that advertised
	// different keys for one machine would (correctly) be refused as a
	// substitution before any of this is reached.
	f2.key = f.key
	var code2 int
	_, stderr2 := capture(t, func() {
		code2 = f2.client().Exec("org-test-01", "echo retry-marker", 0, false, E2ERequire)
	})
	if code2 == 0 || !strings.Contains(stderr2, "cannot seal") {
		t.Errorf("--e2e after a refusal: code=%d stderr=%q, want a failure with a message", code2, stderr2)
	}
	if n := len(f2.bodies()); n != 1 {
		t.Errorf("--e2e sent %d requests, want only the sealed attempt", n)
	}
}

// pinState points the client's pin store at a fresh temp dir and returns the
// file's path, so a test can inspect what was written.
func pinState(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("MACH_STATE_DIR", dir)
	return filepath.Join(dir, pinsFileName)
}

// The key comes from the control plane — the party the seal protects against —
// so the console remembers the first one it is given and seals only to that. The
// first use is also the one moment the operator has no protection at all, so it
// says so rather than pinning silently.
func TestFirstUsePinsTheKeyAndSaysSo(t *testing.T) {
	pinPath := pinState(t)
	f := newFakeExecServer(t, true, true)

	var code int
	stdout, stderr := capture(t, func() {
		code = f.client().Exec("org-test-01", "echo sealed-marker", 0, false, E2EObey)
	})
	if code != 0 || !strings.Contains(stdout, "sealed:echo sealed-marker") {
		t.Fatalf("code = %d stdout = %q stderr = %q", code, stdout, stderr)
	}
	if !strings.Contains(stderr, "pinned the E2E key for org-test-01") {
		t.Errorf("stderr = %q, want a line saying the key was pinned", stderr)
	}
	if !strings.Contains(stderr, KeyFingerprint(f.key.PublicKeyHex())) {
		t.Errorf("stderr = %q, want the fingerprint that was pinned", stderr)
	}

	// It is on disk, 0600, and it is the key that was advertised.
	st, err := os.Stat(pinPath)
	if err != nil {
		t.Fatalf("pin file: %v", err)
	}
	if st.Mode().Perm() != 0o600 {
		t.Errorf("pin file mode = %v, want 0600", st.Mode().Perm())
	}
	var f2 struct {
		Machines map[string]struct {
			PubE2E string `json:"pub_e2e"`
		} `json:"machines"`
	}
	raw, _ := os.ReadFile(pinPath)
	if err := json.Unmarshal(raw, &f2); err != nil {
		t.Fatalf("pin file is not JSON: %v (%s)", err, raw)
	}
	if f2.Machines["org-test-01"].PubE2E != f.key.PublicKeyHex() {
		t.Errorf("pinned key = %q, want the advertised one", f2.Machines["org-test-01"].PubE2E)
	}

	// The second command seals without comment: the pin is established, and a
	// notice on every command would be noise that trains people to ignore it.
	_, stderr = capture(t, func() {
		f.client().Exec("org-test-01", "echo again", 0, false, E2EObey)
	})
	if stderr != "" {
		t.Errorf("stderr = %q, want no notice once the key is pinned", stderr)
	}
}

// A changed key stops sealing, in every mode. This is the whole point: a control
// plane that swaps in its own key gets a refusal naming both keys, not a silent
// command in the clear and not a command sent to the attacker.
func TestChangedKeyRefusesToSeal(t *testing.T) {
	pinState(t)
	f := newFakeExecServer(t, true, true)

	// First use pins.
	capture(t, func() { f.client().Exec("org-test-01", "echo first", 0, false, E2EObey) })

	// The control plane now advertises a different key for the same machine.
	other, err := e2e.GenerateKeyPair()
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	f.key = other

	for _, mode := range []E2EMode{E2EObey, E2ERequire} {
		var code int
		stdout, stderr := capture(t, func() {
			code = f.client().Exec("org-test-01", "echo secret", 0, false, mode)
		})
		if code == 0 {
			t.Fatalf("mode %d: reported success with a changed key", mode)
		}
		if stdout != "" {
			t.Errorf("mode %d: stdout = %q — the command must not have run", mode, stdout)
		}
		if !strings.Contains(stderr, "E2E key for org-test-01 changed") {
			t.Errorf("mode %d: stderr = %q, want the change reported", mode, stderr)
		}
		// Both fingerprints, so the operator can see what changed and compare.
		if !strings.Contains(stderr, KeyFingerprint(f.key.PublicKeyHex())) ||
			!strings.Contains(stderr, KeyFingerprint(other.PublicKeyHex())) {
			t.Errorf("mode %d: stderr = %q, want both fingerprints", mode, stderr)
		}
		if !strings.Contains(stderr, "mach trust org-test-01") {
			t.Errorf("mode %d: stderr = %q, want the remedy named", mode, stderr)
		}
	}
	// Nothing was sent to the machine in either mode.
	if n := len(f.bodies()); n != 1 {
		t.Errorf("requests = %d, want only the pinned first command: %v", n, f.bodies())
	}
}

// `mach trust <machine>` is the only thing that accepts a changed key, and it
// reports both fingerprints when it does.
func TestTrustAcceptsAChangedKey(t *testing.T) {
	pinState(t)
	f := newFakeExecServer(t, true, true)
	capture(t, func() { f.client().Exec("org-test-01", "echo first", 0, false, E2EObey) })

	other, _ := e2e.GenerateKeyPair()
	f.key = other
	c := f.client()

	var fingerprint, previous string
	capture(t, func() {
		var err error
		fingerprint, previous, err = c.TrustMachine("org-test-01")
		if err != nil {
			t.Fatalf("trust: %v", err)
		}
	})
	if fingerprint != KeyFingerprint(other.PublicKeyHex()) {
		t.Errorf("fingerprint = %q, want the new key's", fingerprint)
	}
	if previous == "" || previous == fingerprint {
		t.Errorf("previous = %q, want the fingerprint that was replaced", previous)
	}

	// Sealing works again, to the new key — the fake server opens what it
	// receives with it, so a round trip is the proof.
	var code int
	stdout, stderr := capture(t, func() {
		code = c.Exec("org-test-01", "echo after-trust", 0, false, E2EObey)
	})
	if code != 0 || !strings.Contains(stdout, "sealed:echo after-trust") {
		t.Fatalf("after trust: code = %d stdout = %q stderr = %q", code, stdout, stderr)
	}
}

// --forget drops the pin, and the next sealed command pins again from scratch.
// That is the "turn the protection off for this machine" switch, and it is
// explicit by design.
func TestForgetDropsThePin(t *testing.T) {
	pinState(t)
	f := newFakeExecServer(t, true, true)
	capture(t, func() { f.client().Exec("org-test-01", "echo first", 0, false, E2EObey) })
	c := f.client()

	capture(t, func() {
		existed, err := c.ForgetMachine("org-test-01")
		if err != nil || !existed {
			t.Fatalf("forget: existed=%v err=%v", existed, err)
		}
	})
	if machines, _ := c.PinnedMachines(); len(machines) != 0 {
		t.Errorf("pins after forget = %v, want none", machines)
	}

	// A key that changed while there was no pin is accepted on the next use —
	// that is what forgetting means — and the pin is re-established.
	other, _ := e2e.GenerateKeyPair()
	f.key = other
	var code int
	_, stderr := capture(t, func() {
		code = f.client().Exec("org-test-01", "echo re-pinned", 0, false, E2EObey)
	})
	if code != 0 {
		t.Fatalf("after forget: code = %d stderr = %q", code, stderr)
	}
	if !strings.Contains(stderr, "pinned the E2E key") {
		t.Errorf("stderr = %q, want the re-pin reported", stderr)
	}
	if _, _, _, ok, _ := c.PinnedKey("org-test-01"); !ok {
		t.Error("the key was not pinned again")
	}
}

// --no-e2e never seals, so it never needs a key and must not create or consult
// the pin store: an operator asking for plaintext should not be touched by any of
// this.
func TestNoE2ELeavesThePinStoreAlone(t *testing.T) {
	pinPath := pinState(t)
	f := newFakeExecServer(t, true, true)

	var code int
	stdout, stderr := capture(t, func() {
		code = f.client().Exec("org-test-01", "echo plain", 0, false, E2EForbid)
	})
	if code != 0 || !strings.Contains(stdout, "plain") {
		t.Fatalf("code = %d stdout = %q stderr = %q", code, stdout, stderr)
	}
	if stderr != "" {
		t.Errorf("stderr = %q, want nothing said about keys", stderr)
	}
	if _, err := os.Stat(pinPath); !os.IsNotExist(err) {
		t.Errorf("the pin file exists after --no-e2e: %v", err)
	}
	f.mu.Lock()
	calls := f.pubCalls
	f.mu.Unlock()
	if calls != 0 {
		t.Errorf("the signal was fetched %d time(s) despite --no-e2e", calls)
	}
}

// The pin file is the thing that decides which key this console seals to, so a
// file it cannot read is an error, not an empty pin set: silently re-pinning
// would turn the protection off at exactly the moment something is wrong.
func TestUnreadablePinFileIsAnError(t *testing.T) {
	pinPath := pinState(t)
	if err := os.WriteFile(pinPath, []byte("{not json"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	f := newFakeExecServer(t, true, true)

	var code int
	stdout, stderr := capture(t, func() {
		code = f.client().Exec("org-test-01", "echo hi", 0, false, E2EObey)
	})
	if code == 0 {
		t.Fatal("a corrupt pin file did not stop sealing")
	}
	if stdout != "" {
		t.Errorf("stdout = %q, want nothing sent", stdout)
	}
	if !strings.Contains(stderr, "not readable as JSON") {
		t.Errorf("stderr = %q, want it to explain the pin file is unusable", stderr)
	}
	// It says what the fix is, including what deleting it costs.
	if !strings.Contains(stderr, "re-pins") {
		t.Errorf("stderr = %q, want the consequence of deleting it", stderr)
	}
}

// A sealed reply that never arrives is NOT a refusal, and must not be retried.
//
// This is the fix for a real double execution. The control plane answers 504
// when it dispatched a command and the agent did not reply in time, and the
// console's HTTP reader fails a reply larger than the protocol's bound — both
// were read as "the control plane refused the sealed form", and the plaintext
// retry that followed ran the command a *second* time, unsealed, while the
// operator saw correct-looking output and had no way to know. Nothing about the
// refusal reasoning holds for either: the command was dispatched, so a retry is
// a second execution, and a plaintext one.
func TestExecDoesNotRetryWhenTheSealedReplyIsLost(t *testing.T) {
	pinState(t)
	f := newFakeExecServer(t, true, true)
	f.sealedStatus = http.StatusGatewayTimeout

	var code int
	stdout, stderr := capture(t, func() {
		code = f.client().Exec("org-test-01", "echo must-not-run-twice", 0, false, E2EObey)
	})
	if code == 0 {
		t.Errorf("code = 0, want a failure: the reply was lost, not refused")
	}
	// The retry path announces itself with this exact prefix, and only it does:
	// asserting on the bare words "retrying in plaintext" would also match the
	// message explaining that there is no retry.
	if strings.Contains(stderr, "sealed exec refused") {
		t.Errorf("stderr = %q, want no plaintext retry", stderr)
	}
	if !strings.Contains(stderr, "not retrying in plaintext") {
		t.Errorf("stderr = %q, want the reason there is no retry", stderr)
	}
	if stdout != "" {
		t.Errorf("stdout = %q, want nothing — no result came back", stdout)
	}
	if n := len(f.bodies()); n != 1 {
		t.Fatalf("sent %d requests, want only the sealed attempt: %v", n, f.bodies())
	}

	// --e2e loses the same reply and must also not resend it.
	f2 := newFakeExecServer(t, true, true)
	f2.key, f2.sealedStatus = f.key, http.StatusGatewayTimeout
	var code2 int
	_, stderr2 := capture(t, func() {
		code2 = f2.client().Exec("org-test-01", "echo must-not-run-twice", 0, false, E2ERequire)
	})
	if code2 == 0 {
		t.Errorf("--e2e code = 0, want a failure")
	}
	if strings.Contains(stderr2, "cannot seal") {
		t.Errorf("--e2e stderr = %q: nothing was refused, the reply was lost", stderr2)
	}
	if n := len(f2.bodies()); n != 1 {
		t.Errorf("--e2e sent %d requests, want only the sealed attempt", n)
	}
}

// An unreadable console.json is not the same thing as no console.json. Treating
// every ReadFile error as "not configured" sent plain `mach` down the enrollment
// path, so an admin box whose config was restored with the wrong owner silently
// offered to enroll itself as a target machine — and `mach list` blamed a
// missing file that was right there. (The pin store already makes this
// distinction: an unreadable pin file is an error, never an empty pin set.)
func TestLoadConfigDistinguishesUnreadableFromAbsent(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("MACH_STATE_DIR", dir)

	// Absent: the "not configured" answer, which is what drives setup.
	if _, err := LoadConfig(); err == nil {
		t.Fatal("a missing console.json was accepted")
	} else if _, ok := err.(NotConfiguredError); !ok {
		t.Fatalf("missing config error = %T (%v), want NotConfiguredError", err, err)
	}

	// Present but unreadable: a real error, and specifically not "not configured".
	path := filepath.Join(dir, "console.json")
	if err := os.WriteFile(path, []byte(`{"server":"https://x","api_key":"mach_k"}`), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := os.Chmod(path, 0o000); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	if _, err := LoadConfig(); err == nil {
		t.Fatal("an unreadable console.json was accepted")
	} else if _, ok := err.(NotConfiguredError); ok {
		t.Fatal("an unreadable console.json was reported as not configured — plain `mach` would enroll this box")
	}
}
