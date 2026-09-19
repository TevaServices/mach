package protocol

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"unicode/utf8"
)

// Envelope is the only frame on the wire.
type Envelope struct {
	Type    string          `json:"type"`
	ReqID   string          `json:"req_id,omitempty"`
	Payload json.RawMessage `json:"payload,omitempty"`
}

// ---- agent -> control plane ----

type HelloRequest struct {
	Auth     string `json:"auth"`    // "v1 <base64 ed25519 signature>" over name|challenge (connection-bound)
	PubKey   string `json:"pub_key"` // hex
	Name     string `json:"name"`    // machine name (must match enrollment)
	AgentVer string `json:"agent_version,omitempty"`
	Hostname string `json:"hostname,omitempty"`
	OS       string `json:"os,omitempty"`
	Arch     string `json:"arch,omitempty"`
}

type HelloResponse struct {
	OK         bool   `json:"ok"`
	Error      string `json:"error,omitempty"`
	ServerVer  string `json:"server_version,omitempty"`
	ServerAuth string `json:"server_auth,omitempty"` // "v1 <base64 ed25519 sig>" by the server's identity key over "server|<challenge>"
}

// Output caps, and why they are two numbers rather than one.
//
// MaxOutputBytes bounds the *raw output* one stream may carry back: past it the
// agent truncates and marks the stream. MaxExecReplyBytes bounds the *encoded
// reply* a client will read for one command, and it is much larger on purpose.
// They used to be the same 8 MiB, which made the agent's own documented
// behaviour unreachable: a result at the agent's limit could not fit in the
// reply that had to carry it, so instead of arriving truncated with a marker it
// arrived as an error — and, on the sealed path, as a refusal that made the
// console run the whole command again.
//
// The inflation between the two is real and multiplicative: a stream crosses as
// a JSON string (where Go's encoder replaces each invalid UTF-8 byte with the
// 3-byte replacement rune), as base64 when the text form would be lossy (4/3×),
// on two streams at once, and then — for a sealed command — through the sealed
// envelope's base64 twice more (16/9×).
const (
	// MaxOutputBytes is the most output the agent carries back for one stream
	// (stdout or stderr) before truncating it and appending a visible marker.
	MaxOutputBytes = 8 << 20

	// MaxExecReplyBytes is what a client will read for one exec reply: 16 ×
	// MaxOutputBytes, which covers a full-cap result on both streams, carried in
	// both the text and the exact-bytes forms, through the sealed envelope.
	//
	// It is not the pathological maximum — 8 MiB of NUL bytes on both streams,
	// where JSON escaping alone is 6× — and it does not need to be. Past it the
	// client reports that the reply was too large to read and does not re-send
	// the command, which is honest and costs nothing: the command already ran.
	MaxExecReplyBytes = 16 * MaxOutputBytes
)

// Inbound frame caps. gorilla/websocket's default is *no* limit and
// ReadEnvelope buffers a whole frame before decoding it, so an unbounded socket
// is an unbounded allocation decided by the peer: on the console relay that
// peer holds only an exec-scoped API key, and it shares a process with every
// other machine's command authority. The HTTP exec path already caps a request
// body at 1 MiB; these are the same control on the two WebSocket paths, which
// bypassed it.
//
// The two numbers differ because a frame is not the request that produced it.
// The control plane re-marshals a command into an envelope on the way to the
// agent, and encoding/json HTML-escapes on the way out while the request body
// it came from needed no escaping — so a legal 1 MiB request of `<`, `>` and
// `&` arrives as up to six times that. MaxAgentFrameBytes sits above that worst
// case so a legitimate command is never cut off, and is still a hard bound so
// no frame is unbounded.
const (
	// MaxConsoleFrameBytes bounds one frame a console may send up the relay
	// socket (exec_stream, stream_stdin, stream_kill): the same 1 MiB the HTTP
	// exec path caps a request body at, so neither path is the softer way in.
	MaxConsoleFrameBytes = 1 << 20

	// MaxAgentFrameBytes bounds one frame the control plane may send down to an
	// agent. 6 × MaxConsoleFrameBytes is the escaping worst case above; the
	// round number above it is the point, since this is a ceiling rather than a
	// budget and an agent's own output cap (MaxOutputBytes) is already 8 MiB.
	MaxAgentFrameBytes = 8 << 20
)

type ExecResult struct {
	ExitCode int    `json:"exit_code"`
	Stdout   string `json:"stdout"`
	Stderr   string `json:"stderr"`
	Error    string `json:"error,omitempty"`
	// StdoutB64/StderrB64 carry a stream's exact bytes, and are set only when
	// Stdout/Stderr would be lossy.
	//
	// Stdout and Stderr are JSON strings, and a JSON string must be valid UTF-8:
	// Go's encoder silently replaces every invalid byte with U+FFFD, so a command
	// that prints binary — a tarball, a PNG, latin-1 text — came back both
	// mangled and longer than it was. The exact bytes ride alongside for that
	// case, and only that case, so an ordinary text result is byte-for-byte the
	// frame it always was and an older console (which does not know these fields)
	// still shows the lossy text rather than nothing.
	StdoutB64 string `json:"stdout_b64,omitempty"`
	StderrB64 string `json:"stderr_b64,omitempty"`
}

// SetOutput records a command's output exactly as the machine produced it,
// filling in both the text form (lossy for binary) and, when that form would
// lose something, the exact bytes.
func (r *ExecResult) SetOutput(stdout, stderr []byte) {
	r.Stdout, r.Stderr = string(stdout), string(stderr)
	if !utf8.Valid(stdout) {
		r.StdoutB64 = base64.StdEncoding.EncodeToString(stdout)
	}
	if !utf8.Valid(stderr) {
		r.StderrB64 = base64.StdEncoding.EncodeToString(stderr)
	}
}

// Output returns each stream as the machine produced it, preferring the exact
// bytes and falling back to the text form — which is all a result from an agent
// built before these fields existed can offer, and is also exactly right for
// every result whose output is text.
//
// A base64 field that will not decode is reported as no output rather than as a
// mangled guess: the text form beside it is known-lossy for this stream, so
// printing it would present corruption as the command's output.
func (r ExecResult) Output() (stdout, stderr []byte) {
	return streamBytes(r.StdoutB64, r.Stdout), streamBytes(r.StderrB64, r.Stderr)
}

func streamBytes(b64Form, textForm string) []byte {
	if b64Form == "" {
		return []byte(textForm)
	}
	b, err := base64.StdEncoding.DecodeString(b64Form)
	if err != nil {
		return nil
	}
	return b
}

// MarshalResult encodes an ExecResult for the wire without HTML escaping.
//
// encoding/json escapes <, > and & by default, which is right when JSON is going
// into a <script> block and wrong for every hop this one takes — agent to
// control plane to console to a terminal. It also inflates: a command that cats
// an HTML or XML file would have every angle bracket tripled, which is a large
// part of how a result at the agent's own cap came to exceed the reply that
// carried it. Output is bytes, not markup.
func MarshalResult(res ExecResult) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(res); err != nil {
		return nil, err
	}
	// Encode appends a newline; the payload keeps the shape json.Marshal gave it.
	return bytes.TrimRight(buf.Bytes(), "\n"), nil
}

// ---- console/authenticated-clients -> control plane ----

type ExecRequest struct {
	Machine string   `json:"machine"`
	Command string   `json:"command"`           // shell mode: run via sh -c
	Argv    []string `json:"argv,omitempty"`    // no-shell mode: execve directly, nothing parses anything
	Timeout int      `json:"timeout,omitempty"` // seconds; 0 = 30
	Sealed  string   `json:"sealed,omitempty"`  // E2E: base64 sealed ExecCommand (server relays blind)
	// E2EPub is the console's ephemeral X25519 public key (hex) the agent
	// seals the result back to. Present only when Sealed is set.
	E2EPub string `json:"e2e_pub,omitempty"`
}

type MachinesResponse struct {
	Machines []MachineInfo `json:"machines"`
}

type MachineInfo struct {
	Name      string `json:"name"`
	Hostname  string `json:"hostname,omitempty"`
	OS        string `json:"os,omitempty"`
	Arch      string `json:"arch,omitempty"`
	Online    bool   `json:"online"`
	AgentVer  string `json:"agent_version,omitempty"`
	LastSeen  string `json:"last_seen,omitempty"`
	CreatedAt string `json:"created_at"`

	// E2E is the control plane's answer to "will you accept a sealed command
	// for this machine?" ("on" / "off"), from the setting for the machine's
	// org. It rides each machine rather than the listing as a whole because the
	// setting is per org, and a client holding a machine name can then decide
	// without having to resolve which org that name belongs to.
	E2E string `json:"e2e,omitempty"`
	// E2EReason explains an "off" in one line.
	E2EReason string `json:"e2e_reason,omitempty"`

	// Blocked is the operator's soft block: the agent is still connected, but
	// the control plane will not dispatch to it. It is reported rather than
	// acted on by clients — a blocked machine also stays in the listing, because
	// the operator has to be able to see it in order to unblock it.
	Blocked bool `json:"blocked,omitempty"`

	// Temporary marks an enrollment that belongs to a session rather than to a
	// machine: plain `mach` on a target. Reported so an operator can tell a
	// throwaway row from a real one at a glance, and so a session that never got
	// to retire itself is not mistaken for a machine that stopped working.
	Temporary bool `json:"temporary,omitempty"`
}

// ---- fleet policy (control plane -> agent, agent -> control plane) ----

// PolicyUpdate carries the control plane's fleet-wide exec rules to an agent.
//
// The control plane cannot read a sealed command, so it cannot apply its own
// block list to one; the only place that text exists is on the machine, after
// decryption. So the rules travel: the agent evaluates them exactly where it
// evaluates its own, and a refusal is a refusal whoever wrote the rule.
//
// Rules is the same spec text MACH_POLICY takes (deny:/allowonly/allow:), and
// an empty Rules is meaningful — it clears any ruleset a previous message
// installed, so an operator who removes their fleet policy is not left with
// stale rules being enforced on every machine. Version is a content hash the
// agent echoes back in a PolicyAck.
type PolicyUpdate struct {
	Rules   string `json:"rules"`
	Version string `json:"version"`
}

// PolicyAck confirms which fleet ruleset an agent is enforcing.
type PolicyAck struct {
	Version string `json:"version"`
	// Error is set when the agent could not install what it was sent, so a
	// control plane does not read silence as success.
	Error string `json:"error,omitempty"`
}

// ---- control plane -> agent ----

// The "deleted" frame is the control plane's delete notice: the machine row and
// the agent's key are gone from the database, so this connection is about to be
// closed and the agent must retire rather than reconnect — dialing this name
// again finds nothing.
//
// It carries no payload, like "revoked": the agent needs no data to act, and a
// control-plane-supplied string would only be a log-injection surface. Frame
// tags are raw literals throughout this package (there is no enum), so this one
// is spelled "deleted" at every site — see the agent's terminalFrame mapping and
// consoleapi's delete path.
//
// It is only ever sent on a connection that has already completed the hello
// handshake. That matters: handleAgentWS answers an *unknown* machine name by
// upgrading and closing with no frame at all, deliberately, so the
// unauthenticated endpoint cannot be used to enumerate which names exist. A
// deleted machine is exactly an unknown name there, and must stay that way.

// The "retire" frame is the other direction: an agent telling the control plane
// to retire it. It is sent by a TEMPORARY session on its way out (plain `mach`
// on a target, which keeps nothing on disk and so revokes itself on exit), and
// the control plane accepts it only from a machine enrolled as temporary — a
// permanent agent must not be able to retire a machine the operator expects to
// stay.
//
// It is scoped by construction: the handler uses the name of the connection the
// frame arrived on, so an agent can retire itself and nothing else. Like the
// other terminal frames it carries no payload.

type ExecCommand struct {
	Command string   `json:"command,omitempty"` // shell mode
	Argv    []string `json:"argv,omitempty"`    // no-shell mode (argv[0..] via execve)
	Timeout int      `json:"timeout,omitempty"` // seconds; 0 = 30
}

// SealedExecCommand is the E2E variant of ExecCommand relayed to the
// agent: an opaque sealed blob plus the console's ephemeral reply key.
// The control plane cannot read either component.
type SealedExecCommand struct {
	SealedB64 string `json:"sealed_b64"`
	ReplyPub  string `json:"reply_pub"` // console ephemeral X25519 pubkey (hex)
	Timeout   int    `json:"timeout,omitempty"`
}

// ---- streaming console ----

// StreamStart initiates a streaming exec session (server → agent frame).
// The agent runs the command, streaming chunks as they arrive, and
// terminates with a stream_end frame carrying the exit code.
type StreamStart struct {
	Command string   `json:"command,omitempty"`
	Argv    []string `json:"argv,omitempty"`
}

// StreamOut is a chunk of output (agent → server → console).
type StreamOut struct {
	Stream string `json:"stream"` // "stdout" | "stderr"
	B64    string `json:"b64"`
}

// StreamEnd terminates a streaming session with the final exit code.
type StreamEnd struct {
	ExitCode int    `json:"exit_code"`
	Error    string `json:"error,omitempty"`
}

// StreamStdin carries console stdin to the running command (agent-bound).
type StreamStdin struct {
	B64 string `json:"b64"`
	EOF bool   `json:"eof,omitempty"`
}

// SealedExecResult is the agent's reply when E2E is on: the ExecResult JSON
// sealed to the console's ephemeral public key carried in ExecRequest.E2EPub.
//
// ExitCode rides BESIDE the ciphertext, in the clear, and it is the only thing
// that may. The control plane cannot open the blob, so this is how the relay
// learns the one fact about a sealed command that is documented as learnable —
// the exit status — and what its audit row records. Without it the row carried
// a fabricated 0 for every sealed command, including the ones a machine's own
// policy had just refused with 126: a record that said "succeeded" for a
// command that never ran is worse than no record.
//
// It is a pointer so "the agent did not report one" is distinguishable from a
// real 0 — an agent older than this field sends nothing, and the row then shows
// no exit status rather than inventing one.
//
// Nothing else may be added here in the clear. An error string would defeat the
// seal outright: a policy refusal quotes the command it refused, so relaying it
// would hand the control plane the text it was never allowed to read.
type SealedExecResult struct {
	SealedB64 string `json:"sealed_b64"`
	ExitCode  *int   `json:"exit_code,omitempty"`
}

// UpdateCommand pushes a new agent binary from the control plane. The
// manifest (version + sha256) is signed by the control plane's identity
// key — agents pin that key at enrollment, so only the genuine control
// plane can push an update, even over a hijacked channel.
type UpdateCommand struct {
	URL     string `json:"url,omitempty"`      // optional direct download (https)
	DataB64 string `json:"data_b64,omitempty"` // inline binary (small updates)
	Sha256  string `json:"sha256"`             // integrity: hex digest of the payload
	Version string `json:"version"`            // target version string
	SigB64  string `json:"sig"`                // ed25519 sig by server key over "version|sha256"
}

// ---- QR pairing (unauthenticated browser/phone side) ----

type PairStartResponse struct {
	PairID  string `json:"pair_id"`
	Token   string `json:"token"`
	Code    string `json:"code"`    // challenge code to print on the agent console ONLY
	Expires string `json:"expires"` // RFC3339
}

type PairStatusResponse struct {
	State   string `json:"state"` // pending | approved | denied | expired
	Machine string `json:"machine,omitempty"`
}

type PairApproveRequest struct {
	Code string `json:"code"`
	Name string `json:"name"`
}

// PairClaimRequest is sent by the agent after the phone approves; it
// completes enrollment and creates the machine (single-use token).
type PairClaimRequest struct {
	PubKey string `json:"pub_key"`
	PubE2E string `json:"pub_e2e,omitempty"` // X25519 public key for E2E exec (hex)
	Token  string `json:"token"`
	Name   string `json:"name"`
	// Auth proves possession of the private key for PubKey: "v1 <base64
	// ed25519 signature>" over ClaimMessage(Token). It is required, and it is
	// what makes the claim a statement by the machine rather than by whoever
	// holds the token — see ClaimMessage and SECURITY-NOTES.md.
	Auth string `json:"auth"`
	// Temporary marks an enrollment that belongs to a session rather than to a
	// machine: plain `mach` on a target, which keeps nothing on disk and revokes
	// itself on the way out. It is recorded so the enrollment can be taken over
	// by the next run of that session — even after a Ctrl-C that never got the
	// chance to self-revoke — without the operator revoking or deleting anything.
	// A later permanent enrollment clears it.
	Temporary bool `json:"temporary,omitempty"`
}

// PairStartReq is the agent's request to begin a pairing session.
type PairStartReq struct {
	PubKey   string `json:"pub_key"`
	PubE2E   string `json:"pub_e2e,omitempty"` // X25519 public key for E2E exec (hex)
	Hostname string `json:"hostname,omitempty"`
	OS       string `json:"os,omitempty"`
	Arch     string `json:"arch,omitempty"`
	AgentVer string `json:"agent_version,omitempty"`
}

// ClaimMessage is the exact string an agent signs to complete a pairing.
//
// The token is the whole message because it is already the thing that names
// this pairing: 256 bits of server-generated entropy, single-use, and known only
// to the agent that started the pairing and to whoever read the QR. Signing it
// therefore proves the signer holds the identity key *for this pairing*, and
// cannot be replayed into another one.
//
// The prefix is a domain separator, not decoration. The same identity key signs
// the connection hello (`name|challenge`), and without a distinct prefix a
// signature from one context would be a valid signature in the other for
// whatever string happened to line up. It lives here, in the wire package, so
// the agent and the control plane cannot disagree about the spelling — the two
// halves of the hello message are written once on each side, and this is the
// shape that drifts.
func ClaimMessage(token string) string { return "mach-pair-claim|" + token }

// PairStatusReq is the agent's poll while waiting for phone approval.
type PairStatusReq struct {
	Token string `json:"token"`
}

// RegisterAPIKeyReq is headless enrollment (requires an enroll-scoped key).
type RegisterAPIKeyReq struct {
	APIKey   string `json:"api_key"`
	PubKey   string `json:"pub_key"`
	PubE2E   string `json:"pub_e2e,omitempty"` // X25519 public key for E2E exec (hex)
	Name     string `json:"name"`
	Hostname string `json:"hostname,omitempty"`
	OS       string `json:"os,omitempty"`
	Arch     string `json:"arch,omitempty"`
	AgentVer string `json:"agent_version,omitempty"`
	// Temporary is the same flag as on PairClaimRequest: this enrollment belongs
	// to a session, not to a machine.
	Temporary bool `json:"temporary,omitempty"`
}
