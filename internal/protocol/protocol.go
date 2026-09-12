package protocol

import "encoding/json"

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

type ExecResult struct {
	ExitCode int    `json:"exit_code"`
	Stdout   string `json:"stdout"`
	Stderr   string `json:"stderr"`
	Error    string `json:"error,omitempty"`
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
type SealedExecResult struct {
	SealedB64 string `json:"sealed_b64"`
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
}
