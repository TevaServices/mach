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
}

// ---- control plane -> agent ----

type ExecCommand struct {
	Command string   `json:"command,omitempty"` // shell mode
	Argv    []string `json:"argv,omitempty"`    // no-shell mode (argv[0..] via execve)
	Timeout int      `json:"timeout,omitempty"` // seconds; 0 = 30
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
	Token  string `json:"token"`
	Name   string `json:"name"`
}

// PairStartReq is the agent's request to begin a pairing session.
type PairStartReq struct {
	PubKey   string `json:"pub_key"`
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
	Name     string `json:"name"`
	Hostname string `json:"hostname,omitempty"`
	OS       string `json:"os,omitempty"`
	Arch     string `json:"arch,omitempty"`
	AgentVer string `json:"agent_version,omitempty"`
}
