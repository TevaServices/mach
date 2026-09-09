// Package protocol defines the wire types shared by machd (agent), the
// control plane, and the console CLI. All transport framing is JSON over
// WebSocket, inside an Envelope. Agent identity is an Ed25519 keypair; the
// control plane knows agents by their public key (hex) + machine name.
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
	Auth        string `json:"auth"`                  // "v1 <base64 ed25519 signature>" over name|timestamp
	PubKey      string `json:"pub_key"`               // hex
	Name        string `json:"name"`                  // machine name (must match enrollment)
	Timestamp   string `json:"timestamp"`             // RFC3339, replay window ±5 min
	AgentVer    string `json:"agent_version,omitempty"`
	Hostname    string `json:"hostname,omitempty"`
	OS          string `json:"os,omitempty"`          // e.g. linux
	Arch        string `json:"arch,omitempty"`        // e.g. arm64
}

type HelloResponse struct {
	OK      bool   `json:"ok"`
	Error   string `json:"error,omitempty"`
	ServerVer string `json:"server_version,omitempty"`
}

type ExecResult struct {
	ExitCode int    `json:"exit_code"`
	Stdout   string `json:"stdout"`
	Stderr   string `json:"stderr"`
	Error    string `json:"error,omitempty"` // e.g. binary not found, timeout
}

// ---- console/authenticated-clients -> control plane ----

type ExecRequest struct {
	Machine string `json:"machine"`
	Command string `json:"command"`
	Timeout int    `json:"timeout,omitempty"` // seconds; 0 = 30
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
	LastSeen  string `json:"last_seen,omitempty"` // RFC3339
	CreatedAt string `json:"created_at"`          // RFC3339
}

// ---- control plane -> agent ----

type ExecCommand struct {
	Command string `json:"command"`
	Timeout int    `json:"timeout,omitempty"` // seconds; 0 = 30
}

// ---- QR pairing (unauthenticated browser/phone side) ----

type PairStartResponse struct {
	PairID  string `json:"pair_id"`
	Token   string `json:"token"`   // one-time token embedded in the QR URL
	Code    string `json:"code"`    // challenge code to print on the agent console
	Expires string `json:"expires"` // RFC3339
}

type PairStatusResponse struct {
	State   string `json:"state"` // pending | approved | denied | expired
	Machine string `json:"machine,omitempty"`
}

type PairApproveRequest struct {
	Code    string `json:"code"`    // challenge code typed/compared by human
	Name    string `json:"name"`    // machine name assigned at approval
}

// PairClaimRequest is sent by the agent after the phone approves; it
// completes enrollment and creates the machine (single-use token).
type PairClaimRequest struct {
	PubKey string `json:"pub_key"`
	Token  string `json:"token"`
	Name   string `json:"name"`
}

// ---- shared request types (agent enrollment + console API) ----

type PairStartReq struct {
	PubKey   string `json:"pub_key"`
	Hostname string `json:"hostname,omitempty"`
	OS       string `json:"os,omitempty"`
	Arch     string `json:"arch,omitempty"`
	AgentVer string `json:"agent_version,omitempty"`
}

type PairStatusReq struct {
	Token string `json:"token"`
}

type RegisterAPIKeyReq struct {
	APIKey   string `json:"api_key"`
	PubKey   string `json:"pub_key"`
	Name     string `json:"name"`
	Hostname string `json:"hostname,omitempty"`
	OS       string `json:"os,omitempty"`
	Arch     string `json:"arch,omitempty"`
	AgentVer string `json:"agent_version,omitempty"`
}