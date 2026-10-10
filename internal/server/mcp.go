package server

// MCP v2: a Model Context Protocol endpoint on the control plane, so MCP
// clients (agent runtimes, editors) can drive the fleet through the same
// machinery the CLI uses.
//
// The design rule that matters: the three tools are THIN ADAPTERS over the
// existing console-API handlers, invoked in-process with a response
// recorder. Not reimplemented, not delegated partially — the handler IS the
// API, so every authorization check, org boundary, policy layer, approval
// gate, audit row and E2E decision a console request would meet is met here
// too, by construction. There is no second copy of any of those rules to
// drift (the repo's oldest lesson).
//
// Auth, first cut: bearer API keys only, the same `authConsole` path —
// which means the same per-IP failure limiter, the same key→org binding,
// and the same scope checks. MCP clients are programs holding a key; UI
// sessions can be added later without changing the tool layer (the adapter
// boundary is the handler, and a session principal can be threaded through
// the same recorder call once its org mapping is settled).
//
// Transport: Streamable HTTP (POST returns one JSON-RPC response;
// server-initiated SSE is not needed for request/response tools, so GET is
// a 405 and DELETE ends nothing). Stateless: no Mcp-Session-Id, because
// there is no server-side tool state to key one on.
//
// Output is data, never input: an exec tool result carries the machine's
// bytes as text content and the exit status as a typed field — nothing
// here parses machine output for a control fact.

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"

	"github.com/TevaServices/mach/internal/protocol"
	"github.com/TevaServices/mach/internal/version"
)

// mcpProtocolVersion is the MCP revision this endpoint speaks.
const mcpProtocolVersion = "2025-06-18"

// jsonRPCError codes used here (standard JSON-RPC 2.0 + MCP practice).
const (
	errParse     = -32700
	errInvalidRe = -32600
	errMethod    = -32601
	errInvalidPa = -32602
	errInternal  = -32603
)

type jsonRPCRequest struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params"`
}

type jsonRPCResponse struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Result  any             `json:"result,omitempty"`
	Error   *jsonRPCError   `json:"error,omitempty"`
}

type jsonRPCError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

// toolResult is the MCP tool-call result shape: text content blocks plus a
// flag for "the tool reports failure". Exec failures (non-zero exit) are
// data, not protocol errors — the machine ran something and said so.
type toolResult struct {
	Content []toolContent `json:"content"`
	IsError bool          `json:"isError,omitempty"`
}

type toolContent struct {
	Type string `json:"type"`
	Text string `json:"text"`
}

func textResult(text string, isError bool) toolResult {
	return toolResult{Content: []toolContent{{Type: "text", Text: text}}, IsError: isError}
}

// handleMCP is the endpoint. Auth mirrors authConsole exactly (bearer key,
// failure limiter); everything after auth is JSON-RPC dispatch.
func (s *Server) handleMCP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		// Streamable HTTP would open server-initiated SSE on GET; this
		// server has nothing to push, so the honest answer is the status
		// code that says the method has nothing to do here.
		w.Header().Set("Allow", "POST")
		http.Error(w, "MCP endpoint accepts POST only", http.StatusMethodNotAllowed)
		return
	}
	// Bearer auth, spelled like authConsole so the limiter and the refusal
	// shapes match the console API byte for byte.
	auth := r.Header.Get("Authorization")
	const prefix = "Bearer "
	if len(auth) <= len(prefix) || auth[:len(prefix)] != prefix {
		s.authFailJSONRPC(w)
		return
	}
	ip := s.clientIP(r)
	if s.authFails.blocked(ip) {
		writeJSON(w, http.StatusTooManyRequests, map[string]string{"error": "too many failed auth attempts"})
		return
	}
	ok, keyName, scopes, keyOrg, err := s.st.APIKeyExists(auth[len(prefix):])
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "store error"})
		return
	}
	if !ok {
		s.authFails.record(ip)
		s.authFailJSONRPC(w)
		return
	}

	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 1<<20))
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "body too large"})
		return
	}
	var req jsonRPCRequest
	if err := json.Unmarshal(body, &req); err != nil {
		writeJSONRPC(w, http.StatusOK, jsonRPCResponse{JSONRPC: "2.0", ID: req.ID,
			Error: &jsonRPCError{Code: errParse, Message: "parse error"}})
		return
	}
	// A notification carries no id and expects no response: accept it and
	// answer 202 Accepted with no body, per the transport spec.
	if len(req.ID) == 0 || string(req.ID) == "null" {
		w.WriteHeader(http.StatusAccepted)
		return
	}

	var result any
	var rpcErr *jsonRPCError
	switch req.Method {
	case "initialize":
		result = map[string]any{
			"protocolVersion": mcpProtocolVersion,
			"capabilities":    map[string]any{"tools": map[string]any{}},
			"serverInfo":      map[string]any{"name": "mach", "version": versionString()},
		}
	case "notifications/initialized", "initialized":
		w.WriteHeader(http.StatusAccepted)
		return
	case "ping":
		result = map[string]any{}
	case "tools/list":
		result = map[string]any{"tools": mcpTools()}
	case "tools/call":
		result, rpcErr = s.mcpToolCall(req.Params, keyName, scopes, keyOrg)
	default:
		rpcErr = &jsonRPCError{Code: errMethod, Message: "method not found: " + req.Method}
	}
	resp := jsonRPCResponse{JSONRPC: "2.0", ID: req.ID, Result: result, Error: rpcErr}
	writeJSONRPC(w, http.StatusOK, resp)
}

func (s *Server) authFailJSONRPC(w http.ResponseWriter) {
	writeJSONRPC(w, http.StatusForbidden, jsonRPCResponse{JSONRPC: "2.0", ID: nil,
		Error: &jsonRPCError{Code: errInvalidRe, Message: "invalid api key"}})
}

func writeJSONRPC(w http.ResponseWriter, status int, resp jsonRPCResponse) {
	writeJSON(w, status, resp)
}

// versionString is the one software version, read the only way it may be.
func versionString() string { return version.Version }

// mcpToolCall dispatches tools/call. Each tool delegates to the console-API
// handler through a recorder, then translates the HTTP answer into a tool
// result — the handler's status and body ARE the tool's semantics.
func (s *Server) mcpToolCall(params json.RawMessage, keyName, scopes, keyOrg string) (any, *jsonRPCError) {
	var call struct {
		Name      string          `json:"name"`
		Arguments json.RawMessage `json:"arguments"`
	}
	if err := json.Unmarshal(params, &call); err != nil {
		return nil, &jsonRPCError{Code: errInvalidPa, Message: "bad params"}
	}
	switch call.Name {
	case "machines_list":
		return s.mcpMachinesList(keyName, scopes, keyOrg)
	case "secrets_list":
		return s.mcpSecretsList(call.Arguments, keyName, scopes, keyOrg)
	case "exec":
		return s.mcpExec(call.Arguments, keyName, scopes, keyOrg)
	default:
		return nil, &jsonRPCError{Code: errInvalidPa, Message: "unknown tool: " + call.Name}
	}
}

// callConsoleHandler runs one console-API handler against a synthesized
// request and returns (status, decoded body). The handler is the real one —
// nothing about the request is special except that it never touched a
// socket.
func (s *Server) callConsoleHandler(handler func(http.ResponseWriter, *http.Request, string, string, string), keyName, scopes, keyOrg string, body any) (int, []byte) {
	var payload io.Reader
	if body != nil {
		raw, _ := json.Marshal(body)
		payload = strings.NewReader(string(raw))
	}
	r := httptest.NewRequest(http.MethodPost, "/v2/mcp-adapter", payload)
	if body != nil {
		r.Header.Set("Content-Type", "application/json")
	}
	rec := httptest.NewRecorder()
	handler(rec, r, keyName, scopes, keyOrg)
	return rec.Code, rec.Body.Bytes()
}

func (s *Server) mcpMachinesList(keyName, scopes, keyOrg string) (any, *jsonRPCError) {
	// GET semantics on a POST-only transport: call the handler with a GET
	// request so route/method assumptions inside it hold.
	r := httptest.NewRequest(http.MethodGet, "/v2/mcp-adapter/machines", nil)
	rec := httptest.NewRecorder()
	s.handleMachines(rec, r, keyName, scopes, keyOrg)
	var resp protocol.MachinesResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		// Not a listing — a refusal. Surface the handler's own sentence.
		return textResult(rec.Body.String(), true), nil
	}
	var b strings.Builder
	for _, m := range resp.Machines {
		// The canonical name: the identifier every other surface (audit
		// rows, exec targets) uses, unambiguous when two orgs own the same
		// local name. The org column beside it says whose it is.
		status := "offline"
		if m.Online {
			status = "online"
		}
		if m.Blocked {
			status += ", blocked"
		}
		if m.Temporary {
			status += ", temporary"
		}
		b.WriteString(m.Name + "\t" + m.OS + "/" + m.Arch + "\t" + status)
		if m.Org != "" {
			b.WriteString("\torg " + m.Org)
		}
		b.WriteString("\n")
	}
	if b.Len() == 0 {
		return textResult("no machines visible to this key", false), nil
	}
	return textResult(strings.TrimRight(b.String(), "\n"), false), nil
}

func (s *Server) mcpSecretsList(args json.RawMessage, keyName, scopes, keyOrg string) (any, *jsonRPCError) {
	var a struct {
		Machine string `json:"machine"`
	}
	_ = json.Unmarshal(args, &a) // machine is optional; absence is the registry
	r := httptest.NewRequest(http.MethodGet, "/v2/mcp-adapter/secrets", nil)
	if a.Machine != "" {
		q := r.URL.Query()
		q.Set("machine", a.Machine)
		r.URL.RawQuery = q.Encode()
	}
	rec := httptest.NewRecorder()
	s.handleSecretsList(rec, r, keyName, scopes, keyOrg)
	if rec.Code != http.StatusOK {
		return textResult(rec.Body.String(), true), nil
	}
	// Re-emit the handler's own JSON as text: it is names and provenance
	// only, and re-typing it into tool fields would be a second shape to
	// keep in step.
	return textResult(rec.Body.String(), false), nil
}

func (s *Server) mcpExec(args json.RawMessage, keyName, scopes, keyOrg string) (any, *jsonRPCError) {
	var a struct {
		Machine string   `json:"machine"`
		Command string   `json:"command"`
		Argv    []string `json:"argv"`
		Inject  []string `json:"inject"`
		Timeout int      `json:"timeout"`
	}
	if err := json.Unmarshal(args, &a); err != nil {
		return nil, &jsonRPCError{Code: errInvalidPa, Message: "exec needs machine and (command or argv)"}
	}
	if a.Machine == "" || (a.Command == "" && len(a.Argv) == 0) {
		return nil, &jsonRPCError{Code: errInvalidPa, Message: "exec needs machine and (command or argv)"}
	}
	req := protocol.ExecRequest{
		Machine:   a.Machine,
		Command:   a.Command,
		Argv:      a.Argv,
		Timeout:   a.Timeout,
		InjectEnv: a.Inject,
	}
	// The recorder carries the synthesized request; the handler runs its
	// full pipeline — scope, org boundary, per-org E2E, both policy layers,
	// the approval gate, dispatch, audit — and the tool result is whatever
	// the console API would have answered.
	status, bodyBytes := s.callConsoleHandler(s.handleExec, keyName, scopes, keyOrg, req)
	if status != http.StatusOK {
		// 202 = a pending approval the operator can grant (the console's
		// own contract); everything else is a refusal or a timeout, and the
		// handler's sentence is the honest text for an LLM to see.
		return textResult("exec not run (HTTP "+strconv.Itoa(status)+"): "+strings.TrimRight(string(bodyBytes), "\n")+
			approvalHint(status), status == http.StatusAccepted), nil
	}
	var res protocol.ExecResult
	if err := json.Unmarshal(bodyBytes, &res); err != nil {
		return textResult("unreadable exec reply", true), nil
	}
	stdout, stderr := res.Output()
	var b strings.Builder
	if len(stdout) > 0 {
		b.Write(stdout)
	}
	if len(stderr) > 0 {
		if b.Len() > 0 {
			b.WriteString("\n[stderr] ")
		}
		b.Write(stderr)
	}
	if res.Error != "" {
		if b.Len() > 0 {
			b.WriteString("\n")
		}
		b.WriteString("[mach] " + res.Error)
	}
	return toolResult{
		Content: []toolContent{{Type: "text", Text: strings.TrimRight(b.String(), "\n")}},
		IsError: res.ExitCode != 0 || res.Error != "",
	}, nil
}

// approvalHint tells an MCP client what a 202 means — the same sentence the
// console prints, in the tool result's own words.
func approvalHint(status int) string {
	if status == http.StatusAccepted {
		return " — a pending command approval was recorded; an operator must approve it before this command runs"
	}
	return ""
}

// mcpTools is the tools/list answer. Descriptions state the credential
// model in one line, because an LLM reading them is part of the threat
// model: names only, values live on targets, output is scrubbed there.
func mcpTools() []map[string]any {
	return []map[string]any{
		{
			"name":        "machines_list",
			"description": "List the machines this API key can see (its org's fleet), with platform, online/blocked state and org.",
			"inputSchema": map[string]any{"type": "object", "properties": map[string]any{}},
		},
		{
			"name":        "secrets_list",
			"description": "List secret NAMES (never values — values live on target machines and are scrubbed from all output). Without a machine: the registry for this key's org. With machine: the names that machine reports live.",
			"inputSchema": map[string]any{
				"type": "object",
				"properties": map[string]any{
					"machine": map[string]any{"type": "string", "description": "optional machine name (local name within the key's org, or its full name)"},
				},
			},
		},
		{
			"name":        "exec",
			"description": "Run a command on a machine through the full console pipeline (org boundary, per-org E2E, fleet policy, approvals, audit). inject names secret environment variables resolved on the machine; values never cross the control plane.",
			"inputSchema": map[string]any{
				"type": "object",
				"properties": map[string]any{
					"machine": map[string]any{"type": "string", "description": "machine name exactly as machines_list shows it (the Name column) — never an invented variant; an unknown or offline name is refused with the enrolled list"},
					"command": map[string]any{"type": "string", "description": "shell mode"},
					"argv":    map[string]any{"type": "array", "items": map[string]any{"type": "string"}, "description": "no-shell mode: execve'd directly, nothing parses it"},
					"inject":  map[string]any{"type": "array", "items": map[string]any{"type": "string"}, "description": "secret env-var NAMES to resolve on the machine"},
					"timeout": map[string]any{"type": "integer", "description": "seconds (default 30, max 600)"},
				},
				"required": []string{"machine"},
			},
		},
	}
}
