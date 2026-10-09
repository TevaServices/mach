package server

// MCP endpoint tests. The tools are adapters over the console API handlers,
// so what these tests pin is the adapter seam: auth parity with the console
// API, tenant scoping of the listing, and that exec rides the same pipeline
// (a refusal here is the pipeline's refusal, with its status).

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/TevaServices/mach/internal/broker"
	"github.com/TevaServices/mach/internal/store"
)

// mcpCall posts one JSON-RPC request with a bearer key and decodes the
// response envelope.
func mcpCall(t *testing.T, h http.Handler, key, method, params string) (int, jsonRPCResponse) {
	t.Helper()
	body := `{"jsonrpc":"2.0","id":1,"method":"` + method + `"` + params + `}`
	req := httptest.NewRequest(http.MethodPost, "/v2/mcp", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+key)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	var resp jsonRPCResponse
	_ = json.Unmarshal(rec.Body.Bytes(), &resp)
	return rec.Code, resp
}

func TestMCPRejectsAnonymousAndBadKeys(t *testing.T) {
	s := newTestServer(t)
	testServerStore(t, s)
	h := s.Routes()

	req := httptest.NewRequest(http.MethodPost, "/v2/mcp", strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"ping"}`))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("anonymous MCP call = %d, want 403", rec.Code)
	}

	code, resp := mcpCall(t, h, "mach_wrong", "ping", "")
	if code != http.StatusForbidden || resp.Error == nil {
		t.Fatalf("bad key = %d err=%v, want 403 with an error", code, resp.Error)
	}

	// GET has nothing to do here: the transport is POST-only.
	g := httptest.NewRequest(http.MethodGet, "/v2/mcp", nil)
	grec := httptest.NewRecorder()
	h.ServeHTTP(grec, g)
	if grec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("GET /v2/mcp = %d, want 405", grec.Code)
	}
}

func TestMCPInitializeToolsListAndPing(t *testing.T) {
	s := newTestServer(t)
	st := testServerStore(t, s)
	_ = st.CreateAPIKey("ops", "mach_mcp", "exec:*", "bcross")
	h := s.Routes()

	_, resp := mcpCall(t, h, "mach_mcp", "initialize", `,"params":{}`)
	if resp.Error != nil {
		t.Fatalf("initialize errored: %v", resp.Error)
	}
	if res, ok := resp.Result.(map[string]any); !ok || res["protocolVersion"] != mcpProtocolVersion {
		t.Fatalf("initialize result = %#v", resp.Result)
	}

	_, resp = mcpCall(t, h, "mach_mcp", "tools/list", "")
	tools, ok := resp.Result.(map[string]any)["tools"].([]any)
	if !ok || len(tools) != 3 {
		t.Fatalf("tools/list = %#v, want 3 tools", resp.Result)
	}
	names := map[string]bool{}
	for _, tl := range tools {
		names[tl.(map[string]any)["name"].(string)] = true
	}
	for _, want := range []string{"machines_list", "secrets_list", "exec"} {
		if !names[want] {
			t.Fatalf("tools/list missing %q", want)
		}
	}

	_, resp = mcpCall(t, h, "mach_mcp", "ping", "")
	if resp.Error != nil {
		t.Fatalf("ping errored: %v", resp.Error)
	}
}

// The listing is the tenant's: an org-bound key sees its own org's machines
// and nothing from another org, through the same handler the CLI reads.
func TestMCPMachinesListIsOrgScoped(t *testing.T) {
	s := newTestServer(t)
	st := testServerStore(t, s)
	if err := st.CreateMachine("bcross-web", "pub-a", "h", "linux", "amd64", "v", "", false, "bcross"); err != nil {
		t.Fatalf("seed: %v", err)
	}
	if err := st.CreateMachine("xy-web", "pub-b", "h", "linux", "amd64", "v", "", false, "xy"); err != nil {
		t.Fatalf("seed: %v", err)
	}
	_ = st.CreateAPIKey("ops", "mach_mcp", "exec:*", "bcross")
	h := s.Routes()

	_, resp := mcpCall(t, h, "mach_mcp", "tools/call", `,"params":{"name":"machines_list","arguments":{}}`)
	if resp.Error != nil {
		t.Fatalf("machines_list errored: %v", resp.Error)
	}
	result := resp.Result.(map[string]any)
	content := result["content"].([]any)[0].(map[string]any)["text"].(string)
	if !strings.Contains(content, "bcross-web") {
		t.Fatalf("listing does not show the org's machine: %q", content)
	}
	if strings.Contains(content, "xy-web") {
		t.Fatalf("listing leaked another org's machine: %q", content)
	}
}

// exec through MCP is exec through the console API: a cross-org machine is
// an unknown machine, and the pipeline's refusals come back as tool results
// rather than as new refusal machinery.
func TestMCPExecRidesTheConsolePipeline(t *testing.T) {
	s := newTestServer(t)
	st := testServerStore(t, s)
	if err := st.CreateMachine("xy-web", "pub-b", "h", "linux", "amd64", "v", "", false, "xy"); err != nil {
		t.Fatalf("seed: %v", err)
	}
	_ = st.CreateAPIKey("ops", "mach_mcp", "exec:*", "bcross")
	h := s.Routes()

	_, resp := mcpCall(t, h, "mach_mcp", "tools/call",
		`,"params":{"name":"exec","arguments":{"machine":"xy-web","command":"echo hi"}}`)
	if resp.Error != nil {
		t.Fatalf("exec call errored at the protocol level: %v", resp.Error)
	}
	result := resp.Result.(map[string]any)
	content := result["content"].([]any)[0].(map[string]any)["text"].(string)
	// The machine does not exist for this org; the pipeline's own answer is
	// "offline or unknown", not a cross-org confirmation.
	if !strings.Contains(content, "not run") || !strings.Contains(content, "offline or unknown") {
		t.Fatalf("cross-org exec answered %q, want the pipeline's unknown-machine refusal", content)
	}
}

// testServerStore attaches a real store and broker to a server built
// without either.
func testServerStore(t *testing.T, s *Server) *store.Store {
	t.Helper()
	st, err := store.Open(t.TempDir() + "/mcp.db")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { st.Close() })
	s.st = st
	s.br = broker.New()
	return st
}
