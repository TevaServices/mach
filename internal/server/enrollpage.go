package server

import (
	"fmt"
	"html/template"
	"net/http"
	"os"
	"path/filepath"
	"strings"
)

// ---- Enrollment root: target machine downloads with OS detection ----

// agentDir locates the cross-compiled `mach` binaries. The container image
// ships them at /opt/mach-agents; local dev builds to ./bin/cross.
// Override with MACH_AGENT_DIR.
func (s *Server) agentDir() string { return agentDirPath() }

// knownAgentFiles is the strict allowlist of shippable binaries — download
// requests must name exactly one of these; nothing user-controlled passes.
var knownAgentFiles = map[string]bool{
	"mach-linux-amd64": true, "mach-linux-arm64": true,
	"mach-darwin-amd64": true, "mach-darwin-arm64": true,
	"mach-windows-amd64.exe": true, "mach-windows-arm64.exe": true,
}

func fileExists(p string) bool {
	st, err := os.Stat(p)
	return err == nil && !st.IsDir()
}

// detectOSFromUA maps a User-Agent to (osKey, prettyName) for download
// targeting. Unknown UAs default to linux (the most common target).
func detectOSFromUA(ua string) (string, string) {
	u := strings.ToLower(ua)
	switch {
	case strings.Contains(u, "windows"):
		return "windows", "Windows"
	case strings.Contains(u, "android"):
		return "linux", "Linux (Android detected — pick the Linux build below)"
	case strings.Contains(u, "iphone"), strings.Contains(u, "ipad"), strings.Contains(u, "mac os"), strings.Contains(u, "macintosh"):
		return "darwin", "macOS"
	case strings.Contains(u, "cros"):
		return "linux", "Linux (ChromeOS detected — use the Linux build)"
	default:
		return "linux", "Linux"
	}
}

// detectArchFromUA guesses the CPU arch from UA fragments (phone UAs on
// modern devices are arm64; desktop UAs are ambiguous → amd64 default).
func detectArchFromUA(ua string) string {
	u := strings.ToLower(ua)
	switch {
	case strings.Contains(u, "arm64"), strings.Contains(u, "aarch64"):
		return "arm64"
	case strings.Contains(u, "iphone"), strings.Contains(u, "ipad"),
		strings.Contains(u, "android"), strings.Contains(u, "ipad; cpu os"):
		return "arm64"
	default:
		return "amd64"
	}
}

type enrollData struct {
	Orgs      []string
	PrimaryDL string // /download/<file> for the detected OS
	PrimaryFN string // filename
	PrimaryOS string // pretty OS name detected
	HasDL     bool
	All       []platformRow
}

type platformRow struct {
	OS, Arch, File string
}

var platformRows = []platformRow{
	{"Linux", "amd64 (x86_64)", "mach-linux-amd64"},
	{"Linux", "arm64 (aarch64)", "mach-linux-arm64"},
	{"macOS", "Intel", "mach-darwin-amd64"},
	{"macOS", "Apple Silicon", "mach-darwin-arm64"},
	{"Windows", "amd64", "mach-windows-amd64.exe"},
	{"Windows", "arm64", "mach-windows-arm64.exe"},
}

var enrollTmpl = template.Must(template.New("enroll").Parse(`<!doctype html>
<html><head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>mach — set up a machine</title>
</head><body style="font-family:-apple-system,system-ui,sans-serif;max-width:34rem;margin:2rem auto;padding:0 1rem;">
<h2>mach — set up this machine</h2>
{{if .HasDL}}
<p>Detected platform: <b>{{.PrimaryOS}}</b></p>
<p><a href="{{.PrimaryDL}}" style="display:inline-block;font-size:1.1rem;padding:0.7rem 1.4rem;background:#111;color:#fff;text-decoration:none;">Download for {{.PrimaryOS}}</a>
<code style="color:#555;">{{.PrimaryFN}}</code></p>
{{else}}
<p>Platform not detected — pick from the list below.</p>
{{end}}
<p>Copy the binary to the target machine (scp/USB/whatever works), then on that machine run:</p>
<pre style="background:#f4f4f4;padding:0.8rem;overflow-x:auto;">chmod +x mach{{if .PrimaryFN}}{{if eq .PrimaryFN "mach-windows-amd64.exe"}}.exe{{end}}{{end}}
{{if .PrimaryFN}}{{if eq .PrimaryFN "mach-windows-amd64.exe"}}mach.exe{{else}}./mach{{end}}{{else}}./mach{{end}}   <span style="color:#555;"># then scan the QR it prints</span></pre>
<h3>All platforms</h3>
<table style="border-collapse:collapse;">
{{range .All}}
<tr><td style="padding:0.3rem 0.8rem 0.3rem 0;">{{.OS}}</td><td style="padding:0.3rem 0.8rem 0.3rem 0;color:#555;">{{.Arch}}</td>
<td><a href="/download/{{.File}}">download</a></td></tr>
{{end}}
</table>
<p style="color:#555;font-size:0.85rem;">The binary is static — no other files needed. Enrollment happens on the target machine: run <code>mach</code> there and scan the QR it prints (or use an API key headlessly).</p>
<p style="color:#555;font-size:0.85rem;">Org prefixes available on this control plane: {{range .Orgs}}<code>{{.}}</code> {{end}}— machine names will be <code>&lt;org&gt;-&lt;machine&gt;</code>.</p>
</body></html>`))

func (s *Server) handleEnrollRoot(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	h := w.Header()
	h.Set("X-Frame-Options", "DENY")
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("Referrer-Policy", "no-referrer")
	h.Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'")

	osKey, pretty := detectOSFromUA(r.UserAgent())
	arch := detectArchFromUA(r.UserAgent())
	primaryDL, primaryFN, hasDL := "", "", false
	if fn, ok := agentFilename(osKey, arch); ok {
		primaryDL, primaryFN, hasDL = "/download/"+fn, fn, true
	}
	data := enrollData{
		Orgs: s.ListOrgs(), PrimaryDL: primaryDL, PrimaryFN: primaryFN,
		PrimaryOS: pretty, HasDL: hasDL, All: platformRows,
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	_ = enrollTmpl.Execute(w, data)
}

// agentFilename maps (os, arch) to a shipped binary name, if present.
func agentFilename(osName, arch string) (string, bool) {
	fn := "mach-" + osName + "-" + arch + ext(osName)
	if !knownAgentFiles[fn] {
		return "", false
	}
	if !fileExists(filepath.Join(agentDirPath(), fn)) {
		return "", false
	}
	return fn, true
}

func ext(osName string) string {
	if osName == "windows" {
		return ".exe"
	}
	return ""
}

// agentDirPath locates cross-compiled agent binaries (static helper).
func agentDirPath() string {
	if v := os.Getenv("MACH_AGENT_DIR"); v != "" {
		return v
	}
	if _, err := os.Stat("/opt/mach-agents"); err == nil {
		return "/opt/mach-agents"
	}
	return "bin/cross"
}

// handleAgentDownload serves one binary by exact allowlisted filename.
func (s *Server) handleAgentDownload(w http.ResponseWriter, r *http.Request) {
	fn := filepath.Base(r.PathValue("file"))
	if !knownAgentFiles[fn] || !fileExists(filepath.Join(agentDirPath(), fn)) {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", `attachment; filename="`+fn+`"`)
	w.Header().Set("X-Content-Type-Options", "nosniff")
	http.ServeFile(w, r, filepath.Join(agentDirPath(), fn))
}

var _ = fmt.Sprintf // keep fmt for future page tweaks
