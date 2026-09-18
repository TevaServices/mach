package server

import (
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
	PrimaryDL string // /download/<file> for the selected OS
	PrimaryFN string // filename
	PrimaryOS string // pretty OS name
	HasDL     bool
	RunAs     string // how the operator runs the binary on the target
	// Detected is true when the selection came from the user agent rather than
	// from an explicit tab click, so the page can say which it was.
	Detected bool
	All      []platformRow
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

// enrollPickSource is the recommended-download block. It is its own fragment
// (and its own root element) because the platform tabs below swap it in place —
// picking a platform re-requests just this, rather than reloading the page.
//
// It is also the copy-paste block: choosing the wrong architecture is the most
// common way to get a binary that will not run, and the tabs are how an operator
// corrects the guess the user agent made.
// The download button and the command block used to carry their own hardcoded
// colours (#111 background, #555 text), which is unreadable on a dark screen:
// the page declares `color-scheme: light dark` and so renders dark by default
// for a viewer who prefers it. They now take their colours from the shared
// stylesheet (static/ui.css) like every other page, which is also what makes this
// page and the phone-facing pair page look like the same product.
const enrollPickSource = `{{define "enrollpick"}}
<div id="enroll-pick">
{{if .HasDL}}
<p>Recommended for <b>{{.PrimaryOS}}</b>{{if .Detected}} (detected from your browser){{end}}:</p>
<p><a class="btn-primary" href="{{.PrimaryDL}}">Download for {{.PrimaryOS}}</a>
<code class="muted">{{.PrimaryFN}}</code></p>
<pre id="cmds" class="panel panel-scroll">chmod +x {{.RunAs}}
{{.RunAs}}   <span class="muted"># then scan the QR it prints</span></pre>
<p><button type="button" data-copy="#cmds">Copy commands</button></p>
{{else}}
<p>No build is available for that platform on this control plane.</p>
{{end}}
</div>
{{end}}`

// enrollSource is the page body: the fragment above, the platform tabs that
// replace it, and the full list.
const enrollSource = `{{define "enroll"}}
{{template "enrollpick" .}}
<h2>Choose a platform</h2>
<p>
{{range .Tabs}}
<button type="button" hx-get="/partials/enroll/{{.OSKey}}/{{.ArchKey}}"
        hx-target="#enroll-pick" hx-swap="outerHTML">{{.Label}}</button>
{{end}}
</p>
<h2>All platforms</h2>
<div class="table-scroll" role="region" aria-label="All platforms" tabindex="0">
<table>
<caption class="sr-only">Every build this control plane ships, by platform</caption>
<thead><tr><th scope="col">OS</th><th scope="col">CPU</th><th scope="col">Binary</th></tr></thead>
<tbody>
{{range .All}}
<tr><td>{{.OS}}</td><td class="muted">{{.Arch}}</td>
<td><a href="/download/{{.File}}">download</a></td></tr>
{{end}}
</tbody>
</table>
</div>
<p class="muted">Enrollment happens on the target machine: run <code>mach</code>
there and scan the QR it prints. Orgs on this control plane:
{{range .Orgs}}<code>{{.}}</code> {{end}}— names will be
<code>&lt;org&gt;-&lt;machine&gt;</code>.</p>
{{end}}`

// One template set holds both defines: "enroll" (the page body) and
// "enrollpick" (the fragment the tabs swap), so the page can template the
// fragment inline and the handler can serve it alone.
var enrollTemplate = template.Must(template.New("enroll").Parse(enrollPickSource + enrollSource))

// enrollTab is one platform selector.
type enrollTab struct {
	Label   string
	OSKey   string
	ArchKey string
}

// The tabs cover every platform that ships a build, in the order the table
// lists them. The user agent only chooses the initial default; a wrong guess is
// one click to correct.
var enrollTabs = []enrollTab{
	{"Linux amd64", "linux", "amd64"},
	{"Linux arm64", "linux", "arm64"},
	{"macOS Intel", "darwin", "amd64"},
	{"macOS Apple Silicon", "darwin", "arm64"},
	{"Windows amd64", "windows", "amd64"},
	{"Windows arm64", "windows", "arm64"},
}

// enrollPageData is the full page: the recommendation plus the tabs that can
// replace it. Tabs lives here and NOT on enrollData, because a field on the
// embedded struct is shadowed by one of the same name on the outer — the page
// set the inner slice while `{{range .Tabs}}` read the outer nil one, so the
// "Choose a platform" row rendered empty and an operator whose user agent was
// guessed wrong could not switch to their actual platform.
type enrollPageData struct {
	enrollData
	Tabs []enrollTab
}

// enrollHeaders are for the public enrollment page and its fragments.
//
// This page shares the shell with the control-plane UI, so it needs
// script-src 'self' for the vendored htmx and app.js, and style-src 'self' for the
// linked stylesheet. The pair page keeps the stricter default-src 'none' it has
// always had: it is the page a phone reaches from a QR code and it needs no script
// at all. The script relaxation is a real, if small, widening on an
// unauthenticated page, and it is recorded as such in SECURITY-NOTES.md rather
// than left implicit.
//
// The two headers must be kept in step with uiHeaders: this page renders through
// the same shell, so a policy that is tighter here than there would break a page
// the operator UI proves works.
func enrollHeaders(w http.ResponseWriter) {
	h := w.Header()
	h.Set("X-Frame-Options", "DENY")
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("Referrer-Policy", "no-referrer")
	h.Set("Content-Security-Policy",
		"default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; form-action 'self'")
}

func (s *Server) handleEnrollRoot(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	enrollHeaders(w)
	// The user agent is a hint, never a decision: it picks the initial selection
	// and the tabs correct it.
	osKey, pretty := detectOSFromUA(r.UserAgent())
	arch := detectArchFromUA(r.UserAgent())
	data := s.enrollDataFor(osKey, arch, pretty)
	data.Detected = true
	data.Orgs = s.ListOrgs()
	// One string serves as both the tab title and the page's h1 (see the shell),
	// so it is written to read as a heading: "set up this machine" addresses the
	// person on the target host, which "a machine" did not.
	s.renderIntoShell(w, http.StatusOK, uiShellData{Title: "mach — set up this machine", Public: true},
		enrollTemplate, "enroll", enrollPageData{enrollData: data, Tabs: enrollTabs})
}

// handleEnrollPlatform serves one platform's recommendation as a fragment, for
// the tabs.
func (s *Server) handleEnrollPlatform(w http.ResponseWriter, r *http.Request) {
	osKey := strings.ToLower(r.PathValue("os"))
	arch := strings.ToLower(r.PathValue("arch"))
	// Only shipped combinations resolve. The values are matched against the
	// allowlist rather than interpolated into a path, so a crafted os/arch pair
	// cannot name a file.
	if !knownPlatform(osKey, arch) {
		http.NotFound(w, r)
		return
	}
	enrollHeaders(w)
	data := s.enrollDataFor(osKey, arch, prettyPlatform(osKey))
	s.renderFragment(w, uiSession{}, enrollTemplate, "enrollpick", data)
}

func knownPlatform(osKey, arch string) bool {
	if _, ok := agentFilename(osKey, arch); ok {
		return true
	}
	// A shipped-but-absent binary is still a known platform: the page then says
	// so, which is more useful than a 404.
	for _, t := range enrollTabs {
		if t.OSKey == osKey && t.ArchKey == arch {
			return true
		}
	}
	return false
}

func prettyPlatform(osKey string) string {
	for _, t := range enrollTabs {
		if t.OSKey == osKey {
			return t.Label
		}
	}
	return osKey
}

// enrollDataFor resolves the recommendation for one platform.
func (s *Server) enrollDataFor(osKey, arch, pretty string) enrollData {
	fn, ok := agentFilename(osKey, arch)
	if !ok {
		return enrollData{PrimaryOS: pretty, All: platformRows}
	}
	runAs := "./mach"
	if fn == "mach-windows-amd64.exe" || fn == "mach-windows-arm64.exe" {
		runAs = "mach.exe"
	}
	return enrollData{
		PrimaryDL: "/download/" + fn, PrimaryFN: fn, PrimaryOS: pretty,
		HasDL: true, RunAs: runAs, All: platformRows,
	}
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
