package server

import (
	"html/template"
	"net/http"
	"strconv"
	"strings"

	"github.com/bcross/mach/internal/store"
)

// Minimal phone-facing approve page. Not for human dashboards.
//
// Security properties:
//   - The challenge code is NEVER displayed on this page. The human must
//     type the code they read on the agent's console (anti-QR-theft: a
//     photo of just the QR is useless; a shoulder-surfer must memorize
//     six digits AND photograph the QR).
//   - No machine name is suggested from the agent's self-reported hostname
//     (anti-phishing: the operator chooses the name, unadulterated).
//   - Wrong code attempts are counted; 5 wrong attempts expire the pairing.
//   - Security headers set on every response.

const pairPageTmpl = `<!doctype html>
<html><head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>mach — approve machine</title>
</head><body style="font-family:-apple-system,system-ui,sans-serif;max-width:28rem;margin:3rem auto;padding:0 1rem;">
<h2>mach — approve machine</h2>
{{if .Error}}<p style="color:#b00020;font-weight:600;">{{.Error}}</p>{{end}}
{{if .Done}}
<p>✅ Machine approved and named <b>{{.Name}}</b>. The agent on that machine will finish enrollment within a few seconds.</p>
{{else if .State}}
<p>Pairing state: <b>{{.State}}</b></p>
{{else}}
<p><b>New agent requesting enrollment</b> (self-reported below — verify out-of-band that a new machine is actually being set up):</p>
<table style="border-collapse:collapse;">
<tr><td style="padding-right:1rem;color:#555;">reports hostname</td><td>{{.Hostname}}</td></tr>
<tr><td style="color:#555;">reports platform</td><td>{{.OS}}/{{.Arch}} — agent {{.AgentVer}}</td></tr>
</table>
<p>Type the <b>challenge code shown on the agent's console</b> (12 characters, XXXX-XXXX-XXXX format — the machine being enrolled). It is <i>not</i> in this QR/page.</p>
<form method="POST" action="/pair/{{.Token}}">
<label>Challenge code:<br>
<input name="code" autocomplete="off" autocapitalize="characters" spellcheck="false" required minlength="12" maxlength="19" style="font-size:1.2rem;width:16em;padding:0.4rem;letter-spacing:0.15em;text-transform:uppercase;"></label>
<p><label>Org (pick from the list or free-type a registered one):<br>
<input name="org" list="orgs" required minlength="2" maxlength="20" style="font-size:1.2rem;width:12em;padding:0.4rem;" placeholder="org">
<datalist id="orgs">{{range .Orgs}}<option value="{{.}}">{{end}}</datalist></label></p>
<p><label>Machine name (full name = <code>&lt;org&gt;-&lt;machine&gt;</code>):<br>
<input name="name" required style="font-size:1.2rem;width:16em;padding:0.4rem;" placeholder="machine-part"></label></p>
<p><button type="submit" name="approve" value="1" style="font-size:1.1rem;padding:0.6rem 1.4rem;">Approve</button>
<button type="submit" name="deny" value="1" style="font-size:1.1rem;padding:0.6rem 1.4rem;background:#eee;">Deny</button></p>
</form>
<p style="color:#555;font-size:0.85rem;">5 wrong code attempts expire this pairing. Only approve if you personally initiated enrollment on that machine.</p>
{{end}}
</body></html>`

var pairTmpl = template.Must(template.New("pair").Parse(pairPageTmpl))

type pairPageData struct {
	Error     string
	Done      bool
	Name      string
	State     string
	Hostname  string
	OS        string
	Arch      string
	AgentVer  string
	Token     string
	Orgs      []string
}

func (s *Server) pairPageHandler(w http.ResponseWriter, r *http.Request) {
	// Security headers on every pair-page response.
	h := w.Header()
	h.Set("X-Frame-Options", "DENY")
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("Referrer-Policy", "no-referrer")
	h.Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'")

	token := r.PathValue("token")
	p, err := s.st.PairingByToken(token)
	if err != nil || p == nil {
		http.Error(w, "unknown pairing link", http.StatusNotFound)
		return
	}
	state := s.st.PairingState(p)

	if r.Method == http.MethodPost {
		s.handlePairPost(w, r, p, state)
		return
	}

	switch state {
	case "approved", "denied", "expired":
		renderPair(w, pairPageData{State: state, Name: p.Name})
	default:
		renderPair(w, pairPageData{
			Hostname: p.Hostname, OS: p.OS, Arch: p.Arch, AgentVer: p.AgentVer,
			Token: token, Orgs: s.ListOrgs(),
		})
	}
}

func (s *Server) handlePairPost(w http.ResponseWriter, r *http.Request, p *store.Pairing, state string) {
	_ = r.ParseForm()
	if r.FormValue("deny") == "1" {
		_ = s.st.DenyPairing(p.ID)
		renderPair(w, pairPageData{State: "denied"})
		return
	}
	if state != "pending" {
		renderPair(w, pairPageData{State: state})
		return
	}
	code := normalizeCode(r.FormValue("code"))
	org := strings.ToLower(strings.TrimSpace(r.FormValue("org")))
	machinePart := strings.TrimSpace(r.FormValue("name"))
	name := org + "-" + machinePart

	// Org must be a registered org (dropdown or free-typed), and the
	// composed name must satisfy the org-prefix rule. Conflicts error out
	// and require a new name.
	if !s.orgRegistered(org) {
		renderPair(w, pairPageData{Error: "Unknown org " + strconv.Quote(org) + " — pick one from the list or use a registered org.", State: "pending-retry", Token: p.ID, Orgs: s.ListOrgs()})
		return
	}
	if !store.ValidOrgName(org, name) {
		renderPair(w, pairPageData{Error: "Machine part must be 1-48 chars (letters/digits/hyphen). Final name: " + org + "-<machine>.", State: "pending-retry", Token: p.ID, Orgs: s.ListOrgs()})
		return
	}
	if existing, _ := s.st.MachineByName(name); existing != nil {
		renderPair(w, pairPageData{Error: "Machine name already taken — pick a new name (e.g. " + name + "-2).", State: "pending-retry", Token: p.ID, Orgs: s.ListOrgs()})
		return
	}

	ok, why, err := s.st.ApprovePairing(p.ID, code, name)
	if err != nil {
		http.Error(w, "store error", http.StatusInternalServerError)
		return
	}
	if !ok {
		if why == "bad-code" {
			// Count the attempt; expire the pairing after 5 wrong tries.
			alive, aerr := s.st.RecordPairingAttempt(p.ID, 5)
			if aerr != nil || !alive {
				renderPair(w, pairPageData{Error: "Too many wrong code attempts — this pairing is expired. Run enrollment again on the machine.", State: "expired"})
				return
			}
			renderPair(w, pairPageData{Error: "Wrong code. Do not approve unless you can read the agent's console.", State: "pending-retry", Token: p.ID, Orgs: s.ListOrgs()})
			return
		}
		renderPair(w, pairPageData{State: why, Orgs: s.ListOrgs()})
		return
	}
	s.logf("pair approved: id=%s name=%s", p.ID, name)
	renderPair(w, pairPageData{Done: true, Name: name})
}

func renderPair(w http.ResponseWriter, data pairPageData) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	_ = pairTmpl.Execute(w, data)
}

// normalizeCode uppercases and strips separators so XXXX-XXXX-XXXX can be
// typed with or without dashes/spaces.
func normalizeCode(s string) string {
	var b strings.Builder
	for _, r := range strings.ToUpper(strings.TrimSpace(s)) {
		if r == '-' || r == ' ' {
			continue
		}
		b.WriteRune(r)
	}
	return b.String()
}