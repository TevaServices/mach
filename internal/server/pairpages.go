package server

import (
	"html/template"
	"net/http"
	"strings"

	"github.com/bcross/mach/internal/store"
)

// Minimal phone-facing approve page. Not for human dashboards: this exists
// solely so the machine owner can scan the agent's QR, verify the challenge
// code, and name the machine.

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
<p><b>New agent requesting enrollment:</b></p>
<table style="border-collapse:collapse;">
<tr><td style="padding-right:1rem;color:#555;">hostname</td><td><b>{{.Hostname}}</b></td></tr>
<tr><td style="color:#555;">platform</td><td>{{.OS}}/{{.Arch}} — agent {{.AgentVer}}</td></tr>
</table>
<p>Verify this challenge code matches what the agent printed on the machine's console:</p>
<p style="font-size:2rem;letter-spacing:0.4em;font-weight:700;margin:0.5rem 0 1.5rem;">{{.Code}}</p>
<form method="POST" action="/pair/{{.Token}}">
<input type="hidden" name="expected_code" value="{{.Code}}">
<label>Challenge code (type it to confirm):<br>
<input name="code" inputmode="numeric" autocomplete="off" required style="font-size:1.2rem;width:8em;padding:0.4rem;"></label>
<p><label>Machine name:<br>
<input name="name" required pattern="[A-Za-z0-9-]{1,63}" value="{{.Suggested}}" style="font-size:1.2rem;width:14em;padding:0.4rem;"></label></p>
<p><button type="submit" name="approve" value="1" style="font-size:1.1rem;padding:0.6rem 1.4rem;">Approve</button>
<button type="submit" name="deny" value="1" style="font-size:1.1rem;padding:0.6rem 1.4rem;background:#eee;">Deny</button></p>
</form>
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
	Code      string
	Token     string
	Suggested string
}

func (s *Server) handlePairPage(w http.ResponseWriter, r *http.Request) {
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
		suggested := p.Hostname
		suggested = strings.Map(func(c rune) rune {
			ok := c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-'
			if ok {
				return c
			}
			return '-'
		}, suggested)
		if len(suggested) > 63 {
			suggested = suggested[:63]
		}
		renderPair(w, pairPageData{
			Hostname: p.Hostname, OS: p.OS, Arch: p.Arch, AgentVer: p.AgentVer,
			Code: p.Code, Token: token, Suggested: suggested,
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
	code := r.FormValue("code")
	name := strings.TrimSpace(r.FormValue("name"))
	ok, why, err := s.st.ApprovePairing(p.ID, code, name)
	if err != nil {
		http.Error(w, "store error", http.StatusInternalServerError)
		return
	}
	if !ok {
		if why == "bad-code" {
			renderPair(w, pairPageData{Error: "Challenge code did not match — do not approve unless the codes are identical.", State: "pending-retry"})
			return
		}
		renderPair(w, pairPageData{State: why})
		return
	}
	if !validMachineName(name) {
		// Roll the approval back to pending so it can be redone correctly.
		_ = s.st.ReopenPairing(p.ID)
		renderPair(w, pairPageData{Error: "Name must be 1-63 chars: letters, digits, '-'. Try again.", State: "pending-retry"})
		return
	}
	if existing, _ := s.st.MachineByName(name); existing != nil {
		_ = s.st.ReopenPairing(p.ID)
		renderPair(w, pairPageData{Error: "That machine name is already taken. Pick another.", State: "pending-retry"})
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