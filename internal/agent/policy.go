package agent

import (
	"os"
	"strings"
	"sync"
)

// Per-command execution policy, configured via MACH_POLICY env (survives in
// the service unit) or policy.txt in the state dir:
//
//	deny:rm -rf,deny:mkfs,deny:dd if=/dev/…   substrings — command refuses
//	allowonly:true                             deny-by-default; command must
//	                                           contain an allow: prefix substring
//
// Deny rules are checked against the lowercased command; argv mode checks
// argv[0] and each arg. This is a foot-guard, not a sandbox (documented).
type policy struct {
	mu        sync.Mutex
	deny      []string
	allowOnly bool
	allow     []string
	loaded    bool
}

var globalPolicy policy

func (p *policy) ensure() {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.loaded {
		return
	}
	p.loaded = true
	if v := os.Getenv("MACH_POLICY"); v != "" {
		p.parse(v)
	} else if raw, err := os.ReadFile(policyPath()); err == nil {
		p.parse(string(raw))
	}
}

func policyPath() string {
	return StateDir() + "/policy.txt"
}

func (p *policy) parse(spec string) {
	for _, line := range strings.Split(spec, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		switch {
		case strings.HasPrefix(line, "deny:"):
			p.deny = append(p.deny, strings.ToLower(strings.TrimPrefix(line, "deny:")))
		case line == "allowonly":
			p.allowOnly = true
		case strings.HasPrefix(line, "allow:"):
			p.allow = append(p.allow, strings.ToLower(strings.TrimPrefix(line, "allow:")))
		}
	}
}

// Evaluate returns a refusal reason, or "" to allow. Matching is done on a
// whitespace-normalized, lowercased form so deny rules survive arg-splicing
// (argv joins collapse spaces) — matching is best-effort by design.
func (p *policy) Evaluate(command string, argv []string) string {
	p.ensure()
	joined := strings.ToLower(command)
	if len(argv) > 0 {
		joined = strings.ToLower(strings.Join(argv, " "))
	}
	joined = strings.Join(strings.Fields(joined), " ")
	for _, d := range p.deny {
		if d != "" && strings.Contains(joined, strings.Join(strings.Fields(d), " ")) {
			return "denied by policy (matched: " + d + ")"
		}
	}
	if !p.allowOnly {
		return ""
	}
	for _, a := range p.allow {
		if a != "" && strings.Contains(joined, strings.Join(strings.Fields(a), " ")) {
			return ""
		}
	}
	return "denied by policy (allowlist mode; no allow: rule matched)"
}