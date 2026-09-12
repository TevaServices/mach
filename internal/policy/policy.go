// Package policy implements the command guardrails used by both the control
// plane (a global policy applied to every exec, for every API key) and the
// agent (a per-machine policy applied locally).
//
// Scope, stated plainly: this is a best-effort string guardrail, not a
// confinement boundary and not a sandbox. Rules are matched against a
// normalized rendering of the command, which defeats the cheap evasions
// (quote splicing, escaped whitespace, $IFS, separator swapping), but no
// string matcher can decide what a shell will actually execute — it cannot
// see through a downloaded script, an interpreter, an alias, or an encoded
// payload. Use it to catch mistakes and to make casual misuse fail; use an
// OS-level mechanism (a dedicated unprivileged user, a container, seccomp,
// SELinux/AppArmor) when you need a boundary that holds against an attacker.
package policy

import (
	"strconv"
	"strings"
	"sync"
)

// Grammar (one rule per line; blank lines and #-comments ignored):
//
//	deny:<substring>   refuse a command whose normalized form contains <substring>
//	allowonly          deny everything not explicitly allowed below
//	allow:<prefix>     permit a command whose normalized form starts with <prefix>
//
// Deny rules are fail-closed and match anywhere in the command. Allow rules
// are anchored: a command is permitted only when every command the shell
// would run starts with an allow rule (so an allow rule cannot be satisfied
// by merely mentioning a permitted word later in the line).
type Policy struct {
	mu        sync.RWMutex
	deny      []string
	allowOnly bool
	allow     []string
}

// New returns an empty policy (allow everything).
func New() *Policy { return &Policy{} }

// Replace resets the policy and loads spec into it. It is safe to call
// concurrently with Evaluate.
func (p *Policy) Replace(spec string) {
	deny, allowOnly, allow := parse(spec)
	p.mu.Lock()
	p.deny, p.allowOnly, p.allow = deny, allowOnly, allow
	p.mu.Unlock()
}

func parse(spec string) (deny []string, allowOnly bool, allow []string) {
	for _, line := range strings.Split(spec, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		switch {
		case strings.HasPrefix(line, "deny:"):
			if r := Normalize(strings.TrimPrefix(line, "deny:")); r != "" {
				deny = append(deny, r)
			}
		case line == "allowonly":
			allowOnly = true
		case strings.HasPrefix(line, "allow:"):
			if r := Normalize(strings.TrimPrefix(line, "allow:")); r != "" {
				allow = append(allow, r)
			}
		}
	}
	return deny, allowOnly, allow
}

// Empty reports whether the policy has no rules (nothing to enforce).
func (p *Policy) Empty() bool {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return !p.allowOnly && len(p.deny) == 0
}

// Describe returns the active rules in their original grammar, for logging.
func (p *Policy) Describe() []string {
	p.mu.RLock()
	defer p.mu.RUnlock()
	out := make([]string, 0, len(p.deny)+len(p.allow)+1)
	for _, d := range p.deny {
		out = append(out, "deny:"+d)
	}
	if p.allowOnly {
		out = append(out, "allowonly")
	}
	for _, a := range p.allow {
		out = append(out, "allow:"+a)
	}
	return out
}

// Evaluate returns a refusal reason, or "" to allow. command is the
// shell-mode string; argv is the no-shell argument vector. Exactly one of
// them is meaningful, matching how the command will actually be run: argv
// mode is never re-parsed by a shell, so it is matched as a single command
// (a ';' inside an argument is a literal character there, not a separator).
func (p *Policy) Evaluate(command string, argv []string) string {
	p.mu.RLock()
	deny, allowOnly, allow := p.deny, p.allowOnly, p.allow
	p.mu.RUnlock()

	shellMode := len(argv) == 0
	joined := Normalize(command)
	if !shellMode {
		joined = Normalize(strings.Join(argv, " "))
	}

	for _, d := range deny {
		if strings.Contains(joined, d) {
			return "denied by command policy (deny:" + d + ")"
		}
	}
	if !allowOnly {
		return ""
	}

	segments := []string{joined}
	if shellMode {
		segments = splitCommands(joined)
	}
	if len(segments) == 0 {
		// Nothing to match against an allow rule: fail closed.
		return "denied by command policy (allowlist mode: empty command)"
	}
	for _, seg := range segments {
		if !allowedBy(allow, seg) {
			return "denied by command policy (allowlist mode: no allow: rule matches " + strconv.Quote(seg) + ")"
		}
	}
	return ""
}

// allowedBy reports whether a single command is permitted by the allow
// rules. Matching is anchored at the start of the command and on a word
// boundary, so allow:echo permits "echo hi" but not "echofoo" and not
// "curl evil | echo".
func allowedBy(allow []string, seg string) bool {
	for _, a := range allow {
		if a == "" {
			continue
		}
		if seg == a || strings.HasPrefix(seg, a+" ") {
			return true
		}
	}
	return false
}

// splitCommands separates a normalized command line into the individual
// commands a shell would run, splitting on the control operators. It runs on
// the normalized text, so quoting can no longer hide a separator.
func splitCommands(s string) []string {
	var out []string
	for _, field := range strings.FieldsFunc(s, func(r rune) bool {
		switch r {
		case ';', '|', '&', '\n':
			return true
		}
		return false
	}) {
		if seg := strings.TrimSpace(field); seg != "" {
			out = append(out, seg)
		}
	}
	return out
}

// ifsReplacer expands the shell's IFS trick, the oldest way to smuggle
// whitespace past a substring matcher ("rm${IFS}-rf").
var ifsReplacer = strings.NewReplacer(
	"${ifs:0:1}", " ",
	"${ifs%?}", " ",
	"${ifs}", " ",
	"$ifs", " ",
)

// Normalize renders a command into the canonical form rules are matched
// against: lowercased, shell quoting and escape characters removed, $IFS
// expanded, whitespace collapsed. Those artifacts carry no meaning for
// matching, so dropping them means "r”m -rf" and "rm\ -rf" both normalize
// to "rm -rf" instead of sliding past a deny rule.
func Normalize(s string) string {
	s = strings.ToLower(s)
	s = ifsReplacer.Replace(s)
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); i++ {
		switch c := s[i]; c {
		case '\'', '"', '\\', '`':
			// ASCII bytes that cannot appear inside a multi-byte UTF-8
			// sequence, so dropping them never corrupts a rune.
			continue
		default:
			b.WriteByte(c)
		}
	}
	return strings.Join(strings.Fields(b.String()), " ")
}
