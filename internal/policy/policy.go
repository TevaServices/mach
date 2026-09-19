// Package policy implements the command guardrails used by both the control
// plane (a global policy applied to every exec, for every API key) and the
// agent (a per-machine policy applied locally).
//
// Scope, stated plainly: this is a best-effort string guardrail, not a
// confinement boundary and not a sandbox. Rules are matched against a
// normalized rendering of the command, which defeats the cheap evasions
// (quote splicing, escaped whitespace, $IFS, separator swapping), and against
// the extra renderings below for the text-generating features that can be
// decided statically — every `${…}` parameter expansion, brace expansion, and
// ANSI-C quoting.
//
// It cannot see through a downloaded script, an interpreter, an alias, an
// encoded payload, or a glob (`dd if=/de?/zero` is the string "de?/zero" to
// this matcher and "dev" to the shell, and no amount of pattern work decides
// which characters a `*` will match). Use it to catch mistakes and to make
// casual misuse fail; use an OS-level mechanism (a dedicated unprivileged
// user, a container, seccomp, SELinux/AppArmor) when you need a boundary that
// holds against an attacker.
package policy

import (
	"crypto/sha256"
	"encoding/hex"
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
// concurrently with Evaluate. It returns the lines it did not recognize — the
// caller decides how loud to be about them (see IgnoredWarning).
func (p *Policy) Replace(spec string) []string {
	deny, allowOnly, allow, ignored := parse(spec)
	p.mu.Lock()
	p.deny, p.allowOnly, p.allow = deny, allowOnly, allow
	p.mu.Unlock()
	return ignored
}

// parse reads a ruleset spec. Anything that is not a blank line, a comment, or
// one of the three directives is returned as ignored rather than dropped in
// silence: `deny rm -rf` (no colon), `den:rm`, `Allowonly` and a bare `deny:`
// all parse to zero rules, and an operator who believes an allowlist is in
// force when it was never parsed has no guardrail at all. That is the same
// failure the unreadable-file rule refuses to start over, one level down — the
// parser's job is to report it, not to guess what was meant.
func parse(spec string) (deny []string, allowOnly bool, allow []string, ignored []string) {
	for _, line := range strings.Split(spec, "\n") {
		line = stripComment(strings.TrimSpace(line))
		if line == "" {
			continue
		}
		switch {
		case strings.HasPrefix(line, "deny:"):
			if r := Normalize(strings.TrimPrefix(line, "deny:")); r != "" {
				deny = append(deny, r)
			} else {
				ignored = append(ignored, line)
			}
		case line == "allowonly":
			allowOnly = true
		case strings.HasPrefix(line, "allow:"):
			if r := Normalize(strings.TrimPrefix(line, "allow:")); r != "" {
				allow = append(allow, r)
			} else {
				ignored = append(ignored, line)
			}
		default:
			ignored = append(ignored, line)
		}
	}
	return deny, allowOnly, allow, ignored
}

// IgnoredWarning renders the report for lines Replace could not use, or "" when
// there are none. One wording in one place, because this string is what an
// operator greps for after a rule they wrote had no effect — and the agent and
// the control plane both write it.
func IgnoredWarning(ignored []string) string {
	if len(ignored) == 0 {
		return ""
	}
	return "ignored " + strconv.Itoa(len(ignored)) + " rule line(s), which match no directive in the grammar: " +
		strconv.Quote(strings.Join(ignored, " | "))
}

// stripComment removes a trailing #-comment, using the shell's own rule for
// where one starts: at the beginning of a word (start of line, or after
// whitespace). Only whole-line comments used to be recognized, so
// `allowonly # only these` was silently not an allowlist — the line matched no
// rule and vanished — and `deny:rm -rf # never` became a deny for the substring
// "rm -rf # never", which matches nothing. Both failed open, which is the
// direction a guardrail must never fail.
func stripComment(line string) string {
	for i := 0; i < len(line); i++ {
		if line[i] != '#' {
			continue
		}
		if i == 0 || line[i-1] == ' ' || line[i-1] == '\t' {
			return strings.TrimSpace(line[:i])
		}
	}
	return line
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

// Fingerprint is a short content hash of a ruleset. Two ends of a connection
// use it to tell one version of the rules from another without shipping the
// rules back and forth: the control plane names the version it pushed, and an
// agent echoes the version it is enforcing.
func Fingerprint(spec string) string {
	sum := sha256.Sum256([]byte(spec))
	return hex.EncodeToString(sum[:8])
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
	var joined string
	var segments []string
	denyForms := []string{}
	if shellMode {
		// Deny rules match every rendering the command could take (see
		// denyRenderings) — the text as written is always one of them, so a
		// rendering can tighten a rule but never loosen one. The allowlist's
		// segmentation splits on the raw text (splitLines) before Normalize
		// folds the newline away, because that is the check a collapsed
		// separator defeats.
		joined = Normalize(command)
		segments = splitLines(command)
		denyForms = denyRenderings(command)
	} else {
		joined = Normalize(strings.Join(argv, " "))
		segments = []string{joined}
		denyForms = []string{joined}
	}

	for _, d := range deny {
		for _, form := range denyForms {
			if strings.Contains(form, d) {
				return "denied by command policy (deny:" + d + ")"
			}
		}
	}
	if !allowOnly {
		return ""
	}

	// A backtick is stripped by Normalize (it is quoting, and dropping it makes
	// `r\`m` match a deny rule), so by the time the text is a segment there is no
	// way to tell that one was there. Checked on the raw command, in shell mode
	// only, for the same reason as the substitution check below: an allow rule
	// cannot authorize what it cannot see.
	if shellMode && strings.ContainsRune(command, '`') {
		return "denied by command policy (allowlist mode: backtick command substitution, which an allow rule cannot authorize)"
	}

	if len(segments) == 0 {
		// Nothing to match against an allow rule: fail closed.
		return "denied by command policy (allowlist mode: empty command)"
	}
	for _, seg := range segments {
		if !allowedBy(allow, seg) {
			return "denied by command policy (allowlist mode: no allow: rule matches " + strconv.Quote(seg) + ")"
		}
		// An allow rule matches a prefix, and a prefix stops describing what will
		// run once the shell can start a *second* command inside it. `$(...)`,
		// backticks and process substitution all do that, and only the first
		// survives Normalize (which strips backticks as quoting): with
		// `allowonly` + `allow:kubectl`, `kubectl get pods $(rm -rf /)` and
		// ``echo `rm -rf /` `` both passed an allowlist whose documented promise
		// is that every command the shell would run starts with an allow rule.
		//
		// This is a refusal, not a parse: the constructs cannot be enumerated, so
		// an allowlist declines the ones it cannot see through rather than
		// pretending to judge them. argv mode is untouched — nothing re-parses an
		// argument vector, so `-- echo '$(date)'` still passes its literal text.
		if shellMode && hasSubstitution(seg) {
			return "denied by command policy (allowlist mode: " + strconv.Quote(seg) +
				" starts a nested command, which an allow rule cannot authorize; use argv mode for a literal)"
		}
	}
	return ""
}

// hasSubstitution reports whether a normalized command can start a nested one.
// It runs on the normalized text, where backticks have already been removed —
// so the caller checks the pre-normalized command for those separately, through
// the ContainsRune check in Evaluate, which Normalize cannot report.
func hasSubstitution(seg string) bool {
	return strings.Contains(seg, "$(") || strings.Contains(seg, "<(") || strings.Contains(seg, ">(")
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

// splitLines renders a raw shell command into the normalized segments an
// allowlist is matched against, splitting on newlines BEFORE normalization.
//
// A newline ends a command in the shell, and Normalize collapses all whitespace
// — newlines included — into single spaces. Splitting after normalizing
// therefore could not see the separator at all: with `allowonly` +
// `allow:journalctl -u`, the single string "journalctl -u nginx\nrm -rf /"
// became one segment, `journalctl -u nginx rm -rf /`, which still satisfies the
// prefix rule while the shell passes both lines to bash -c and runs them. The
// identical input with a ';' was refused, so the one separator splitCommands
// names was the one it could not reach — an allowlist trivially bypassed by any
// pasted multi-line command.
//
// Only \n is a separator here, because only \n starts a new command in a shell.
// The other whitespace characters Normalize folds (tab, \r, \v, \f) separate
// words rather than commands there, so collapsing them is what lets the matcher
// see through them rather than something to preserve.
func splitLines(command string) []string {
	var out []string
	for _, line := range strings.Split(command, "\n") {
		n := Normalize(line)
		if n == "" {
			continue
		}
		out = append(out, splitCommands(n)...)
	}
	return out
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

// denyRenderings returns every normalized form a deny rule is matched against.
//
// The first is the command exactly as written, with the enumerated $IFS
// spellings folded by Normalize — so nothing that used to be caught stops being
// caught, and every rendering below can only add refusals.
//
// The rest exist because a shell generates text this matcher cannot see, and
// the shapes are bounded even where the spellings are not:
//
//   - A parameter expansion may produce whitespace, nothing, or anything else.
//     `${IFS:0:1}` is a space, and `${IFS: -1}`, `${IFS:?}` and `${IFS:1:1}`
//     are the same space spelled three more ways, so the enumerated replacer in
//     Normalize could never have covered them: `rm${IFS:0}-rf /` slid past a
//     `deny:rm -rf`, while the same command with the space written out was
//     refused. The spellings cannot be enumerated, but the two extremes can be
//     rendered — the expansion removed entirely (which can only join the text
//     around it) and the expansion replaced by a space (which can only separate
//     it) — and a rule that matches either is refused.
//   - Brace expansion is the same shape without a '$': `{rm,-rf,/}` is one word
//     to the matcher and three to the shell, so its comma-separated members are
//     rendered as the separate words they become.
//   - ANSI-C quoting is not an expansion at all but a literal with an encoding:
//     `$'\x72\x6d'` *is* `rm`, so it is decoded rather than guessed at.
//
// What is deliberately absent is the glob: `?` and `*` are decided by the
// filesystem at run time, and a matcher that guessed would be inventing facts.
func denyRenderings(command string) []string {
	base := Normalize(command)
	out := []string{base}
	add := func(s string) {
		if s != base {
			for _, seen := range out {
				if seen == s {
					return
				}
			}
			out = append(out, s)
		}
	}
	if strings.Contains(command, "${") {
		add(Normalize(expandAway(command, "")))
		add(Normalize(expandAway(command, " ")))
	}
	if strings.Contains(command, "'") && strings.Contains(command, "\\") {
		add(Normalize(ansiCDecoded(command)))
	}
	if strings.Contains(command, "{") && strings.Contains(command, ",") {
		add(Normalize(flattenBraces(command)))
	}
	return out
}

// expandAway replaces every ${…} parameter expansion with repl, skipping nested
// braces so `${a${b}c}` is one expansion rather than two. A '$' with no brace is
// left alone: `$IFS` and `$VAR` are single words to the shell, and Normalize
// already folds the IFS spellings that can become whitespace.
func expandAway(s, repl string) string {
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); {
		if s[i] != '$' || i+1 >= len(s) || s[i+1] != '{' {
			b.WriteByte(s[i])
			i++
			continue
		}
		depth, j := 0, i+1
		for ; j < len(s); j++ {
			switch s[j] {
			case '{':
				depth++
			case '}':
				depth--
			}
			if depth == 0 {
				break
			}
		}
		if j >= len(s) {
			// Unterminated: leave it as written rather than swallowing the rest.
			b.WriteString(s[i:])
			break
		}
		b.WriteString(repl)
		i = j + 1
	}
	return b.String()
}

// flattenBraces renders a comma-separated brace group as the words it expands
// to, so `{rm,-rf,/}` reads as `rm -rf /`. A group with no comma is left alone
// (a lone brace is ordinary text to the shell, and `{a..z}` needs an expansion
// this does not attempt — under-matching there is the safe direction only when
// it does not also drop a literal, which is why the base rendering is always
// still checked).
func flattenBraces(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); {
		if s[i] != '{' {
			b.WriteByte(s[i])
			i++
			continue
		}
		j := strings.IndexByte(s[i:], '}')
		if j < 0 {
			b.WriteString(s[i:])
			break
		}
		body := s[i+1 : i+j]
		if !strings.Contains(body, ",") {
			b.WriteString(s[i : i+j+1])
			i += j + 1
			continue
		}
		b.WriteByte(' ')
		b.WriteString(strings.ReplaceAll(body, ",", " "))
		b.WriteByte(' ')
		i += j + 1
	}
	return b.String()
}

// ansiCDecoded renders $'…' ANSI-C quoting as the literal text the shell will
// see, so `$'\x72\x6d' -rf /` reads as `rm -rf /`. Only the escapes that
// produce text are decoded; anything unrecognized is kept verbatim, which can
// only make the rendering less specific and never more.
func ansiCDecoded(s string) string {
	if !strings.Contains(s, "$'") {
		return s
	}
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); {
		if s[i] != '$' || i+1 >= len(s) || s[i+1] != '\'' {
			b.WriteByte(s[i])
			i++
			continue
		}
		var lit strings.Builder
		j := i + 2
		for j < len(s) && s[j] != '\'' {
			if s[j] == '\\' && j+1 < len(s) {
				lit.WriteByte(s[j])
				lit.WriteByte(s[j+1])
				j += 2
				continue
			}
			lit.WriteByte(s[j])
			j++
		}
		if j >= len(s) {
			b.WriteString(s[i:]) // unterminated quote: ordinary text
			break
		}
		b.WriteString(unescapeANSI(lit.String()))
		i = j + 1
	}
	return b.String()
}

// unescapeANSI decodes the C-style escapes bash understands inside $'…'.
func unescapeANSI(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); i++ {
		if s[i] != '\\' || i+1 >= len(s) {
			b.WriteByte(s[i])
			continue
		}
		i++
		switch c := s[i]; c {
		case 'n':
			b.WriteByte('\n')
		case 't':
			b.WriteByte('\t')
		case 'r':
			b.WriteByte('\r')
		case 'a':
			b.WriteByte(7)
		case 'b':
			b.WriteByte(8)
		case 'f':
			b.WriteByte(12)
		case 'v':
			b.WriteByte(11)
		case 'e', 'E':
			b.WriteByte(27)
		case '\\', '\'', '"', '?':
			b.WriteByte(c)
		case 'x', 'u', 'U':
			width := map[byte]int{'x': 2, 'u': 4, 'U': 8}[c]
			v, n := parseHexDigits(s[i+1:], width)
			if n == 0 {
				b.WriteByte('\\')
				b.WriteByte(c)
				break
			}
			b.WriteRune(rune(v))
			i += n
		default:
			b.WriteByte('\\')
			b.WriteByte(c)
		}
	}
	return b.String()
}

const hexDigits = "0123456789abcdefABCDEF"

// parseHexDigits reads between 1 and width hex digits and returns their value
// and how many were consumed.
func parseHexDigits(s string, width int) (int, int) {
	n, v := 0, 0
	for ; n < width && n < len(s); n++ {
		d := strings.IndexByte(hexDigits, s[n])
		if d < 0 {
			break
		}
		if d >= 16 {
			d -= 6 // uppercase A-F sit above the lowercase ones in hexDigits
		}
		v = v*16 + d
	}
	return v, n
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
