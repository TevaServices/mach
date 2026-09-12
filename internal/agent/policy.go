package agent

import (
	"os"
	"sync"

	"github.com/bcross/mach/internal/policy"
)

// Per-machine command guardrail, configured via MACH_POLICY env (survives in
// the service unit) or policy.txt in the state dir. The grammar and matching
// semantics live in internal/policy, which the control plane's global policy
// shares:
//
//	deny:rm -rf          refuse commands containing this substring
//	allowonly            deny by default; every command must start with an
//	                     allow: rule
//	allow:systemctl      permit commands starting with this prefix
//
// This is a guardrail, not a confinement boundary — see the package comment
// on internal/policy for what it can and cannot promise.
type lazyPolicy struct {
	once sync.Once
	p    policy.Policy
}

// globalPolicy is loaded on first use: reading the state dir at process
// start would run before the agent has dropped privileges.
var globalPolicy lazyPolicy

func (l *lazyPolicy) Evaluate(command string, argv []string) string {
	l.once.Do(func() {
		if v := os.Getenv("MACH_POLICY"); v != "" {
			l.p.Replace(v)
			return
		}
		if raw, err := os.ReadFile(policyPath()); err == nil {
			l.p.Replace(string(raw))
		}
	})
	return l.p.Evaluate(command, argv)
}

// install replaces the process-wide guardrail at runtime. The lazy load is
// marked done so a later Evaluate never re-reads the environment out from under
// whoever installed the rules.
func (l *lazyPolicy) install(spec string) {
	l.once.Do(func() {})
	l.p.Replace(spec)
}

func policyPath() string {
	return StateDir() + "/policy.txt"
}
