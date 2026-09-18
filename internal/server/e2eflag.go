package server

// E2E feature flag — whether this control plane accepts end-to-end encrypted
// (sealed) exec commands, decided per org.
//
// E2E is a server-side setting, not a client preference, because it is the
// server that has to accept or refuse ciphertext: it is the party that cannot
// read a sealed command, and the one an operator points at when they say "this
// fleet must be inspectable" or "this fleet must not be". Consoles therefore do
// not decide anything on their own — the control plane tells every client what
// it accepts (GET /v1/machines/{name}/e2epub, and the fleet listing), and a
// console either obeys that signal or exits with a message saying it cannot do
// what it was asked to do. Both outcomes are visible; neither is silent.
//
// It is per org because orgs are how this fleet is divided — machine names are
// org-prefixed, MACH_ORG/MACH_ORGS define who may be enrolled, and the people
// who own one org are not the people who own the next. A team that wants sealed
// commands should not have to talk another team out of a fleet-wide setting, so
// the choice is theirs to make. A machine's org is the configured prefix its
// name carries; a name whose org cannot be resolved falls back to the default
// rather than borrowing another org's answer.
//
// Resolution order for a command against machine <org>-<name>:
//
//  1. MACH_E2E, when set — the deployment pin. It applies to every org, because
//     a container spec is the natural place to say "this deployment never
//     accepts ciphertext" and a pin there should win over a row someone can
//     change from a shell on the box.
//  2. the stored setting for that org ("e2e:<org>").
//  3. the stored default ("e2e"), for orgs without their own setting.
//  4. on.
//
// On/off, concretely, and what it means for existing agents:
//
//   - ON (the default, and the behaviour of every deployment that never touches
//     this): the control plane relays sealed exec commands and answers /e2epub
//     with the machine's X25519 key. Agents' E2E keys are untouched.
//   - OFF: sealed exec is refused (403, audited, with the reason in the
//     response) and /e2epub advertises no key, so a console obeying the signal
//     never tries to seal. Commands for that org run in plaintext, where the
//     fleet-wide block list can read them.
//
// Nothing on the agent changes in either direction, for either setting. An
// agent keeps its e2e.key, keeps registering its public half at enrollment, and
// keeps opening whatever sealed frame reaches it — with the flag off no sealed
// frame ever does, because the refusal happens at the control plane, before
// dispatch. Turning the flag back on therefore restores sealing immediately: no
// re-enrollment, no agent restart, no key rotation. An agent enrolled while E2E
// was off still has a key registered; nothing is lost by flipping it either
// way, and an agent cannot tell from its side which way it is set.

import (
	"fmt"
	"log"
	"os"
	"sort"
	"strings"

	"github.com/TevaServices/mach/internal/store"
)

const (
	// e2eSettingKey is the default row ("on" / "off"); e2eOrgKey(org) is the
	// per-org override.
	e2eSettingKey = "e2e"

	// e2eEnv overrides every org when set. Values are validated at startup: a
	// typo in a container spec must not be silently ignored, because the
	// operator would have no way to tell an ignored value from an honoured one.
	e2eEnv = "MACH_E2E"

	e2eOn  = "on"
	e2eOff = "off"
)

// e2eOrgKey is the settings row holding one org's override.
func e2eOrgKey(org string) string { return e2eSettingKey + ":" + org }

// modeOf is the operator-facing spelling of the boolean.
func modeOf(on bool) string {
	if on {
		return e2eOn
	}
	return e2eOff
}

// parseE2EFlag accepts the spellings an operator might reasonably write.
func parseE2EFlag(v string) (string, bool) {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "on", "1", "true", "yes", "enable", "enabled":
		return e2eOn, true
	case "off", "0", "false", "no", "disable", "disabled":
		return e2eOff, true
	}
	return "", false
}

// validateE2EEnv fails startup on an unusable MACH_E2E rather than falling back
// to the stored settings, matching how an unreadable MACH_EXEC_POLICY_FILE is
// treated: a control plane running with a different E2E posture than the
// operator believes is worse than one that refuses to start.
func validateE2EEnv() error {
	v := strings.TrimSpace(os.Getenv(e2eEnv))
	if v == "" {
		return nil
	}
	if _, ok := parseE2EFlag(v); !ok {
		return fmt.Errorf("%s=%q is not a valid E2E setting (use on or off)", e2eEnv, v)
	}
	return nil
}

// storedE2E reads one settings row as an on/off value. A row that is absent or
// unusable reports ok=false and the caller moves to the next rule in the order
// documented above.
func storedE2E(st *store.Store, key string) (on bool, ok bool) {
	if st == nil {
		// Only reachable when a Server is built without a store (the IP-limit
		// tests do that): no store, no stored setting.
		return false, false
	}
	v, err := st.Setting(key)
	if err != nil {
		// A store that cannot be read must not silently change the posture; the
		// read failure is logged rather than swallowed so it is not a mystery.
		log.Printf("server: e2e: could not read %q, ignoring it: %v", key, err)
		return false, false
	}
	if v == "" {
		return false, false
	}
	parsed, parseOK := parseE2EFlag(v)
	if !parseOK {
		log.Printf("server: e2e: stored setting %q = %q is not on/off, ignoring it", key, v)
		return false, false
	}
	return parsed == e2eOn, true
}

// resolveE2E is the single place the flag is decided for one org, so the admin
// command cannot report one thing while the server does another. org == ""
// resolves the default (rules 1, 3, 4).
//
// It is read per request rather than cached, so a change takes effect
// immediately, with no restart. The cost is at most two primary-key lookups on
// a path that is already network-bound.
func resolveE2E(st *store.Store, org string) (on bool, source string) {
	if v, ok := parseE2EFlag(os.Getenv(e2eEnv)); ok {
		return v == e2eOn, fmt.Sprintf("%s=%s (applies to every org)", e2eEnv, v)
	}
	if org != "" {
		if on, ok := storedE2E(st, e2eOrgKey(org)); ok {
			return on, fmt.Sprintf("stored setting %q for org %q", modeOf(on), org)
		}
	}
	if on, ok := storedE2E(st, e2eSettingKey); ok {
		return on, "stored default"
	}
	if org == "" {
		return true, fmt.Sprintf("default (no %s, no stored setting)", e2eEnv)
	}
	if org != "" {
		// The org resolved, but nothing is configured for it and there is no
		// default row: the built-in default applies, and the source line says
		// which org it was decided for.
		return true, fmt.Sprintf("default for org %q (nothing stored)", org)
	}
	return true, fmt.Sprintf("default (no %s, no stored setting)", e2eEnv)
}

// E2EState is the control signal a client reads before it decides how to send
// a command: what this control plane will accept for that machine, and why.
type E2EState struct {
	// Enabled is whether sealed exec is accepted for this org.
	Enabled bool `json:"e2e_enabled"`
	// Mode is the same fact in the spelling an operator sees: "on" or "off".
	Mode string `json:"e2e"`
	// Org is the org the answer applies to ("" when it could not be resolved
	// from the machine name, in which case the default governs).
	Org string `json:"e2e_org,omitempty"`
	// Reason explains a refusal in one line, and is empty when enabled.
	Reason string `json:"e2e_reason,omitempty"`
}

// e2eStateForOrg builds the signal for one org ("" = the default).
func (s *Server) e2eStateForOrg(org string) E2EState {
	on, _ := resolveE2E(s.st, org)
	st := E2EState{Enabled: on, Mode: e2eOff, Org: org}
	if on {
		st.Mode = e2eOn
		return st
	}
	where := "this control plane"
	if org != "" {
		where = "org " + org
	}
	st.Reason = fmt.Sprintf("sealed exec is disabled for %s; commands run in plaintext, "+
		"where the fleet-wide block list can read them (turn E2E back on with "+
		"`mach-server e2e on --org %s`)", where, orDefault(org, "<org>"))
	return st
}

func orDefault(v, fallback string) string {
	if v == "" {
		return fallback
	}
	return v
}

// orgOf resolves the org a machine belongs to, by matching the configured
// prefixes longest-first (org labels may themselves contain "-", so the first
// dash is not a safe split). ok is false when no configured org matches: the
// caller then uses the default setting rather than guessing that a machine
// belongs to some other org.
func (s *Server) orgOf(machine string) (string, bool) {
	orgs := s.ListOrgs()
	sort.Slice(orgs, func(i, j int) bool { return len(orgs[i]) > len(orgs[j]) })
	for _, o := range orgs {
		if strings.HasPrefix(machine, o+"-") {
			return o, true
		}
	}
	return "", false
}

// e2eStateFor builds the control signal for a machine: the answer for its org,
// or the default when the org cannot be resolved.
func (s *Server) e2eStateFor(machine string) E2EState {
	org, ok := s.orgOf(machine)
	if !ok {
		return s.e2eStateForOrg("")
	}
	return s.e2eStateForOrg(org)
}

// E2EMode reports the effective setting for one org and where it came from.
// Exported for the admin command, which must print exactly what the server will
// do. org == "" reports the default.
func E2EMode(st *store.Store, org string) (mode, source string) {
	on, source := resolveE2E(st, org)
	val := e2eOff
	if on {
		val = e2eOn
	}
	return val, source
}

// SetE2E stores the setting for one org ("" sets the default). The MACH_E2E
// override, when set, still wins — the admin command says so rather than
// pretending the write took effect.
func SetE2E(st *store.Store, org string, on bool) error {
	val := e2eOff
	if on {
		val = e2eOn
	}
	key := e2eSettingKey
	if org != "" {
		key = e2eOrgKey(org)
	}
	return st.SetSetting(key, val)
}

// ClearE2E drops one org's override so it follows the default again.
func ClearE2E(st *store.Store, org string) error {
	return st.DeleteSetting(e2eOrgKey(org))
}

// StoredE2EOrgs lists orgs with their own stored setting, sorted.
func StoredE2EOrgs(st *store.Store) ([]string, error) {
	all, err := st.Settings()
	if err != nil {
		return nil, err
	}
	var orgs []string
	for k := range all {
		if strings.HasPrefix(k, e2eSettingKey+":") {
			orgs = append(orgs, strings.TrimPrefix(k, e2eSettingKey+":"))
		}
	}
	sort.Strings(orgs)
	return orgs, nil
}
