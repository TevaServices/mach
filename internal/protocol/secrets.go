package protocol

import (
	"errors"
	"fmt"
	"strings"
)

// Secrets: names travel, values never do.
//
// A secret's VALUE lives only on the target machine, in each agent's local
// store (internal/agent: <state dir>/secrets.json, mode 0600). Only NAMES ever
// cross any wire. The control plane may learn which names a machine holds and
// the org they were provisioned under — never a value: it relays a push as an
// opaque sealed blob, lists and announcements carry names alone, and a result
// frame carries only a name and an ok/error status. Injection is resolved by
// the agent at exec time from the names in ExecCommand.InjectEnv /
// StreamStart.InjectEnv, and every byte the agent sends back is scrubbed
// against the union of its locally stored values. That scrubbing is
// best-effort: a value echoed back hex- or base64-encoded, or transformed, is
// not caught — see internal/agent/secrets.go for the stated limits.
//
// Frame tags are raw literals in this package (there is no enum), so each is
// spelled the same at every site:
//
//	secret_push           control plane → agent: SealedSecretPush. The
//	                      SecretPayload travels INSIDE the sealed envelope, so
//	                      even the control plane relaying it cannot read the
//	                      value it is delivering.
//	secret_push_result    agent → control plane: SecretPushResult.
//	secret_list           control plane → agent (no payload).
//	secret_list_result    agent → control plane: SecretListResult — names only.
//	secrets_announce      agent → control plane: SecretsAnnounce — names only,
//	                      sent at connect and after a successful push.
//	secrets_announce_ack  control plane → agent: SecretsAnnounceAck.

// SecretPayload is the JSON sealed inside a secret_push envelope. It is the
// only structure in this file that carries a value, and it never travels
// unsealed: the control plane wraps it in e2e.Seal to the machine's key and
// relays SealedSecretPush opaque.
type SecretPayload struct {
	Name      string `json:"name"`
	Org       string `json:"org"`
	Value     string `json:"value"`
	CreatedAt string `json:"created_at,omitempty"`
}

// SealedSecretPush is the agent-visible shape of a secret_push frame: an
// opaque sealed blob plus the sender's ephemeral public key, mirroring
// SealedExecCommand. The control plane relays it blind — it cannot read the
// value it is pushing.
//
// ReplyPub is shape symmetry with SealedExecCommand, carried for the sender's
// ephemeral key; the agent does not use it, because a secret_push_result
// carries no value (name and status only) and so travels unsealed.
type SealedSecretPush struct {
	SealedB64 string `json:"sealed_b64"`
	ReplyPub  string `json:"reply_pub,omitempty"`
}

// SecretPushResult is the agent's reply to a secret_push. Name and status
// only — never a value, and an Error that must never quote one either.
type SecretPushResult struct {
	Name  string `json:"name"`
	OK    bool   `json:"ok"`
	Error string `json:"error,omitempty"`
}

// SecretListResult is the answer to a secret_list: the org and the NAMES the
// machine holds for it. Values are not a field of this structure, which is
// the strongest form of that statement the wire can make.
type SecretListResult struct {
	Org   string   `json:"org"`
	Names []string `json:"names"`
}

// SecretsAnnounce is sent by the agent at connect and after a successful
// push, so the control plane knows which names this machine holds without
// having to poll. Names only, ever.
type SecretsAnnounce struct {
	Org   string   `json:"org"`
	Names []string `json:"names"`
}

// SecretsAnnounceAck is the control plane's reply to an announce: how many
// names it recorded. A count, and nothing else — there is nothing else to say.
type SecretsAnnounceAck struct {
	Count int `json:"count"`
}

// ValidSecretName enforces the grammar and the reserved list for a secret
// NAME, in one place — the wire package — because names cross every wire
// (pushes, lists, announcements, injection requests) and both ends must
// refuse the same things. A secret name becomes an environment variable, so
// it must be a legal identifier, and it must not collide with the variables
// that decide where a command runs: MACH_* (the agent's own control
// variables), PATH (a secret named PATH is not a guard, it is a hijack), and
// LD_*/DYLD_* (the dynamic loader's namespace).
func ValidSecretName(name string) error {
	if name == "" {
		return errors.New("secret name is empty")
	}
	if name == "PATH" {
		return errors.New("secret name PATH is reserved")
	}
	for _, p := range []string{"MACH_", "LD_", "DYLD_"} {
		if strings.HasPrefix(name, p) {
			return fmt.Errorf("secret names starting %q are reserved", p)
		}
	}
	for i, r := range name {
		switch {
		case r == '_' || r >= 'A' && r <= 'Z':
		case i > 0 && r >= '0' && r <= '9':
		default:
			return fmt.Errorf("secret name %q must match [A-Z_][A-Z0-9_]*", name)
		}
	}
	return nil
}
