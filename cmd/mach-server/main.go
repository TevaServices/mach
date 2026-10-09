// Command mach-server — the control plane: public broker/approval service
// and its admin commands. This is the only publicly reachable component
// and ships as a container; it is deliberately separate from the `mach`
// remote-connection binary that runs on target machines and admin boxes.
package main

import (
	"fmt"
	"os"
	"runtime"
	"strings"

	"github.com/TevaServices/mach/internal/controlplane"
	"github.com/TevaServices/mach/internal/version"
)

func main() {
	args := os.Args[1:]
	if len(args) == 0 {
		usage()
		os.Exit(2)
	}
	switch args[0] {
	case "serve":
		controlplane.Serve()
	case "add-api-key":
		// mach-server add-api-key <name> <scopes> [--org ORG]
		// scopes: enroll | readonly | exec:* | exec:m1|m2|...
		// The key secret is generated server-side (192-bit) and printed ONCE.
		// --org binds the key to one tenant; omitted means the primary org.
		if len(args) < 3 {
			fmt.Fprintln(os.Stderr, "usage: mach-server add-api-key <name> <scopes> [--org ORG]\n       scopes: enroll | readonly | exec:* | exec:m1|m2|...")
			os.Exit(2)
		}
		org := ""
		rest := args[3:]
		for i := 0; i < len(rest); i++ {
			switch {
			case rest[i] == "--org" && i+1 < len(rest):
				org = rest[i+1]
				i++
			case strings.HasPrefix(rest[i], "--org="):
				org = strings.TrimPrefix(rest[i], "--org=")
			default:
				fmt.Fprintln(os.Stderr, "usage: mach-server add-api-key <name> <scopes> [--org ORG]")
				os.Exit(2)
			}
		}
		// Printed are the values that were STORED, not the arguments as typed.
		// The secret below is shown once, so this line is the operator's only
		// record of what was minted — and the two can differ, because "admin"
		// is an alias for exec:* and the name is lowercased.
		key, storedName, storedScopes, storedOrg, err := controlplane.AddAPIKey(args[1], args[2], org)
		if err != nil {
			fmt.Fprintln(os.Stderr, "mach-server: "+err.Error())
			os.Exit(1)
		}
		fmt.Printf("api key created: name=%q scopes=%q org=%q\n", storedName, storedScopes, storedOrg)
		fmt.Printf("KEY (shown once, store it now): %s\n", key)
	case "revoke-api-key":
		// mach-server revoke-api-key <name>
		if len(args) < 2 {
			fmt.Fprintln(os.Stderr, "usage: mach-server revoke-api-key <name>")
			os.Exit(2)
		}
		if err := controlplane.RevokeAPIKey(args[1]); err != nil {
			fmt.Fprintln(os.Stderr, "mach-server: "+err.Error())
			os.Exit(1)
		}
	case "e2e":
		// mach-server e2e [on|off|inherit] [--org ORG] — whether this control
		// plane accepts sealed (E2E) exec commands, per org. Reports the
		// effective setting when given no value. Stored in the database;
		// MACH_E2E overrides every org when set.
		set, org := "", ""
		rest := args[1:]
		for i := 0; i < len(rest); i++ {
			switch {
			case rest[i] == "--org" && i+1 < len(rest):
				org = strings.ToLower(strings.TrimSpace(rest[i+1]))
				i++
			case strings.HasPrefix(rest[i], "--org="):
				org = strings.ToLower(strings.TrimSpace(strings.TrimPrefix(rest[i], "--org=")))
			case set == "":
				set = rest[i]
			default:
				fmt.Fprintln(os.Stderr, "usage: mach-server e2e [on|off|inherit] [--org ORG]")
				os.Exit(2)
			}
		}
		if err := controlplane.E2E(set, org); err != nil {
			fmt.Fprintln(os.Stderr, "mach-server: "+err.Error())
			os.Exit(1)
		}
	case "revoke-machine":
		// mach-server revoke-machine <name> [--purge-audit]
		if len(args) < 2 {
			fmt.Fprintln(os.Stderr, "usage: mach-server revoke-machine <name> [--purge-audit]")
			os.Exit(2)
		}
		purge := len(args) > 2 && strings.TrimSpace(args[2]) == "--purge-audit"
		if err := controlplane.RevokeMachine(args[1], purge); err != nil {
			fmt.Fprintln(os.Stderr, "mach-server: "+err.Error())
			os.Exit(1)
		}
	case "delete-machine":
		// mach-server delete-machine <name> [--purge-audit]
		if len(args) < 2 {
			fmt.Fprintln(os.Stderr, "usage: mach-server delete-machine <name> [--purge-audit]")
			os.Exit(2)
		}
		purge := len(args) > 2 && strings.TrimSpace(args[2]) == "--purge-audit"
		if err := controlplane.DeleteMachine(args[1], purge); err != nil {
			fmt.Fprintln(os.Stderr, "mach-server: "+err.Error())
			os.Exit(1)
		}
	case "attest":
		// mach-server attest <agent-binary> <version> [--out FILE]
		if len(args) < 3 {
			fmt.Fprintln(os.Stderr, "usage: mach-server attest <agent-binary> <version> [--out FILE]")
			os.Exit(2)
		}
		out := ""
		if len(args) >= 5 && args[3] == "--out" {
			out = args[4]
		}
		if err := controlplane.Attest(args[1], args[2], out); err != nil {
			fmt.Fprintln(os.Stderr, "mach-server: "+err.Error())
			os.Exit(1)
		}
	case "verify-attestation":
		// mach-server verify-attestation <attestation-file> <agent-binary>
		if len(args) < 3 {
			fmt.Fprintln(os.Stderr, "usage: mach-server verify-attestation <attestation-file> <agent-binary>")
			os.Exit(2)
		}
		if err := controlplane.VerifyAttestation(args[1], args[2]); err != nil {
			fmt.Fprintln(os.Stderr, "mach-server: "+err.Error())
			os.Exit(1)
		}
	case "add-org":
		// mach-server add-org <name> — create a tenant. The UI's org
		// management belongs to the superadmin; the CLI is the bootstrap and
		// the host-shell path for the same power.
		if len(args) != 2 {
			fmt.Fprintln(os.Stderr, "usage: mach-server add-org <name>")
			os.Exit(2)
		}
		if err := controlplane.AddOrg(args[1]); err != nil {
			fmt.Fprintln(os.Stderr, "mach-server: "+err.Error())
			os.Exit(1)
		}
	case "add-member":
		// mach-server add-member [--org ORG] <email> <role>
		// role: superadmin | admin | operator | viewer. The first member of a
		// fresh control plane must be created here: the UI grants nothing to
		// an identity without a membership row.
		org, email, role := "", "", ""
		rest := args[1:]
		var positional []string
		for i := 0; i < len(rest); i++ {
			switch {
			case rest[i] == "--org" && i+1 < len(rest):
				org = rest[i+1]
				i++
			case strings.HasPrefix(rest[i], "--org="):
				org = strings.TrimPrefix(rest[i], "--org=")
			default:
				positional = append(positional, rest[i])
			}
		}
		if len(positional) != 2 {
			fmt.Fprintln(os.Stderr, "usage: mach-server add-member [--org ORG] <email> <role>\n       role: superadmin | admin | operator | viewer")
			os.Exit(2)
		}
		email, role = positional[0], positional[1]
		if err := controlplane.AddMember(org, email, role); err != nil {
			fmt.Fprintln(os.Stderr, "mach-server: "+err.Error())
			os.Exit(1)
		}
	case "remove-member":
		// mach-server remove-member [--org ORG] <email>
		org := ""
		rest := args[1:]
		var positional []string
		for i := 0; i < len(rest); i++ {
			switch {
			case rest[i] == "--org" && i+1 < len(rest):
				org = rest[i+1]
				i++
			case strings.HasPrefix(rest[i], "--org="):
				org = strings.TrimPrefix(rest[i], "--org=")
			default:
				positional = append(positional, rest[i])
			}
		}
		if len(positional) != 1 {
			fmt.Fprintln(os.Stderr, "usage: mach-server remove-member [--org ORG] <email>")
			os.Exit(2)
		}
		if err := controlplane.RemoveMember(org, positional[0]); err != nil {
			fmt.Fprintln(os.Stderr, "mach-server: "+err.Error())
			os.Exit(1)
		}
	case "list-members":
		// mach-server list-members [--org ORG]
		org := ""
		rest := args[1:]
		for i := 0; i < len(rest); i++ {
			switch {
			case rest[i] == "--org" && i+1 < len(rest):
				org = rest[i+1]
				i++
			case strings.HasPrefix(rest[i], "--org="):
				org = strings.TrimPrefix(rest[i], "--org=")
			default:
				fmt.Fprintln(os.Stderr, "usage: mach-server list-members [--org ORG]")
				os.Exit(2)
			}
		}
		if err := controlplane.ListMembers(org); err != nil {
			fmt.Fprintln(os.Stderr, "mach-server: "+err.Error())
			os.Exit(1)
		}
	case "version":
		fmt.Printf("mach-server %s (%s/%s)\n", version.Version, runtime.GOOS, runtime.GOARCH)
	default:
		usage()
		os.Exit(2)
	}
}

func usage() {
	fmt.Fprint(os.Stderr, `mach-server — mach control plane (broker, pairing, audit; the only public component)

  mach-server serve                              run the control plane
                                                 (MACH_DB, MACH_LISTEN, MACH_PUBLIC_URL,
                                                  MACH_ORG=<org prefix>, MACH_TRUST_PROXY=1,
                                                  MACH_E2E=on|off, MACH_EXEC_POLICY/_FILE)
  mach-server e2e [on|off|inherit] [--org ORG]   whether this control plane accepts sealed (E2E)
                                                 exec commands, per org (no --org = the default
                                                 for orgs without their own setting; inherit =
                                                 drop an org's override). Stored in the database;
                                                 MACH_E2E overrides every org when set. Clients
                                                 are told which it is and obey or refuse to run.
  mach-server add-api-key <name> <scopes> [--org ORG]
                                                 create a key: enroll | readonly | exec:* | exec:m1|m2
                                                 (secret generated server-side, printed once;
                                                 --org binds the key to one tenant — omitted
                                                 means the primary org)
  mach-server revoke-api-key <name>              revoke a key: it stops authenticating (row is kept;
                                                 an unknown name errors out)
  mach-server add-org <name>                     create a tenant (the UI's org management belongs
                                                 to a superadmin; this is the bootstrap path)
  mach-server add-member [--org ORG] <email> <role>
                                                 grant a signed-in identity its powers: superadmin
                                                 (every org, plus org management), admin (full
                                                 control of one org), operator (exec + approve),
                                                 viewer (read-only). The FIRST member of a fresh
                                                 control plane must be created here — the UI
                                                 grants nothing to an identity without a row
  mach-server remove-member [--org ORG] <email>  drop one membership binding
  mach-server list-members [--org ORG]           list membership rows
  mach-server revoke-machine <name> [--purge-audit]
                                                 revoke a machine; its agent self-retires
  mach-server delete-machine <name> [--purge-audit]
                                                 delete a machine so its name and agent key can
                                                 be reused (recovery path after revocation)
  mach-server attest <bin> <ver> [--out FILE]     write a signed in-toto attestation for an
                                                 agent binary (default: <bin>.intoto.jsonl);
                                                 records the build's toolchain, flags, module
                                                 graph and VCS revision, read from the binary
  mach-server verify-attestation <att> <bin>     check an attestation against this control
                                                 plane's key AND against the binary's sha256
  mach-server version

Machine names are org-prefixed: <MACH_ORG>-<machine> (unique; conflicts error out).

Releases: attest each agent binary at build time and keep the .intoto.jsonl files
with the artifacts. Agents are updated through their distribution points (the
apt/rpm/apk repositories, winget/Homebrew) — the control plane does not push
agent binaries, and the attestation is what makes the release pipeline and any
later auditor able to check where the bytes came from.
`)
}
