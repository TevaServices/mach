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

	"github.com/bcross/mach/internal/controlplane"
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
		// mach-server add-api-key <name> <scopes>
		// scopes: enroll | readonly | exec:* | exec:m1|m2|...
		// The key secret is generated server-side (192-bit) and printed ONCE.
		if len(args) < 3 {
			fmt.Fprintln(os.Stderr, "usage: mach-server add-api-key <name> <scopes>\n       scopes: enroll | readonly | exec:* | exec:m1|m2|...")
			os.Exit(2)
		}
		key, err := controlplane.AddAPIKey(args[1], args[2])
		if err != nil {
			fmt.Fprintln(os.Stderr, "mach-server: "+err.Error())
			os.Exit(1)
		}
		fmt.Printf("api key created: name=%q scopes=%q\n", args[1], args[2])
		fmt.Printf("KEY (shown once, store it now): %s\n", key)
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
	case "push-update":
		// mach-server push-update <machine> <agent-binary-path> <version> [--attestation FILE]
		if len(args) < 4 {
			fmt.Fprintln(os.Stderr, "usage: mach-server push-update <machine> <agent-binary-path> <version> [--attestation FILE]")
			os.Exit(2)
		}
		att := ""
		if len(args) >= 6 && args[4] == "--attestation" {
			att = args[5]
		}
		if err := controlplane.PushUpdate(args[1], args[2], args[3], att); err != nil {
			fmt.Fprintln(os.Stderr, "mach-server: "+err.Error())
			os.Exit(1)
		}
	case "version":
		fmt.Printf("mach-server %s (%s/%s)\n", controlplane.Version, runtime.GOOS, runtime.GOARCH)
	default:
		usage()
		os.Exit(2)
	}
}

func usage() {
	fmt.Fprint(os.Stderr, `mach-server — mach control plane (broker, pairing, audit; the only public component)

  mach-server serve                              run the control plane
                                                 (MACH_DB, MACH_LISTEN, MACH_PUBLIC_URL,
                                                  MACH_ORG=<org prefix>, MACH_TRUST_PROXY=1)
  mach-server add-api-key <name> <scopes>        create a key: enroll | readonly | exec:* | exec:m1|m2
                                                 (secret generated server-side, printed once)
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
  mach-server push-update <machine> <bin> <ver> [--attestation FILE]
                                                 queue a signed agent update for a machine;
                                                 with --attestation the binary must be the one
                                                 that attestation describes, or nothing is sent
  mach-server version

Machine names are org-prefixed: <MACH_ORG>-<machine> (unique; conflicts error out).

Releases: attest each agent binary at build time, keep the .intoto.jsonl files with
the artifacts, and pass --attestation to push-update so no unattested binary can be
shipped. The agent itself does not consume the attestation — what it enforces is the
pinned-key manifest signature over the sha256; the attestation is what makes the
release pipeline and any later auditor able to check where the bytes came from.
`)
}
