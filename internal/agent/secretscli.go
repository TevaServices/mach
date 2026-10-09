// The on-box CLI for secrets: `mach secrets add|remove|list`.
//
// This is the machine owner's path, distinct from the control plane's push:
// the value is typed here (never accepted on argv, where it would land in
// shell history and `ps`), validated against the same name/value rules, and
// stored in the same <state dir>/secrets.json the agent reads per exec. It
// requires an enrolled machine, and refuses when the enrollment carries no
// org — an agent enrolled before the feature must re-enroll rather than have
// its entries tagged with a guessed org.

package agent

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"strings"

	"golang.org/x/term"
)

// SecretsCommand implements `mach secrets add NAME | remove NAME | list`.
// It returns a process exit code.
func SecretsCommand(args []string) int {
	rest := args[1:]
	if len(rest) == 0 {
		usageSecrets()
		return 2
	}
	stateDir := StateDir()
	cfg, err := LoadConfig(stateDir)
	if err != nil {
		fmt.Fprintln(os.Stderr, "mach: secrets live on an enrolled machine: "+err.Error())
		return 2
	}
	if cfg.Org == "" {
		fmt.Fprintln(os.Stderr, "mach: re-enroll to learn your machine's org (this enrollment predates it; secrets cannot be tagged without it)")
		return 2
	}
	switch rest[0] {
	case "add":
		if len(rest) != 2 {
			usageSecrets()
			return 2
		}
		// Exactly one argument: the NAME. The value is never an argv flag —
		// it is read without echo below — so a value cannot land in shell
		// history or `ps` by way of this command.
		name := rest[1]
		value := readSecretValue(fmt.Sprintf("Value for %s (input hidden): ", name))
		if value == "" {
			fmt.Fprintln(os.Stderr, "mach: no value entered")
			return 2
		}
		if err := AddLocalSecret(stateDir, cfg.Org, name, value); err != nil {
			fmt.Fprintln(os.Stderr, "mach: "+err.Error())
			return 2
		}
		fmt.Printf("stored %s (org %s); it is injected when a command asks for it by name\n", name, cfg.Org)
	case "remove":
		if len(rest) != 2 {
			usageSecrets()
			return 2
		}
		if err := RemoveLocalSecret(stateDir, cfg.Org, rest[1]); err != nil {
			fmt.Fprintln(os.Stderr, "mach: "+err.Error())
			return 2
		}
		fmt.Printf("removed %s\n", rest[1])
	case "list":
		// This path is reached only for `mach secrets list --local`: a plain
		// `mach secrets list` is routed to the control plane's registry
		// before dispatch (cmd/mach), because the plan gives that spelling to
		// the registry and the relayed machine list.
		local := false
		for _, a := range rest[1:] {
			if a == "--local" {
				local = true
			}
		}
		if !local || len(rest) != 2 {
			usageSecrets()
			return 2
		}
		names, err := ListLocalSecrets(stateDir, cfg.Org)
		if err != nil {
			fmt.Fprintln(os.Stderr, "mach: "+err.Error())
			return 2
		}
		fmt.Printf("org %s:\n", cfg.Org)
		if len(names) == 0 {
			fmt.Println("  (no secrets stored)")
			return 0
		}
		for _, name := range names {
			fmt.Println("  " + name)
		}
	default:
		usageSecrets()
		return 2
	}
	return 0
}

func usageSecrets() {
	fmt.Fprintln(os.Stderr, `usage: mach secrets add NAME     store a secret (value read without echo; never pass it on the command line)
       mach secrets remove NAME  remove one
       mach secrets list [--local]
                                 list NAMES only — values are never printed;
                                 --local reads THIS machine's store, the
                                 default asks the control plane's registry
       mach secrets push <machine> NAME --value-file <path|->
                                 seal and push a secret to a machine
                                 (console-API; needs a configured key)`)
}

// readSecretValue reads a secret value without terminal echo when stdin is a
// tty, so it never lands in scrollback or SSH session recording. Falls back
// to a plain read when stdin is piped/redirected — the same shape the
// console's setup wizard uses for API keys. Only the line terminator is
// trimmed: leading/trailing spaces inside a value may be significant.
func readSecretValue(prompt string) string {
	fmt.Print(prompt)
	fd := int(os.Stdin.Fd())
	if term.IsTerminal(fd) {
		b, err := term.ReadPassword(fd)
		fmt.Println()
		if err == nil {
			return string(b)
		}
	}
	line, _ := bufio.NewReader(os.Stdin).ReadString('\n')
	return strings.TrimRight(line, "\r\n")
}

// AddLocalSecret validates and stores a secret from this machine's own CLI,
// tagged with the machine's own org.
func AddLocalSecret(stateDir, org, name, value string) error {
	if org == "" {
		return errors.New("machine has no org; re-enroll")
	}
	return newFileSecretStore(stateDir, org).put(name, value, org)
}

// RemoveLocalSecret removes a stored secret by name.
func RemoveLocalSecret(stateDir, org, name string) error {
	if org == "" {
		return errors.New("machine has no org; re-enroll")
	}
	return newFileSecretStore(stateDir, org).remove(name)
}

// ListLocalSecrets returns the own-org secret NAMES. Values are not a return
// value of this function, which is the point.
func ListLocalSecrets(stateDir, org string) ([]string, error) {
	if org == "" {
		return nil, errors.New("machine has no org; re-enroll")
	}
	return newFileSecretStore(stateDir, org).names()
}
