package main

// The social-engineering foot-guard for the temporary session (#23).
//
// Bare `mach` on a fresh host enrolls it — grants a standing, remotely
// command-executing identity to whoever holds the control plane — and it does
// so after two prompts that read like ordinary setup. An attacker talks a
// victim through exactly those prompts ("just paste this and press enter").
// The warning below sits FIRST, before anything about servers or orgs, and
// requires a conscious ENTER: it names what is about to happen and who the
// decision should belong to. It is deliberately not skippable by a flag: a
// script that could bypass it is exactly the instruction an attacker would
// recite. (mach register / mach install stay prompt-free — headless paths.)
//
// EOF aborts as well: a closed terminal is not a confirmation.

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
)

// bootStdin is ONE reader for the whole boot (guard + prompts): every
// bufio.Reader buffers what follows the line it answers, so separate readers
// swallow each other's input — the guard's ENTER, then the URL and org
// prompts, all come off this one buffer in order.
var bootStdin = bufio.NewReader(os.Stdin)

// readLineErr reads one line off bootStdin without the trailing newline.
func readLineErr() (string, error) {
	line, err := bootStdin.ReadString('\n')
	if err != nil {
		return "", err
	}
	return strings.TrimSuffix(line, "\n"), nil
}

// readLine is readLineErr for the prompts, which treat EOF as empty.
func readLine() string {
	s, _ := readLineErr()
	return strings.TrimSpace(s)
}

const confirmText = `WARNING: This command will enroll this machine as a temporary target.
ONLY continue if the person asking you to run this is someone you
personally know and trust.

Press ENTER to continue, or Ctrl-C to abort. `

// confirmTrustedOrigin prints the warning and blocks until the operator
// presses ENTER. Anything else — EOF, or a typed word — aborts the session
// before it asks for a control plane or enrolls anything.
func confirmTrustedOrigin(w io.Writer) error {
	fmt.Fprint(w, confirmText)
	// stdinReaders is ONE bufio.Reader for the whole boot: promptServer and
	// promptOrg used to build their own, and a reader buffers what follows its
	// line — the first swallowed the next prompt's answer whole. One shared
	// reader for guard + prompts; every consumer reads from the same buffer.
	line, err := readLineErr()
	if err != nil {
		// EOF (or a closed terminal) is not a confirmation.
		return errors.New("aborted at the warning (no confirmation given) — nothing was enrolled")
	}
	if line != "" {
		// A typed answer is treated as a refusal: the prompt asked for ENTER.
		return errors.New("aborted: you did not confirm with ENTER — nothing was enrolled")
	}
	return nil
}
