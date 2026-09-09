package console

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"

	"golang.org/x/term"
)

// LocalExec executes a line in the local default shell (console `:!` escape).
func LocalExec(cmdline string) int {
	var c *exec.Cmd
	switch runtime.GOOS {
	case "windows":
		c = exec.Command("powershell", "-NoProfile", "-NonInteractive", "-Command", cmdline)
	default:
		c = exec.Command("sh", "-c", cmdline)
	}
	c.Stdout = os.Stdout
	c.Stderr = os.Stderr
	fmt.Printf("(local) $ %s\n", cmdline)
	if err := c.Run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	return 0
}

// readSecret reads an API key without terminal echo when stdin is a tty
// (so the bearer key never lands in scrollback or SSH session recording).
// Falls back to a plain read when stdin is piped/redirected.
func readSecret(prompt string) string {
	fmt.Print(prompt)
	fd := int(os.Stdin.Fd())
	if term.IsTerminal(fd) {
		b, err := term.ReadPassword(fd)
		fmt.Println()
		if err == nil {
			return strings.TrimSpace(string(b))
		}
	}
	line, _ := bufio.NewReader(os.Stdin).ReadString('\n')
	return strings.TrimSpace(line)
}

// FirstRunWizard walks a brand-new admin machine through console setup:
// control plane URL + API key, stored so plain `mach` works forever after.
func FirstRunWizard() int {
	rd := bufio.NewReader(os.Stdin)
	def := os.Getenv("MACH_SERVER")
	fmt.Println("mach console setup (one time)")
	fmt.Print("Control plane URL")
	if def != "" {
		fmt.Printf(" [%s]", def)
	}
	fmt.Print(": ")
	line, _ := rd.ReadString('\n')
	server := strings.TrimSpace(line)
	if server == "" {
		server = def
	}
	if server == "" {
		fmt.Fprintln(os.Stderr, "mach: a control plane URL is required (set MACH_SERVER to skip the prompt)")
		return 2
	}
	apiKey := readSecret("API key (input hidden): ")
	if apiKey == "" {
		fmt.Fprintln(os.Stderr, "mach: an API key is required (create one with: mach-server add-api-key <name> <scopes>)")
		return 2
	}
	dir := StateDirDefault()
	if err := os.MkdirAll(dir, 0o700); err != nil {
		fmt.Fprintln(os.Stderr, "mach: "+err.Error())
		return 1
	}
	cfgPath := filepath.Join(dir, "console.json")
	cfgText := fmt.Sprintf(`{"server": %q, "api_key": %q}`+"\n", server, apiKey)
	if err := os.WriteFile(cfgPath, []byte(cfgText), 0o600); err != nil {
		fmt.Fprintln(os.Stderr, "mach: "+err.Error())
		return 1
	}
	// A pre-existing console.json may carry looser permissions from an
	// earlier version; enforce 0600 on every save.
	_ = os.Chmod(cfgPath, 0o600)
	fmt.Printf("Saved to %s (0600) — plain `mach` works from now on.\n", cfgPath)
	return 0
}
