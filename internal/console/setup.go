package console

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
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
	fmt.Print("API key: ")
	keyLine, _ := rd.ReadString('\n')
	apiKey := strings.TrimSpace(keyLine)
	if apiKey == "" {
		fmt.Fprintln(os.Stderr, "mach: an API key is required (create one with: machctl add-api-key <name> <key>)")
		return 2
	}
	dir := StateDirDefault()
	if err := os.MkdirAll(dir, 0o700); err != nil {
		fmt.Fprintln(os.Stderr, "mach: "+err.Error())
		return 1
	}
	cfgText := fmt.Sprintf(`{"server": %q, "api_key": %q}`+"\n", server, apiKey)
	if err := os.WriteFile(filepath.Join(dir, "console.json"), []byte(cfgText), 0o600); err != nil {
		fmt.Fprintln(os.Stderr, "mach: "+err.Error())
		return 1
	}
	fmt.Printf("Saved to %s — plain `mach` works from now on.\n", filepath.Join(dir, "console.json"))
	return 0
}