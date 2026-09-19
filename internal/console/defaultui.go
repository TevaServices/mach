package console

import (
	"fmt"
	"os"
)

// ConsoleDefault is what plain `mach` shows on a configured admin machine:
// the fleet status table, one shot (same output as `mach list`).
func ConsoleDefault() int {
	c, err := DefaultClient()
	if err != nil {
		fmt.Fprintln(os.Stderr, "mach: "+err.Error())
		return 2
	}
	machines, err := c.Machines()
	if err != nil {
		fmt.Fprintln(os.Stderr, "mach: "+err.Error())
		return 3
	}
	fmt.Printf("%-20s %-8s %-10s %-18s %s\n", "NAME", "STATE", "OS", "HOSTNAME", "AGENT")
	if len(machines) == 0 {
		fmt.Println("(no machines enrolled — run `mach` on a target machine to enroll it)")
		return 0
	}
	for _, m := range machines {
		state := "offline"
		if m.Online {
			state = "online"
		}
		ver := m.AgentVer
		if ver == "" {
			ver = "?"
		}
		// Hostname, OS, arch and version are agent-reported: a machine chooses
		// its own hostname, and a hostname can contain an escape sequence. The
		// table is printed to a terminal, so it goes through the same filter the
		// command output does.
		fmt.Printf("%-20s %-8s %-10s %-18s %s\n",
			m.Name, state,
			string(safeForTerminal([]byte(m.OS+"/"+m.Arch), os.Stdout)),
			string(safeForTerminal([]byte(m.Hostname), os.Stdout)),
			string(safeForTerminal([]byte(ver), os.Stdout)))
	}
	return 0
}
