package console

import (
	"fmt"
	"os"
)

// ConsoleDefault is what plain `mach` shows on a configured admin machine:
// the fleet status table, one shot (same output as `mach list`).
func ConsoleDefault() int {
	machines, err := DefaultClient().Machines()
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
		fmt.Printf("%-20s %-8s %-10s %-18s %s\n", m.Name, state, m.OS+"/"+m.Arch, m.Hostname, ver)
	}
	return 0
}