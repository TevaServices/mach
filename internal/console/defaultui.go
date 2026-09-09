package console

import (
	"fmt"
	"os"
	"time"
)

// ConsoleDefault is what plain `mach` shows on a configured admin machine:
// the fleet at a glance, refreshing every 5 seconds until Ctrl-C.
func ConsoleDefault() int {
	tick := time.NewTicker(5 * time.Second)
	defer tick.Stop()

	for {
		machines, err := DefaultClient().Machines()
		if err != nil {
			fmt.Fprintln(os.Stderr, "\nmach: "+err.Error())
			return 3
		}
		fmt.Print("\033[H\033[2J") // clear screen
		fmt.Println("mach — fleet status (Ctrl-C to exit; `mach exec <m> <cmd>` to act)")
		fmt.Printf("%-20s %-8s %-10s %-18s %-12s %s\n", "NAME", "STATE", "OS", "HOSTNAME", "AGENT", "ENROLLED")
		if len(machines) == 0 {
			fmt.Println("(no machines enrolled — run `mach` on a target machine to enroll it)")
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
			fmt.Printf("%-20s %-8s %-10s %-18s %-12s %s\n", m.Name, state, m.OS+"/"+m.Arch, m.Hostname, ver, m.CreatedAt[:10])
		}
		select {
		case <-tick.C:
		}
	}
}