//go:build !windows

package agent

import (
	"fmt"
	"os"
)

// serviceMain is Windows-only: the MSI there registers a real Windows service
// whose ImagePath runs `mach service`. Everywhere else the distribution
// packages supervise machd with systemd/launchd/OpenRC wrapping plain
// `mach run`; the SCM dispatcher and its handler exist only where SCM does
// (service_windows.go).
func serviceMain(_ string) {
	fmt.Fprintln(os.Stderr, "mach: service is Windows-only; run `mach run` (the distribution packages supervise it)")
	os.Exit(2)
}
