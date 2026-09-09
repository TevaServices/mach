package agent

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// Install writes the systemd unit and enables the long-running service.
// This is the "long term, named access to a site" mode.
func Install(stateDir string) error {
	cfg, err := LoadConfig(stateDir)
	if err != nil {
		return err
	}
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	exe, err = filepath.Abs(exe)
	if err != nil {
		return err
	}

	unit := fmt.Sprintf(`[Unit]
Description=mach agent (%s)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=%s run
StateDirectory=mach
Restart=always
RestartSec=5
# Hardening: the agent only needs to exec commands and make outbound calls.
NoNewPrivileges=no
DynamicUser=no

[Install]
WantedBy=multi-user.target
`, cfg.Name, exe)

	unitPath := "/etc/systemd/system/machd.service"
	if err := os.WriteFile(unitPath, []byte(unit), 0o644); err != nil {
		return fmt.Errorf("writing %s (are you root?): %w", unitPath, err)
	}
	for _, args := range [][]string{
		{"systemctl", "daemon-reload"},
		{"systemctl", "enable", "--now", "machd.service"},
	} {
		cmd := exec.Command(args[0], args[1:]...)
		out, err := cmd.CombinedOutput()
		if err != nil {
			return fmt.Errorf("%s: %v: %s", strings.Join(args, " "), err, out)
		}
	}
	fmt.Printf("Installed and started machd.service (machine %q). It will reconnect automatically after reboots and network loss.\n", cfg.Name)
	return nil
}