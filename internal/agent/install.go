package agent

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

// Install registers the agent as an OS service for the long-running mode:
//   - linux:  systemd unit /etc/systemd/system/machd.service (enable + start)
//   - darwin: launchd plist ~/Library/LaunchAgents/com.bcross.mach.plist
//   - windows: Task Scheduler job "machd", runs at logon, restarts daily
//
// Best-effort on unsupported setups: returns guidance instead of failing hard.
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

	switch runtime.GOOS {
	case "darwin":
		return installLaunchd(cfg.Name, exe, stateDir)
	case "windows":
		return installWindows(cfg.Name, exe)
	default:
		return installSystemd(cfg.Name, exe)
	}
}

// ---- linux: systemd ----

func installSystemd(name, exe string) error {
	unit := fmt.Sprintf(`[Unit]
Description=mach agent (%s)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=%s run
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
`, name, exe)

	unitPath := "/etc/systemd/system/machd.service"
	if err := os.WriteFile(unitPath, []byte(unit), 0o644); err != nil {
		return fmt.Errorf("writing %s (need root — run: sudo mach install): %w", unitPath, err)
	}
	if _, err := os.Stat("/run/systemd/system"); err != nil {
		return fmt.Errorf("systemd not running; the agent works fine with `mach run` under your own supervisor")
	}
	for _, args := range [][]string{
		{"systemctl", "daemon-reload"},
		{"systemctl", "enable", "--now", "machd.service"},
	} {
		out, err := runCmd(args[0], args[1:]...)
		if err != nil {
			return fmt.Errorf("%s: %v: %s", strings.Join(args, " "), err, out)
		}
	}
	fmt.Printf("Installed and started machd.service (machine %q). It reconnects automatically after reboots and network loss.\n", name)
	return nil
}

// ---- macOS: launchd ----

func installLaunchd(name, exe, stateDir string) error {
	home, _ := os.UserHomeDir()
	plistDir := filepath.Join(home, "Library", "LaunchAgents")
	plistPath := filepath.Join(plistDir, "com.bcross.mach.plist")
	logPath := filepath.Join(stateDir, "machd.log")

	plist := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>com.bcross.mach</string>
  <key>ProgramArguments</key>
  <array>
    <string>%s</string>
    <string>run</string>
  </array>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><true/>
  <key>StandardOutPath</key><string>%s</string>
  <key>StandardErrorPath</key><string>%s</string>
</dict>
</plist>
`, exe, logPath, logPath)

	if err := os.MkdirAll(plistDir, 0o755); err != nil {
		return err
	}
	if err := os.WriteFile(plistPath, []byte(plist), 0o644); err != nil {
		return err
	}
	label := "com.bcross.mach"
	_, _ = runCmd("launchctl", "unload", plistPath) // idempotent re-install
	if out, err := runCmd("launchctl", "load", plistPath); err != nil {
		return fmt.Errorf("launchctl load: %v: %s", err, out)
	}
	fmt.Printf("Installed and loaded LaunchAgent %s (machine %q). It starts at login and keeps running (KeepAlive).\n", label, name)
	fmt.Printf("Note: for a headless Mac that runs before login, also run: sudo launchctl bootstrap system %s\n", plistPath)
	return nil
}

// ---- Windows: Task Scheduler ----

func installWindows(name, exe string) error {
	// Runs at logon; task restarts daily and on failure after 1 minute.
	sched := fmt.Sprintf(`schtasks /Create /F /TN "machd" /SC ONLOGON /RL HIGHEST /TR "'%s' run"`, exe)
	if out, err := runCmd("cmd", "/c", sched); err != nil {
		return fmt.Errorf("schtasks: %v: %s", err, out)
	}
	if out, err := runCmd("cmd", "/c", `schtasks /Change /TN "machd" /RI 1`); err != nil {
		_ = out // restart interval best-effort
	}
	fmt.Printf("Installed Task Scheduler job %q (machine %q): starts at logon, restarts on failure.\n", "machd", name)
	return nil
}