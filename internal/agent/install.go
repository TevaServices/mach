package agent

import (
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
)

// Install registers the agent as an OS service for the long-running mode:
//   - linux:  systemd unit /etc/systemd/system/machd.service (enable + start)
//   - darwin: launchd plist ~/Library/LaunchAgents/com.bcross.mach.plist
//   - windows: Task Scheduler job "machd", runs at logon, restarts daily
//
// The supervisor restarts the agent on FAILURE, not on any exit: exit 0 means
// stop. A clean exit is how the agent reports that the control plane retired it
// — revoked, or deleted — and a supervisor that restarts it anyway turns a
// deliberate retirement into a restart loop. It also races the update path,
// which starts its own detached replacement and then exits 0; under
// Restart=always the supervisor would resurrect the old image alongside it.
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
		return installSystemd(cfg.Name, exe, stateDir)
	}
}

// dropUser is the account the agent drops to when installed as root.
func dropUser() string {
	if v := os.Getenv("MACH_USER"); v != "" {
		return v
	}
	return "nobody"
}

// chownTree hands the state directory (and everything in it) to the
// unprivileged account the service will run as, so a root-performed
// enrollment stays readable by the dropped agent.
func chownTree(root, username string) error {
	u, err := user.Lookup(username)
	if err != nil {
		return err
	}
	uid, err := strconv.Atoi(u.Uid)
	if err != nil {
		return err
	}
	gid, err := strconv.Atoi(u.Gid)
	if err != nil {
		return err
	}
	return filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		return os.Chown(path, uid, gid)
	})
}

// ---- linux: systemd ----

func installSystemd(name, exe, stateDir string) error {
	// Run the service directly as the unprivileged account (User=) rather
	// than letting the process drop: the state dir, env, and permissions
	// then match what the agent needs, and `mach run` under the unit is
	// identical to the manual case.
	runAs := dropUser()
	envLine := "Environment=MACH_STATE_DIR=" + stateDir + "\n"
	userLine := ""
	if os.Geteuid() == 0 {
		if _, err := user.Lookup(runAs); err == nil {
			userLine = "User=" + runAs + "\n"
			envLine += "Environment=MACH_KEEP_PRIVILEGES=1\n" // no double-drop
			if err := chownTree(stateDir, runAs); err != nil {
				return fmt.Errorf("chowning state dir %s to %s: %v", stateDir, runAs, err)
			}
		} else {
			// No such user: keep the root-run unit (droppriv is best-effort).
			runAs = "root"
		}
	}
	unit := systemdUnit(name, userLine, envLine, exe)

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
	fmt.Printf("Installed and started the mach agent service (machine %q, running as %s). It reconnects automatically after reboots and network loss.\n", name, runAs)
	return nil
}

// ---- macOS: launchd ----

func installLaunchd(name, exe, stateDir string) error {
	home, _ := os.UserHomeDir()
	plistDir := filepath.Join(home, "Library", "LaunchAgents")
	plistPath := filepath.Join(plistDir, "com.bcross.mach.plist")
	logPath := filepath.Join(stateDir, "machd.log")

	plist := launchdPlist(exe, logPath)

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
	fmt.Printf("Installed and loaded LaunchAgent %s (machine %q). It starts at login and is restarted if it crashes; a clean exit (the control plane retiring this machine) is left alone.\n", label, name)
	fmt.Printf("Note: for a headless Mac that runs before login, also run: sudo launchctl bootstrap system %s\n", plistPath)
	return nil
}

// xmlEscape makes a string safe for element text / attribute values in the
// plist (paths with & < > " ' would otherwise corrupt the XML).
func xmlEscape(s string) string {
	r := strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;", `"`, "&quot;", "'", "&apos;")
	return r.Replace(s)
}

// systemdUnit renders the Linux unit file.
//
// Split out of Install so the supervisor semantics are assertable without root
// and without a systemd running: Restart=on-failure is a correctness property —
// it is what makes a clean exit mean "stop" — and a property that only shows up
// on a machine you are trying to retire is one worth pinning in a test.
func systemdUnit(name, userLine, envLine, exe string) string {
	return fmt.Sprintf(`[Unit]
Description=mach agent (%s)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
%s%sExecStart="%s" run
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
`, name, userLine, envLine, exe)
}

// launchdPlist renders the macOS LaunchAgent.
//
// KeepAlive is SuccessfulExit=false rather than true, for the same reason the
// unit says on-failure: exit 0 means stop. KeepAlive <true/> restarts a retired
// agent forever, and races the update path, which starts its own detached
// replacement and then exits 0.
func launchdPlist(exe, logPath string) string {
	return fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
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
  <key>KeepAlive</key>
  <dict><key>SuccessfulExit</key><false/></dict>
  <key>StandardOutPath</key><string>%s</string>
  <key>StandardErrorPath</key><string>%s</string>
</dict>
</plist>
`, xmlEscape(exe), xmlEscape(logPath), xmlEscape(logPath))
}

// ---- Windows: Task Scheduler ----

func installWindows(name, exe string) error {
	// Runs at logon; task restarts daily and on failure after 1 minute.
	// /TR receives a command-line string: the executable must be wrapped in
	// quotes so paths with spaces parse (single quotes are NOT valid for
	// schtasks). We pass argv directly — no cmd /c, so no double parsing.
	if out, err := runCmd("schtasks", "/Create", "/F", "/TN", "machd", "/SC", "ONLOGON", "/RL", "HIGHEST", "/TR", `"`+exe+`" run`); err != nil {
		return fmt.Errorf("schtasks: %v: %s", err, out)
	}
	if out, err := runCmd("schtasks", "/Change", "/TN", "machd", "/RI", "1"); err != nil {
		_ = out // restart interval best-effort
	}
	fmt.Printf("Installed Task Scheduler job %q (machine %q): starts at logon, restarts on failure.\n", "machd", name)
	return nil
}
