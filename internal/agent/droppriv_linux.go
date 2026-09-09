//go:build linux

package agent

import (
	"log"
	"os"
	"os/user"
	"strconv"
	"syscall"
)

// DropPrivileges (linux): the agent drops to an unprivileged user when
// running as root, unless MACH_KEEP_PRIVILEGES=1. Uses the user in
// MACH_USER (default "nobody"). Call only AFTER state files are loaded —
// a dropped process can no longer read root-owned state.
func DropPrivileges() {
	if os.Geteuid() != 0 || os.Getenv("MACH_KEEP_PRIVILEGES") == "1" {
		return
	}
	target := os.Getenv("MACH_USER")
	if target == "" {
		target = "nobody"
	}
	u, err := user.Lookup(target)
	if err != nil {
		return // no such user; run as-is (best-effort)
	}
	uid, err := strconv.Atoi(u.Uid)
	if err != nil {
		return
	}
	gid, err := strconv.Atoi(u.Gid)
	if err != nil {
		return
	}
	// Order matters: credentials can be set while still root; after setuid
	// nothing below root level can change them again.
	if err := syscall.Setgid(gid); err != nil {
		return
	}
	if err := syscall.Setgroups([]int{gid}); err != nil {
		return
	}
	if err := syscall.Setuid(uid); err != nil {
		return
	}
	log.Printf("agent: dropped privileges to %s (uid=%d gid=%d)", target, uid, gid)
}
