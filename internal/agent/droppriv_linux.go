//go:build linux

package agent

import (
	"log"
	"os"
	"os/user"
	"strconv"
	"syscall"
)

// DropPrivileges (linux): re-exec context drops to an unprivileged user
// when running as root, unless MACH_KEEP_PRIVILEGES=1. Uses the user in
// MACH_USER (default "nobody").
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
	uid, _ := strconv.Atoi(u.Uid)
	gid, _ := strconv.Atoi(u.Gid)
	if err := syscall.Setgroups([]int{gid}); err != nil {
		return
	}
	if err := syscall.Setgid(gid); err != nil {
		return
	}
	if err := syscall.Setuid(uid); err != nil {
		return
	}
	log.Printf("agent: dropped privileges to %s (uid=%d gid=%d)", target, uid, gid)
}