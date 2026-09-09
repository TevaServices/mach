//go:build !linux

package agent

// DropPrivileges is a no-op off Linux: launchd (macOS) and Task Scheduler
// (Windows) already run the agent in the user's own context.
func DropPrivileges() {}