//go:build windows

package agent

import (
	"fmt"
	"os"
	"time"

	"golang.org/x/sys/windows/svc"
)

// ServiceName is the Windows service name the distribution MSI registers.
// It matches the Linux unit names (machd.service, /etc/init.d/machd).
const ServiceName = "machd"

// serviceRun wraps runDaemon for the service, with one Windows-specific
// behavior: an UNENROLLED machine waits for enrollment instead of exiting.
//
// Without it a freshly installed service fails the very thing the MSI does
// at install (msiexec starts the service and requires it to stay up): the
// agent exits 1 — SCM restarts it (the failure actions the package
// configures), producing a restart loop that ends in a 1920 install failure
// (observed: event 7023 "terminated with error: Incorrect function" every
// ~36s until msiexec gave up after four minutes). The Linux packages dodge
// this the other way — they never start machd on an unenrolled host (systemd
// enable-not-start with Restart=on-failure) — but this service is started at
// install AND at boot, so it must be able to sit unenrolled. Waiting is the
// honest shape for that: the service holds RUNNING with no credentials (there
// are none to load), polls the state dir, and serves the moment the operator
// enrolls it — no manual `sc start machd` after enrollment, and a boot with a
// not-yet-enrolled machine is a quiet wait rather than a failure loop.
func serviceRun(stateDir string, ctl *sessionCtl) error {
	for {
		if IsEnrolled(stateDir) {
			break
		}
		if ctl.stopped() {
			return nil
		}
		select {
		case <-ctl.done:
			return nil
		case <-time.After(30 * time.Second):
		}
	}
	return runDaemon(stateDir, ctl)
}

// serviceHandler implements svc.Handler: report RUNNING, then serve the
// agent's daemon loop (the reconnect loop every other mode shares) until the
// service is stopped or a terminal frame ends it.
//
// Exit codes carry the supervision contract the distribution packages share
// (AGENTS.md invariant 22 — restart on failure, never on any exit): an error
// exits 1, so the SCM's failure actions (the `sc failure` step the package
// runs at install) restart it — matching the systemd unit's Restart=on-failure;
// a clean loop end (revoked, deleted, a stop request) exits 0 and stays
// stopped. Once enrolled, re-service starts with `sc start machd`.
type serviceHandler struct {
	stateDir string
	// run is injectable for tests; nil means serviceRun.
	run func(stateDir string, ctl *sessionCtl) error
}

func (h *serviceHandler) Execute(args []string, r <-chan svc.ChangeRequest, status chan<- svc.Status) (bool, uint32) {
	run := h.run
	if run == nil {
		run = serviceRun
	}
	status <- svc.Status{State: svc.StartPending, WaitHint: 30000}

	// Non-tracing ctl: a service has no terminal to announce to. stop() ends
	// the reconnect loop WITHOUT the retire frame — a stopped service is not a
	// retired enrollment (that contrast is why the two stop paths exist).
	ctl := &sessionCtl{done: make(chan struct{})}
	done := make(chan error, 1)
	go func() { done <- run(h.stateDir, ctl) }()
	status <- svc.Status{State: svc.Running, Accepts: svc.AcceptStop | svc.AcceptShutdown}

	for {
		select {
		case err := <-done:
			if err != nil {
				return false, 1
			}
			return false, 0
		case c := <-r:
			switch c.Cmd {
			case svc.Interrogate:
				status <- c.CurrentStatus
			case svc.Stop, svc.Shutdown:
				// Acknowledge the stop (SCM refuses/keeps the service otherwise)
				// and let the loop end itself: the socket closes, the read
				// unblocks, serveLoop exits. A command already running is not
				// cancelled — the same rule the console teardown has.
				status <- svc.Status{State: svc.StopPending, WaitHint: 30000}
				ctl.stop()
			}
		}
	}
}

// serviceMain is the `mach service` entry point, and only reaches here
// meaningfully when the SCM started the process. Anything else (a shell) is
// refused with a pointer at the command it wanted, because silently becoming
// the daemon would be the second way to start a two-identity host.
func serviceMain(stateDir string) {
	in, err := svc.IsWindowsService()
	if err != nil || !in {
		fmt.Fprintln(os.Stderr, "mach: service is the Windows service entry point and is started by the SCM")
		fmt.Fprintln(os.Stderr, "     run `mach run` for the interactive daemon")
		os.Exit(2)
	}
	if err := svc.Run(ServiceName, &serviceHandler{stateDir: stateDir}); err != nil {
		fmt.Fprintln(os.Stderr, "mach: service: "+err.Error())
		os.Exit(1)
	}
}
