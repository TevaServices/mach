//go:build windows

package agent

import (
	"errors"
	"testing"
	"time"

	"golang.org/x/sys/windows/svc"
)

// The service handler's contract with the SCM. RUNNING must be prompt — SCM
// 1053s a slow start, and the MSI's StartServices waits only briefly — and it
// must accept Stop and Shutdown. An SCM stop (or system shutdown) ends with
// exit 0: a stopped service is not a service failure, so the failure actions
// the package configures do not restart it (invariant 22 — a stop is not a
// failure to be restarted, and a revoked machine must stay retired). A run
// loop that ends on its own with an error is a FAILURE (exit 1): that is the
// restart-on-failure the `sc failure` step exists for.
//
// The SCM's own Stopped status is set by the dispatcher after Execute
// returns, so these tests run Execute directly, the way svc.Run does.

func TestServiceHandlerRunsAndStopsCleanly(t *testing.T) {
	h := &serviceHandler{
		run: func(_ string, ctl *sessionCtl) error {
			<-ctl.done // hold RUNNING until the SCM asks to stop
			return nil
		},
	}
	changes := make(chan svc.ChangeRequest, 4)
	status := make(chan svc.Status, 8)
	done := make(chan bool, 1)
	go func() {
		_, exit := h.Execute([]string{}, changes, status)
		done <- exit == 0
	}()

	// Promptly RUNNING, accepting the stop controls a stop request needs.
	var running svc.Status
	for {
		running = <-status
		if running.State == svc.Running {
			break
		}
	}
	if running.Accepts&(svc.AcceptStop|svc.AcceptShutdown) == 0 {
		t.Errorf("RUNNING accepts %d, want Stop|Shutdown — an SCM stop would be refused", running.Accepts)
	}

	// The stop must be acknowledged with StopPending (SCM kills a service that
	// ignores the request) and end cleanly.
	changes <- svc.ChangeRequest{Cmd: svc.Stop}
	sawPending := false
	for {
		select {
		case s := <-status:
			if s.State == svc.StopPending {
				sawPending = true
			}
		case ok := <-done:
			if !ok {
				t.Fatal("an SCM stop ended the service with a nonzero exit — the failure actions would restart it")
			}
			if !sawPending {
				t.Error("no StopPending was reported before the stop completed")
			}
			return
		case <-time.After(5 * time.Second):
			t.Fatal("the handler did not return after a stop request")
		}
	}
}

func TestServiceHandlerReportsAFailingLoopAsFailure(t *testing.T) {
	h := &serviceHandler{
		run: func(_ string, _ *sessionCtl) error {
			return errors.New("config unreadable")
		},
	}
	status := make(chan svc.Status, 8)
	res := make(chan bool, 1)
	go func() {
		_, exit := h.Execute([]string{}, make(chan svc.ChangeRequest), status)
		res <- exit != 0
	}()
	// Drain whatever statuses arrived; the exit code is the assertion.
	for {
		select {
		case s := <-status:
			_ = s
		case ok := <-res:
			if !ok {
				t.Fatal("a failing daemon loop exited 0 — the SCM would not restart it even though the package configures restart-on-failure")
			}
			return
		case <-time.After(5 * time.Second):
			t.Fatal("the handler did not return for a failing run loop")
		}
	}
}

// serviceRun must WAIT for enrollment on an unenrolled machine — not exit.
// That wait is what keeps the freshly installed service startable (the MSI's
// StartServices requires a service that stays up) and keeps a boot on a
// not-yet-enrolled machine quiet. A stop must end the wait at once, cleanly
// (a stop is not failure — the failure actions must not restart a service the
// operator just stopped).
func TestServiceRunWaitsForEnrollmentAndStopsCleanly(t *testing.T) {
	if IsEnrolled(t.TempDir()) {
		t.Fatal("an empty state dir reported enrolled")
	}
	ctl := &sessionCtl{done: make(chan struct{})}
	done := make(chan error, 1)
	go func() { done <- serviceRun(t.TempDir(), ctl) }()
	time.Sleep(100 * time.Millisecond) // inside the 30s poll select
	close(ctl.done)
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("the waiting service ended with an error: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("a stop did not interrupt the enrollment wait")
	}
}
