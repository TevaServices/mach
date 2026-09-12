package agent

// terminalFrame decides which frames stop the reconnect loop for good. Getting
// this wrong is not a cosmetic bug: a frame that fails to stop the loop leaves an
// agent dialing a name the control plane no longer knows, forever, while the
// operator believes the machine is retired.

import (
	"errors"
	"testing"
)

func TestTerminalFrameMapping(t *testing.T) {
	cases := []struct {
		frame string
		want  error
	}{
		// Both terminal frames mean "do not dial this name again".
		{"revoked", errRevoked},
		{"deleted", errDeleted},
		// Everything else must keep the loop alive. A false positive here would
		// silently retire a healthy machine.
		{"pong", nil},
		{"exec", nil},
		{"exec_stream", nil},
		{"stream_stdin", nil},
		{"policy", nil},
		{"update", nil},
		{"hello", nil},
		{"hello_result", nil},
		{"", nil},
		{"nonsense", nil},
	}
	for _, c := range cases {
		if got := terminalFrame(c.frame); !errors.Is(got, c.want) {
			t.Errorf("terminalFrame(%q) = %v, want %v", c.frame, got, c.want)
		}
	}
}

// The two terminal frames must stay distinguishable. Collapsing them would make
// the log line an operator reads after a deletion claim the machine was revoked,
// which sends them looking for a tombstone that does not exist.
func TestTerminalFramesAreDistinct(t *testing.T) {
	if errors.Is(errDeleted, errRevoked) {
		t.Fatal("errDeleted and errRevoked are the same error; the log line would be wrong")
	}
}
