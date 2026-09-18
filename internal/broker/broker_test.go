package broker

import (
	"testing"

	"github.com/TevaServices/mach/internal/protocol"
)

// A full console buffer may drop output, but it must not drop the terminal
// record. stream_end is how the console learns the exit status and how the relay
// learns it should write an audit row with a real code rather than "unknown": a
// console that never receives one hangs forever, because it sets no read
// deadline and the relay's pings keep the socket healthy regardless.
//
// The console client's own test covers the receiving half (a stream that ends
// without a terminal record is reported, not read as success). This is the
// sending half: the frame has to survive a backlog.
func TestSendToStreamNeverDropsTheTerminalFrame(t *testing.T) {
	b := New()
	const session = "sess-1"
	ch := make(chan protocol.Envelope, 4)
	b.BindStream(session, ch, "bcross-a")

	// Fill the buffer with output chunks, as an agent outpacing its console does.
	for i := 0; i < 4; i++ {
		b.SendToStream(session, protocol.Envelope{Type: "stream_out"})
	}
	if len(ch) != 4 {
		t.Fatalf("buffer holds %d frames, want it full at 4", len(ch))
	}

	// The terminal record arrives with no room. It must displace an output chunk,
	// not be dropped.
	b.SendToStream(session, protocol.Envelope{Type: "stream_end", ReqID: session})

	sawEnd := false
	for len(ch) > 0 {
		env := <-ch
		if env.Type == "stream_end" {
			sawEnd = true
		}
	}
	if !sawEnd {
		t.Fatal("the terminal frame was dropped — the console would hang with no exit status")
	}
	if len(ch) != 0 {
		t.Errorf("%d frames left after draining", len(ch))
	}
}

// The negative control: output chunks are still dropped when the buffer is full,
// which is what keeps a console that stopped reading from stalling the agent pump
// for every other command on the connection.
func TestSendToStreamStillDropsOutputWhenFull(t *testing.T) {
	b := New()
	const session = "sess-2"
	ch := make(chan protocol.Envelope, 2)
	b.BindStream(session, ch, "bcross-a")

	for i := 0; i < 10; i++ {
		b.SendToStream(session, protocol.Envelope{Type: "stream_out"})
	}
	if len(ch) != 2 {
		t.Fatalf("buffer holds %d frames, want it bounded at 2", len(ch))
	}
	// A terminal frame then gets through, and only one output chunk was evicted.
	b.SendToStream(session, protocol.Envelope{Type: "stream_end"})
	ends, outs := 0, 0
	for len(ch) > 0 {
		switch (<-ch).Type {
		case "stream_end":
			ends++
		case "stream_out":
			outs++
		}
	}
	if ends != 1 {
		t.Errorf("terminal frames delivered = %d, want 1", ends)
	}
	if outs != 1 {
		t.Errorf("output chunks kept = %d, want 1 (one evicted to make room)", outs)
	}
}
