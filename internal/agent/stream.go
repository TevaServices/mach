package agent

// Streaming console: live output via streaming chunks
// rather than a kernel PTY. `mach console` opens a dedicated WebSocket
// (auth: bearer on the upgrade request) and gets live stdout/stderr as
// the command produces them; Ctrl-C sends a stream_kill frame. Wire types
// live in internal/protocol (StreamStart/StreamOut/StreamEnd/StreamStdin).

import (
	"encoding/json"

	"github.com/bcross/mach/internal/protocol"
)

// streamOutChunkSize is the max bytes per stream_out chunk (agent side).
const streamOutChunkSize = 32 << 10

// mustJSONStream marshals a streaming wire struct (used in streamexec.go).
func mustJSONStream(v any) json.RawMessage {
	b, _ := json.Marshal(v)
	return b
}

// b64Encode encodes a chunk for the wire (streamexec.go).
func b64Encode(b []byte) string { return stdBase64(b) }

// referencedProtocol keeps the protocol import for the wire docs above.
var _ = protocol.StreamStart{}