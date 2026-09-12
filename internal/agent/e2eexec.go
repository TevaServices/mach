package agent

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"log"

	"github.com/bcross/mach/internal/e2e"
	"github.com/bcross/mach/internal/protocol"
)

// handleExecFrame dispatches an exec envelope: sealed (E2E) or plaintext.
// In sealed mode the envelope payload is protocol.SealedExecCommand; the
// agent opens it with its X25519 key, executes, and seals the ExecResult
// back to the console's ephemeral reply key. The control plane relays
// ciphertext only.
func handleExecFrame(conn *protocol.WSConn, env protocol.Envelope, sem chan struct{}, e2eKey *E2EKeyPair) {
	var sealed protocol.SealedExecCommand
	if err := json.Unmarshal(env.Payload, &sealed); err == nil && sealed.SealedB64 != "" {
		handleSealedExec(conn, env, sealed, e2eKey, sem)
		return
	}
	handleExec(conn, env, sem)
}

func handleSealedExec(conn *protocol.WSConn, env protocol.Envelope, sealed protocol.SealedExecCommand, e2eKey *E2EKeyPair, sem chan struct{}) {
	inner, err := openSealedCommand(e2eKey, sealed)
	if err != nil {
		// Cannot read the command; tell the console in the clear only that
		// decryption failed (no content, since we have none) — but say why, since
		// the reason is about the envelope and not the command. "wrong machine"
		// and "the other end speaks a different format version" are the two that
		// happen in practice, and they have different fixes.
		replyExec(conn, env.ReqID, protocol.ExecResult{
			Error:    "e2e: sealed command failed to open: " + err.Error(),
			ExitCode: 126,
		})
		return
	}
	replyKey, err := hex.DecodeString(sealed.ReplyPub)
	if err != nil || len(replyKey) != 32 {
		replyExec(conn, env.ReqID, protocol.ExecResult{Error: "e2e: bad reply key", ExitCode: 126})
		return
	}
	// Run the opened command through the same policy/exec path. The inner
	// ExecCommand is re-marshaled into an envelope that handleExec parses;
	// reqID preserved so the result routes correctly.
	var cmd protocol.ExecCommand
	if err := json.Unmarshal(inner, &cmd); err != nil {
		replyExec(conn, env.ReqID, protocol.ExecResult{Error: "e2e: sealed payload not an ExecCommand", ExitCode: 126})
		return
	}
	cmdPayload, _ := json.Marshal(cmd)

	// Execute with the standard path but capture the result for sealing.
	res := runCommandResult(cmdPayload, sem)

	resPayload, _ := json.Marshal(res)
	sealedRes, err := e2e.Seal(replyKey, resPayload)
	if err != nil {
		log.Printf("agent: e2e seal failed: %v", err)
		// Cannot seal — send a plaintext failure notice (no command output;
		// none was exposed) so the console doesn't hang.
		replyExec(conn, env.ReqID, protocol.ExecResult{Error: "e2e: failed to seal result", ExitCode: 126})
		return
	}
	// SealedB64 is base64 of the SealedMessage JSON (console OpenB64 decodes).
	payload, _ := json.Marshal(protocol.SealedExecResult{SealedB64: stdBase64(sealedRes)})
	_ = conn.WriteEnvelope(protocol.Envelope{Type: "exec_result", ReqID: env.ReqID, Payload: payload})
}

// openSealedCommand opens sealed_b64 with the agent's E2E private key and
// returns the inner ExecCommand JSON.
//
// It takes the keypair rather than a state directory: the key is all it needs,
// and passing it means a temporary session — which holds its key only in memory —
// can run a sealed command without ever writing one to disk.
func openSealedCommand(e2eKey *E2EKeyPair, sealed protocol.SealedExecCommand) ([]byte, error) {
	if e2eKey == nil {
		return nil, errors.New("this agent has no E2E key loaded — refusing a sealed command")
	}
	body, err := base64.StdEncoding.DecodeString(sealed.SealedB64)
	if err != nil {
		return nil, err
	}
	return e2e.Open(&e2eKey.Private, body)
}
