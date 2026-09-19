package server

// The control plane's identity key is the one key the whole fleet pins. Every
// agent stores its public half at enrollment and verifies the hello and every
// update manifest against it, so a boot that quietly produces a *different*
// identity does not look like a broken key — it looks like every agent in the
// fleet refusing to connect, with nothing on the control plane to explain it.
//
// "No key yet" and "cannot read my key" are therefore different answers, and
// only the first may mint a replacement.

import (
	"os"
	"path/filepath"
	"testing"
)

func TestServerKeyIsNeverSilentlyReplaced(t *testing.T) {
	dir := t.TempDir()
	// A nested path, so the creating branch also exercises MkdirAll.
	path := filepath.Join(dir, "nested", "server.key")

	// First boot: minted and persisted.
	s := &Server{}
	if err := s.loadOrCreateServerKey(path); err != nil {
		t.Fatalf("first boot: %v", err)
	}
	if s.serverKeyHex == "" {
		t.Fatal("no identity key after first boot")
	}
	first := s.serverKeyHex

	// A restart is the same identity — that is the whole reason it is on disk.
	s2 := &Server{}
	if err := s2.loadOrCreateServerKey(path); err != nil {
		t.Fatalf("reload: %v", err)
	}
	if s2.serverKeyHex != first {
		t.Fatal("a restart minted a different identity key")
	}

	// A loose mode is tightened on load, the way the agent's own key is: a
	// volume restored from a backup can arrive world-readable.
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	s3 := &Server{}
	if err := s3.loadOrCreateServerKey(path); err != nil {
		t.Fatalf("reload after a loose mode: %v", err)
	}
	if got := fileMode(t, path); got != 0o600 {
		t.Fatalf("identity key left at mode %o, want 600", got)
	}
	if s3.serverKeyHex != first {
		t.Fatal("tightening the mode changed the identity")
	}

	// A corrupt file is refused, not replaced, and the file is left alone:
	// replacing it is a decision for the operator, not for a boot.
	if err := os.WriteFile(path, []byte("this is not a hex ed25519 private key"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	s4 := &Server{}
	if err := s4.loadOrCreateServerKey(path); err == nil {
		t.Fatal("a corrupt identity key was silently replaced")
	}
	if raw, _ := os.ReadFile(path); string(raw) != "this is not a hex ed25519 private key" {
		t.Fatalf("the corrupt key was overwritten: %q", raw)
	}

	// An unreadable one is refused too. A directory stands in for a read
	// failure because the answer then does not depend on which user the test
	// runs as — chmod 000 does not stop root.
	dirPath := filepath.Join(dir, "unreadable.key")
	if err := os.Mkdir(dirPath, 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	s5 := &Server{}
	if err := s5.loadOrCreateServerKey(dirPath); err == nil {
		t.Fatal("an unreadable identity key was silently replaced")
	}
	// And nothing was written over it: it is still the directory it was.
	if st, err := os.Stat(dirPath); err != nil || !st.IsDir() {
		t.Fatalf("the unreadable key path was overwritten: %v %v", st, err)
	}
}

func fileMode(t *testing.T, path string) os.FileMode {
	t.Helper()
	st, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat %s: %v", path, err)
	}
	return st.Mode().Perm()
}
