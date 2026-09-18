// Package version is mach's one source of truth for its software version.
//
// The value is compiled in, and a release build overrides it at link time:
//
//	go build -ldflags "-X github.com/TevaServices/mach/internal/version.Version=0.3.0"
//
// A plain `go build` reports "devel" below, and that default says so on purpose:
// a binary that cannot say what it is must not claim to be a release. Nothing
// reads a version from the environment at runtime — a version an env var could
// change is a version no bug report can pin.
//
// Two binaries, one string. The agent and the control plane used to carry
// separate constants ("0.1.0-dev" and "0.2.0") that disagreed and that nothing
// compared, so `mach version` and `mach-server version` answered differently for
// the same checkout and neither could be trusted. This package is a leaf —
// stdlib only — for one reason: internal/server cannot import
// internal/controlplane (that dependency runs the other way), so the one value
// server, agent, controlplane and cmd all need has to live below all of them.
//
// Two near neighbours are deliberately NOT this. internal/agent's
// fleetPolicy.Version is a ruleset fingerprint (a content hash of the rules
// being enforced) and internal/e2e's sealedVersion is a message-format version.
// Both answer "do these two agree on the wire", never "what was this built as".
//
// -X sets a string variable only if the linker still has a use for it, and a
// typo in the symbol path does nothing at all rather than failing loudly. So
// this one has to stay genuinely read: `mach version` and `mach-server version`
// print it, the control plane compares it against every agent's reported version
// and renders it on signed-in pages, and the agent sends it at enrollment and on
// every connect. A build that stamped a version nothing read would keep the
// default below and say nothing about it.
package version

// Version is the mach software version, stamped at build time. It is a var and
// not a const because -X cannot set a constant.
var Version = "devel"
