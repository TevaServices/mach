package server

// Embedded first-party assets: the two vendored scripts and the stylesheet.
//
// htmx is pinned and vendored — a single file with no dependencies and no build
// step — which is why the pages can be interactive without adding npm, a
// bundler, or a third-party origin to the control plane's critical path. A CDN
// would break the CSP and make the only publicly reachable component depend on
// someone else's uptime. The stylesheet follows the same rule: it is authored,
// committed and embedded, and nothing generates it.
//
// Serving is the strict allowlist in uihandlers.go (knownStaticFiles), never a
// file server over this directory.

import (
	"crypto/sha256"
	"embed"
	"encoding/hex"
)

//go:embed static/htmx.min.js static/app.js static/ui.css
var staticFiles embed.FS

// mustAsset reads an embedded asset, panicking if it is missing.
//
// A panic is right here and would not be anywhere else in this package: the
// paths are compile-time constants checked by the go:embed directive itself, so
// the only way to reach this is a renamed file that the embed line was not
// updated for. That is a broken build, not a runtime condition, and failing at
// init is how it is caught before a control plane starts serving pages that
// reference an asset it cannot read.
func mustAsset(name string) []byte {
	b, err := staticFiles.ReadFile(name)
	if err != nil {
		panic("server: embedded asset " + name + ": " + err.Error())
	}
	return b
}

// uiCSSBytes is the authored stylesheet, held once.
//
// It has two consumers that must never diverge: handleUIStatic serves it as a
// file, and the pair page inlines these same bytes into its own <style> (it
// cannot link a stylesheet — see pairpages.go). Reading it once here is what
// makes "one authored stylesheet, two delivery mechanisms" true by construction
// rather than by discipline.
var uiCSSBytes = mustAsset("static/ui.css")

// assetVersion is a short content digest of every served asset, appended to
// their URLs as ?v= by the shell.
//
// This is load-bearing rather than cosmetic. handleUIStatic serves these with
// `max-age=31536000, immutable`, which is correct for a fixed URL and wrong for
// one whose contents change: without a digest in the URL, a browser that has
// app.js keeps it for a year, so a shipped fix to the pages' interactive
// behaviour would not reach an operator who had visited before — and the symptom
// would be the old behaviour, silently, with nothing in any log.
//
// Hashing all three (not just the file that changed) is deliberate: one version
// for the whole asset set means they cannot be deployed half-old, and a browser
// holding a stale ui.css against fresh markup is the failure this exists to
// prevent.
var assetVersion = func() string {
	h := sha256.New()
	for _, name := range []string{"static/htmx.min.js", "static/app.js", "static/ui.css"} {
		h.Write(mustAsset(name))
	}
	return hex.EncodeToString(h.Sum(nil)[:4])
}()
