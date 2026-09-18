# Third-party notices

Code vendored into this repository rather than pulled in as a Go
module dependency. Each entry records what ships inside our binaries,
where it came from, and under what license — even where that license
requires no attribution, so a person auditing a release binary can
find every non-project component without a diff.

## htmx 2.0.10

- **What:** `internal/server/static/htmx.min.js` — the whole of it,
  unmodified, embedded in the control-plane binary by
  `internal/server/assets.go` and served to the web UI and the public
  enrollment page.
- **Source:** <https://github.com/bigskysoftware/htmx/tree/v2.0.10>
  (`dist/htmx.min.js` from that tag).
- **License:** Zero-Clause BSD. Reproduced verbatim below.

```
Zero-Clause BSD
=============

Permission to use, copy, modify, and/or distribute this software for
any purpose with or without fee is hereby granted.

THE SOFTWARE IS PROVIDED “AS IS” AND THE AUTHOR DISCLAIMS ALL
WARRANTIES WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES
OF MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE
FOR ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY
DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN
AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT
OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
```

Go module dependencies are recorded in `go.mod` and are not vendored
into the tree; all of them are BSD/MIT/Apache-2.0 licensed.