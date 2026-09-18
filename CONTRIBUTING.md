# Contributing to mach

Thanks for contributing. This file covers the license terms for
contributions, the sign-off requirement, and how to get a change
through CI. Read `AGENTS.md` too — it documents the repo's conventions,
the security invariants, and the full testing requirements, and it
applies to human contributors as much as to AI ones.

## Licensing: inbound = outbound

This project is licensed under the **Apache License 2.0**
([LICENSE](LICENSE)).

**By submitting a pull request, you license your contribution to this
project under that same Apache-2.0 license, and only under it.** No CLA,
no copyright assignment, no additional terms — what you see in `LICENSE`
is what you give and what you get back. If your contribution contains
code you wrote for an employer, make sure that's something you can do;
the sign-off below is your statement that you can.

## Sign your work (DCO)

Every commit must carry a `Signed-off-by:` line matching its author —
the same [Developer Certificate of Origin](https://developercertificate.org/)
the Linux kernel uses. This is how you attest that you have the right
to submit the code, and it replaces a heavyweight CLA.

If `user.name` and `user.email` are configured, adding the sign-off is
one flag:

```
git commit -s
```

Already-committed work: `git rebase --signoff origin/main`, or amend
the tip with `git commit --amend -s`. CI checks every commit in a PR
and fails if the `Signed-off-by:` line is missing or does not match the
commit's author or committer.

## Before you open a PR

The same suite CI runs is the suite `mise.toml` defines (see
`AGENTS.md → Testing` for what each covers):

```
mise run lint        # gofmt + vet (fmt-check)
mise run test        # unit tests
mise run e2e         # end-to-end: control plane, enrollment, exec, console, policy
```

(`mise` tasks work with no Go toolchain only for container builds; for
tests, install the toolchain via `mise install` or your package manager.
`mise run e2e:postgres` exercises the Postgres path if you touch
anything in the store or DB layer.)

Ground expectations, all enforced by review:

- **Tests are not optional** — a bug fix comes with the test that fails
  without it, a feature comes with coverage of its behavior, and a
  security-relevant change comes with the test that proves the property.
- **Do not regress the security invariants** in `AGENTS.md → Security
  invariants` — and read `SECURITY-NOTES.md` before touching anything
  on a trust boundary (pairing, policy, E2E, streaming, audit). If your
  change alters what a component learns or can do, update
  `SECURITY-NOTES.md` in the same PR; it is documentation for reviewers,
  and drifting from the code is worse than being absent.
- **Refusals are behavior, not errors to work around.** A policy or
  scope refusal is a designed outcome; if a legitimate use case needs
  something a refusal blocks, change the design, not the check.
- Keep the CLI contract stable: machine output on stdout, `mach: `
  diagnostics on stderr, `--json` shape unchanged without a reason.

## Reporting a security issue

Do **not** open a public issue or PR for a vulnerability. Follow
[SECURITY.md](SECURITY.md).

## Scope

Small, focused PRs get reviewed faster. Follow-up work tracks in
GitHub issues (#2 sandboxing, #3 PTY, #4 signed image manifests,
#5 multi-server) — comment there before starting one so effort doesn't
collide.