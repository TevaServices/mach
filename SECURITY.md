# Security policy

## Threat model

`SECURITY-NOTES.md` is the full threat model and control list, including
an honest *Known gaps* section (pre-1.0). Read it before deploying mach
beyond a household, and before submitting changes to anything on a trust
boundary — pairing, enrollment, command policy, E2E sealing, the
streaming relay, the audit log, or the update path.

## Supported versions

mach is pre-1.0. Only the latest release on the `main` branch receives
security fixes.

## Reporting a vulnerability

Use GitHub's **private vulnerability reporting**: Security tab →
"Report a vulnerability". That is the fastest route and keeps the
issue private until a fix is out.

If you cannot use that, open a plain issue saying only "security —
please enable private reporting or share a contact" and nothing else;
do not describe the bug in the issue. Public issues describing a
live vulnerability will be edited.

Please include:

- a description of the issue and its security impact (which component
  or trust boundary it crosses);
- reproduction steps, ideally with the `mise run local:*` playground;
- the affected path, if you know it (`mach exec`, `mach console`,
  pairing, the web UI, the update/attestation path, ...);
- your thoughts on fixes or mitigations, if you have them.

## What to expect

- Acknowledgement within a few days; a fix timeline estimate once the
  report is understood.
- Credit in the fix's commit message and release notes, unless you ask
  to stay anonymous.
- Reports in the spirit of coordinated disclosure: please hold off on
  public disclosure until a fix ships, and tell us your intended
  disclosure date if you have one.

This project is run in the open, and safe-harbor applies: good-faith
research, including testing against your *own* deployments, is welcome.
Noisy scanning of third-party mach deployments is between you and those
deployments' operators.