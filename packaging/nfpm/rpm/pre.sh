#!/bin/sh
# rpm %pre — create the service account before files land.
# Idempotent: reruns on upgrade; a pre-existing user is fine.

if ! id -u mach >/dev/null 2>&1; then
    useradd --system --home-dir /var/lib/mach --no-create-home \
        --shell /sbin/nologin mach
fi

# Record whether the agent is serving right now: %post on upgrade restarts
# exactly what was running (so an upgrade never reads as an outage, and a
# deliberately stopped agent — revoked machine, operator stop — stays
# stopped). rpm does not stop the unit on upgrade; %post restarts it to swap
# the binary in.
if systemctl is-active --quiet machd.service 2>/dev/null; then
    : > /run/machd.was-running
fi
exit 0