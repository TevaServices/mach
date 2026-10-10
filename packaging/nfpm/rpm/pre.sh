#!/bin/sh
# rpm %pre — create the service account before files land.
# Idempotent: reruns on upgrade; a pre-existing user is fine.

if ! id -u mach >/dev/null 2>&1; then
    useradd --system --home-dir /var/lib/mach --no-create-home \
        --shell /sbin/nologin mach
fi
exit 0
