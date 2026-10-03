#!/bin/sh
# apk post-install — install the OpenRC service into the default runlevel
# and create the state dir. Never START it here: machd with an unenrolled
# state dir would respawn forever; enrollment is a person at the machine.
# After enrollment: `sudo rc-service machd start`.
# (OpenRC instead of systemd: alpine has no systemd. Semantics pinned in
# the init script itself.)

install -d -o mach -g mach -m 0700 /var/lib/mach
rc-update add machd default 2>/dev/null || true
exit 0