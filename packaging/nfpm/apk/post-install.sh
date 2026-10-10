#!/bin/sh
# apk post-install — install the OpenRC service into the default runlevel
# and create the state dir. First installs never START it here: machd with
# an unenrolled state dir would respawn forever; enrollment is a person at
# the machine. After enrollment: `sudo rc-service machd start`.
# (OpenRC instead of systemd: alpine has no systemd. Semantics pinned in
# the init script itself.)
#
# On upgrade the pre-deinstall has already stopped the service, so an
# enrolled machine is brought back here — config.json in the state dir is
# the enrollment marker (agent/config.go). apk has no hook that runs before
# the pre-deinstall, so there is no was-running marker like the deb/rpm
# scripts use: a deliberately stopped (revoked) machine gets ONE restart
# per upgrade and exits 0 again — the supervisor contract stays intact, at
# the cost of a single bounce. The state dir lives at /var/lib/mach on this
# package too (see pre-install).

install -d -o mach -g mach -m 0700 /var/lib/mach
rc-update add machd default 2>/dev/null || true
if [ -f /var/lib/mach/config.json ]; then
    rc-service machd restart 2>/dev/null || rc-service machd start 2>/dev/null || :
fi
exit 0