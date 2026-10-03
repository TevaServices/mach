#!/bin/sh
# rpm %preun — stop the unit on erase or upgrade (arg 0 = erase).
# Never on a plain package upgrade start/stop churn: on upgrade (arg 1)
# the unit keeps running unless files it needs are about to vanish —
# convention is to stop on erase only and let %posttrans restart; for a
# simple agent, stopping on upgrade is acceptable and simpler: the
# upgrade replaces the binary, so stop it either way (old binary dies
# with the package otherwise).

if [ "$1" -eq 0 ]; then
    systemctl stop machd.service || :
fi
exit 0