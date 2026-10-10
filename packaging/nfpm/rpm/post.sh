#!/bin/sh
# rpm %post — reload systemd and enable the unit.
#
# First installs never start it: machd with an unenrolled state dir would
# crash-loop; enrollment is a person at the machine (QR). Start after
# enrollment: sudo systemctl start machd.
#
# On upgrade the %pre recorded whether the agent was serving; restart
# exactly that. rpm never stops the unit on upgrade, so this is also what
# swaps the old binary for the new one — without it the old binary keeps
# running with the new one on disk. A deliberately stopped agent left no
# marker and stays stopped.

systemctl daemon-reload || :
systemctl enable machd.service || :
if [ -f /run/machd.was-running ]; then
    rm -f /run/machd.was-running
    systemctl restart machd.service || :
fi
exit 0