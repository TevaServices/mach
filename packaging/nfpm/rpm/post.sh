#!/bin/sh
# rpm %post — reload systemd and enable the unit.
#
# First installs never start it: machd with an unenrolled state dir would
# crash-loop; enrollment is a person at the machine (QR). Start after
# enrollment: sudo systemctl start machd. config.json is the enrollment
# marker (agent/config.go).
#
# On upgrade this restart is also what swaps the binary: rpm never stops
# the unit on upgrade, so the OLD binary keeps running with the new one on
# disk until something restarts it. The restart covers every unit that did
# not retire itself — running (old binary), failed, or stopped by a signal
# (ExecMainStatus 130, e.g. an operator's systemctl stop). A retired
# machine's agent exited 0 on its own and must stay stopped: exit 0 means
# stop, and the suite pins that the supervisor never restarts a clean
# exit. Same rule as the deb scripts; see the deb postinst comment.

systemctl daemon-reload || :
systemctl enable machd.service || :
if [ -f /var/lib/mach/config.json ]; then
    st=$(systemctl is-active machd.service 2>/dev/null || true)
    ex=$(systemctl show machd.service -p ExecMainStatus --value 2>/dev/null || true)
    if [ "$st" != "inactive" ] || [ "$ex" != "0" ]; then
        systemctl restart machd.service || :
    fi
fi
exit 0