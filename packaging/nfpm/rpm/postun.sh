#!/bin/sh
# rpm %postun — on final REMOVE only (arg 0): disable the unit and remove
# state. rpm upgrades (arg 1) must not touch the service (the new package
# already re-enabled it in %post).

if [ "$1" -eq 0 ]; then
    systemctl disable machd.service || :
    rm -rf /var/lib/mach
    if id -u mach >/dev/null 2>&1; then
        userdel mach || :
    fi
    getent group mach >/dev/null 2>&1 && groupdel mach || :
fi
exit 0