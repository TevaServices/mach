#!/bin/sh
# apk pre-install — create the system account before files land.
# -S system user, -D no password, -H don't create home, nologin shell.

if ! id -u mach >/dev/null 2>&1; then
    adduser -S -D -H -h /var/lib/mach -s /sbin/nologin -G mach mach 2>/dev/null \
        || { addgroup -S mach 2>/dev/null; adduser -S -D -H -h /var/lib/mach -s /sbin/nologin mach; }
fi
exit 0