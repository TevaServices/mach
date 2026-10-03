#!/bin/sh
# apk pre-deinstall — stop the service (upgrade or removal).

rc-service machd stop 2>/dev/null || :
exit 0