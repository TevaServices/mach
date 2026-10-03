#!/bin/sh
# rpm %post — reload systemd and enable (never start) the unit.
# machd with an unenrolled state dir would crash-loop; enrollment is a
# person at the machine (QR). Start after enrollment:
#   sudo systemctl start machd

systemctl daemon-reload || :
systemctl enable machd.service || :
exit 0