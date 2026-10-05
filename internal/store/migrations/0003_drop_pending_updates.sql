-- 0003: drop the pushed-update queue. The control plane no longer pushes
-- agent binaries — updates go through the distribution points (apt/rpm/apk,
-- winget/MSI, brew), each of whose supervisors restarts the agent on failure
-- only. The table held signed update manifests queued for delivery on the
-- machine's next connect; nothing queues them anymore.
DROP TABLE IF EXISTS pending_updates;