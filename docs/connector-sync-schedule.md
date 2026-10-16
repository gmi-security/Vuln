# Nightly connector imports

Scheduled connector work starts daily at **9:00 PM Arizona time (`America/Phoenix`)**, equivalent to **04:00 UTC the following day**, year-round. The scheduler checks once per minute, so a healthy idle worker starts within about a minute of that time.

The general connector batch retains its 25-minute gap between configured connector starts. CrowdStrike Spotlight can therefore start later than 9 PM, and imports can run for hours into the following day. This changes start timing, not import duration or resource requirements.

The same nightly rule applies to enabled Defender customer imports, ConnectWise ticket-status reads, and risk/threat-enrichment refreshes. Existing enable/disable settings remain effective. No connectors or scanner jobs are newly enabled.

## Restarts and manual actions

- The nightly start is eligible from 9 PM until midnight on that Arizona date. A late restart in that window may start the night's batch. A daytime restart does not launch a missed batch; the next automatic opportunity is 9 PM. Work already launched can continue after midnight.
- The general batch and ConnectWise/risk jobs atomically claim that night in `background_job_runs` before provider work. Defender uses the existing locked customer connection and `last_attempt_at`. Subsequent scheduler checks cannot repeatedly start the same nightly job.
- Failed or interrupted nightly attempts do not automatically retry throughout the day. Manual **Sync now / Resume sync** remains available. Spotlight retains its existing checkpoint/cursor recovery behavior and previous completed generation.
- A manual import earlier in the day does not postpone the fixed nightly start by another 24 hours. An already-active import retains the existing overlap guards.

## Separate schedules

Saved Elasticsearch and CrowdStrike tiles retain their configured refresh intervals. Summary workers, scan progress polling, scanner-side schedules, Nessus-offset scans, and independent Vulners Bridge scans are unchanged. The old `autoSyncIntervalHours` field remains for the independent Vulners Bridge scan interval; the Settings label now reflects that use.

Ticket drafts and ConnectWise ticket creation remain manual. The scheduled ConnectWise job reads ticket statuses; it does not create tickets.

No schema migration or connector reconfiguration is required. Build and deploy the application and compiled workers together. This scheduling change does not resolve the separately observed web-process memory crash.
