# Nightly connector imports

Scheduled connector work starts daily at **9:00 PM Arizona time (`America/Phoenix`)**, equivalent to **04:00 UTC the following day**, year-round. The scheduler checks once per minute, so a healthy idle worker starts within about a minute of that time.

The general connector batch retains its 25-minute gap between configured connector starts. CrowdStrike Spotlight can therefore start later than 9 PM, and imports can run for hours into the following day. This changes start timing, not import duration or resource requirements.

The same nightly rule applies to enabled Defender customer imports, ConnectWise ticket-status reads, and risk/threat-enrichment refreshes. Existing enable/disable settings remain effective. No connectors or scanner jobs are newly enabled.

## Restarts and manual actions

- The nightly start is eligible from 9 PM until midnight on that Arizona date. A late restart in that window may start the night's batch. A daytime restart does not launch a missed batch; the next automatic opportunity is 9 PM. Work already launched can continue after midnight.
- The general batch and ConnectWise/risk jobs atomically claim that night in `background_job_runs` before provider work. Defender uses the existing locked customer connection and `last_attempt_at`. Subsequent scheduler checks cannot repeatedly start the same nightly job.
- Failed nightly attempts do not automatically retry throughout the day. After a worker restart, an enabled scheduler checks once for the selected Spotlight customer's unfinished `running` checkpoint and resumes that exact run, including during daytime. It rechecks the current customer route and holds the existing database worker lock; if the run completed, failed, disappeared or changed scope before recovery, it refuses to create a replacement. Ambiguous customer routing requires manual selection. Manual **Sync now / Resume sync** remains available.
- In split runtime mode, a web-process crash restarts web independently, preserving the import worker and summary workers. Web retries are bounded by the supervisor's existing restart budget. Worker failures and exhausted web retries still restart the entire generation without overlapping writers; checkpoint recovery covers that case.
- A manual import earlier in the day does not postpone the fixed nightly start by another 24 hours. An already-active import retains the existing overlap guards.

## Separate schedules

Saved Elasticsearch and CrowdStrike tiles retain their configured refresh intervals. Summary workers, scan progress polling, scanner-side schedules, Nessus-offset scans, and independent Vulners Bridge scans are unchanged. The old `autoSyncIntervalHours` field remains for the independent Vulners Bridge scan interval; the Settings label now reflects that use.

Ticket drafts and ConnectWise ticket creation remain manual. The scheduled ConnectWise job reads ticket statuses; it does not create tickets.

No schema migration or connector reconfiguration is required. Build and deploy the application and compiled workers together. This scheduling change does not resolve the separately observed web-process memory crash.

## October 29 import interruption

Production logs showed the web process reaching its 8 GiB V8 limit and exiting with SIGABRT. The supervisor then stopped the healthy writer, leaving a partial Spotlight checkpoint. The nightly claim survived, but its in-memory job did not, so the importer stayed interrupted until manually resumed. A stored `running` flag alone is not evidence of a live worker; check the application status and tenant advisory lock too.

The recovery change preserves healthy workers during bounded web retries and resumes the selected unfinished checkpoint after a writer restart. It does not increase heap limits or claim to fix the web process's underlying memory growth. Completed counts and summaries remain on the previous generation until the new import passes its normal completion checks.

Validation: reproduced worker loss with a real child-process crash before the fix; 1,119 suite tests passed with seven optional database tests skipped; final Linux focused tests passed (87), TypeScript and production build passed. Separate disposable PostgreSQL checks verified legacy/reviewed checkpoint resume, customer filtering, refusal of completed/failed/changed-scope checkpoints, no replacement generation, and exclusion of overlapping workers. No production data was used in those database tests.
