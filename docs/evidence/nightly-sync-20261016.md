# Arizona nightly sync verification — 2026-10-16

Connector imports now use a fixed 9:00 PM America/Phoenix start instead of an elapsed 24-hour interval. Enabled Defender imports, ConnectWise ticket-status reads and risk refresh use the same nightly rule. The existing connector stagger, manual sync, saved-tile refresh intervals, customer assignments and scanner schedules are preserved.

## Validation

- New daytime/restart tests failed against the old behavior, then passed with the shared calendar-time gate.
- Boundary checks cover 20:59:59 to 21:00, winter/summer, daylight-saving transition dates, year rollover, midnight, daytime restart, the next night's run, disabled automation and busy workers.
- The general batch additionally uses an atomic `background_job_runs` claim, so losing its cached scheduler metadata on restart does not duplicate the same night's start.
- Isolated PostgreSQL checks passed: twelve simultaneous claims permit one start; a failed attempt remains claimed; next-night eligibility does not drift with the previous start minute; enabled/disabled Defender customer scheduling and daytime manual override behave as expected. The disposable cluster had a private Unix socket and no TCP listener. No provider requests were made.
- Targeted suite: 28 passed, one optional PostgreSQL test skipped. TypeScript no-emit check passed.
- Final Linux suite: **1,008 passed, seven optional database tests skipped, zero failed**. Both compiled worker builds and the production webpack build passed. The separately executed PostgreSQL test covers the changed SQL scheduling behavior.
- Read-only production checks before deployment confirmed auto-sync enabled, the general scheduler enabled, no general sync-all active, and read/write health ready.

## Operational limits

The nightly start can catch up until Arizona midnight; a daytime restart waits until the next 9 PM. An already-started batch can continue after midnight. CrowdStrike may start later than 9 PM because configured connectors retain their 25-minute start gaps. A failed or interrupted attempt requires manual resume or the next nightly attempt; stored checkpoints and previously completed data remain intact.

The independently observed 8 GiB web-process memory crash is not fixed by this change. Scheduling moves automatic imports overnight and does not promise a completion time or remove all daytime background work.
