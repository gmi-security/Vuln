# SQL save recovery — October 15, 2026

## Incident and evidence

Production was serving its previous committed view with writes blocked. PostgreSQL was reachable, no blocking transactions were found, and the completed Defender import was already published. A later save logged `SQL platform save timed out after 300000ms`, followed by an idle-in-transaction timeout. Historical heap crashes in the same log belonged to older processes.

The full-save fallback compared every platform record and calculated reporting hashes **after** opening its transaction and acquiring the writer fence. A read-only production-data benchmark loaded 1,073,267 findings, changed one scan only in private memory, and exercised the old writer against a fake SQL client: comparison took 133,942 ms. The application's idle-in-transaction limit is 90 seconds. There is enough CPU work between SQL statements to exceed that limit even for a scan-only edit. The old logs do not identify the exact caller of the failed save; this establishes a reproducible failure mechanism, not a claim that every historical timeout had the same cause.

## Change

- Prepare full comparisons and reporting hashes before borrowing a database connection. Retain frozen changed rows and the next hash index, not another copy of all unchanged payloads.
- Recheck the SQL authority epoch/revision after preparation, then write bounded batches. Publish rows, metadata, reporting revisions and commit audit atomically. Replace the writer's committed state only after COMMIT succeeds.
- Guard preparation against concurrent RAM mutations and a five-minute deadline. The transaction retains the five-minute ordinary-save budget; full comparisons discovering at least 100,000 changed findings receive the same fifteen-minute limit already used for scoped bulk imports.
- Scope Nessus progress/error updates to scan IDs. Completed or partially failed imports promote back to full scope so findings, aliases and completion markers cannot be omitted.
- Pause new general, scanner-export and Vulners Bridge scheduler ticks while platform persistence is blocked. Existing saved schedule settings are unchanged. This does not cancel already-running external scans.
- Log safe phase, scope, elapsed time and row counts for SQL saves. Preserve fail-closed behavior on database/fence failures.

No schema migration, credential change, connector cadence change, tile-refresh change or automatic ticket creation is included. Production remains on one SQL writer and a separate committed web reader.

## Verification

- Regression tests first demonstrated missing prepared-save behavior and background ticks continuing after blocked storage.
- Full suite: 941 passed, 7 optional database tests skipped, zero failed. Both auxiliary worker builds and the Linux Next production build passed.
- Separate private PostgreSQL suite: 19 checks passed, including full preparation with no borrowed connection, fault injection after an actual row insert, rollback of rows/authority/reporting, successful retry with independently matched reporting hashes, stale-writer fencing, committed reads and restart recovery.
- Independent code review found a Nessus scope regression; it was fixed and covered by real store/import logic with mocked provider transport, including restart with no stale closures. Follow-up review found no remaining blocking code issues.
- Read-only production-data benchmark with the revised writer: one scan edit prepared in 130,357 ms, then simulated writes took 2 ms. A second pass changed all 1,073,267 findings plus that scan in private RAM: preparation 144,290 ms, simulated writes 12,350 ms, peak sampled RSS 8,422 MiB. Both performed **zero production writes**. Fake SQL timings are not production database latency measurements. Worker heap allowance remains 16 GiB; the host has 32 GiB RAM.

## Release and remaining limits

Merge the reviewed branch through a PR, verify the staged source matches the merged tree, and deploy the already-built artifacts. Preserve production operator scripts and environment. Stop the existing supervisor and all children before starting the new build. Verify both read and write readiness, a real new commit, and absence of new persistence failures before calling recovery complete.

Full unscoped imports still compare the entire platform and require memory/CPU. This fix removes that work from idle SQL transactions; broader conversion of old import paths to explicit mutation scopes remains separate work. Genuine database outages and stale-writer violations still block writes deliberately.

## Follow-up: import correlation CPU

After the transaction fix deployed, startup recovered and a real metadata save committed. The scheduled Nessus sync then made the writer unresponsive while committed web reads remained available and persistence was not blocked. A ten-second CPU profile attributed 8,626 of 8,982 samples to the compiled `importVendorFindings` function. Its correlation index called `lookupAsset` for each finding, rescanning the entire inventory each time; each Nessus scan also indexed unrelated customers. Concurrent captures were invalidated while that import continued.

The follow-up builds inventory maps once, preserving first exact-identifier matches, ambiguous-alias rejection, normalization, customer boundaries and the existing last-finding-wins behavior. Nessus requests only its customer's correlation index; the multi-customer Vulners importer retains its existing scope. No matching/classification rules change.

Read-only comparison against 1,073,267 live finding identities and 15,049 assets: the original algorithm took 348 ms for a 1,000-finding sample; the indexed algorithm took 37 ms for the same sample, 1,683 ms for the full set and 199 ms for one customer's index. Sample keys and finding references matched; customer-scoped results matched the filtered full index. Peak observed RSS was 1,026 MiB. Production writes: zero. Independent review also compared 300 generated fixtures against the original lookup rules. Full suite: 943 passed, 7 optional DB tests skipped; Linux Next and both auxiliary worker builds passed.

The interrupted scheduled run's persisted start timestamp must be made due once after stopping the old writer, using the existing fenced metadata writer and atomic reporting publication. Require the exact observed timestamp; keep the 24-hour setting and connector-specific daily gates unchanged. This retries the interrupted import rather than treating its start as a successful day's sync.
