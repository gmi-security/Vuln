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

## Follow-up: frozen captures and concurrent progress

Live verification kept read/write health available, but full saves repeatedly finished preparation and then aborted with `platform-capture-changed` during the write phase. RAM mutations were invalidating an already-detached generation. The log identifies the mutation-version conflict, not which caller changed the version.

Separate the RAM capture check from general cancellation: check the capture throughout preparation and reporting digest completion, then commit its frozen rows, metadata and reporting even if later RAM changes arrive. Later mutations retain their dirty scope and their own queued save; they cannot be acknowledged by the earlier commit. Delta writes retain the capture check throughout because they still reference live values. Deadlines, generic cancellation and SQL epoch/revision fencing remain active for every write. Preparation-phase changes still retry.

Nessus new-scan imports also mark their completion/partial failure dirty after the awaited import, so a capture taken during the API request cannot suppress persistence of later findings and completion metadata. Regression coverage includes queued-save acknowledgment, restart, preparation refusal, delta capture rejection and general cancellation after INSERT, plus real PostgreSQL row/reporting consistency across a later RAM mutation.

Verification: 949 tests passed, seven optional database tests skipped, zero failed; the separate disposable PostgreSQL suite passed all 20 checks. Independent review found no remaining code issues. During verification the previously deployed version completed a full production save (411 inserted records, 234 updated), followed by successful scoped scan updates; the final change avoids the observed write-phase recapture loop.

## October 23: scoped reporting stream timeout

The latest failure was a reachable database with application writes blocked after two 30-minute publication attempts. Both reached the reporting phase: the final attempt spent 1,299,283 ms writing and 500,718 ms reporting before its deadline. The completed Defender source import remained stored, but its generation differed from the platform publication marker. Capture-change retries and unrelated malformed Server Action messages do not establish the cause of this timeout.

The reporting ID stream used `company_id=ANY($4::text[])`. Production EXPLAIN selected the global bucket/order index and filtered unrelated customers from heap rows. A scalar `company_id=$4` used the existing customer/bucket/order index. A read-only comparison of the same 15,722 IDs across 33 pages took 2,488 ms with the old predicate and 256 ms with equality. These are sample query timings, not a whole-publication benchmark.

Scoped publication now streams each unique affected customer separately, resetting the pagination cursor per customer. This preserves each customer's order, reporting hashes, moved/deleted-record handling, frozen payload reuse, and the atomic data/reporting commit. Unscoped publication remains supported. No timeout, schema, schedule, credentials, or ticket behavior changes.

Validation before deployment:

- Targeted regression tests failed against the old array predicate, then passed with scalar scopes. Duplicate customer scopes retain the prior SQL membership semantics.
- Full suite: 1,083 passed, seven optional database tests skipped, zero failed. TypeScript, Linux Next production build, and both auxiliary worker builds passed.
- Fresh private PostgreSQL cluster: all 25 checks passed, including rollback, timed-out transaction retry, customer moves/deletions, uncertain COMMIT handling, stale-writer rejection, and restart. A 64,001-row bulk fixture committed with independently matched reporting hashes. No production database writes were used for these tests.
- Independent review found no blocking issues. Additional checks covered equal-order pagination, reversed/duplicate scopes, and unscoped company additions.

Release acceptance requires the pending production generation to commit, its source and platform markers to agree, subsequent ordinary saves to succeed, and read/write health to remain ready. The slow write phase is unchanged; the sample speedup alone does not establish that the entire production save fits its budget. Genuine database failures must still block saving rather than silently discard data.

The PR security gate also identified newly reported vulnerabilities in the existing Next.js 16.4.0 dependency. This release updates Next.js and its ESLint configuration to 16.4.1, retaining the already-patched sharp 0.35.5 image library. This dependency patch is separate from the persistence root cause. The repeated full suite again passed 1,083 tests with seven optional skips; TypeScript, the Linux production build, and both worker builds passed against the patched lockfile.
