# Vuln Storage Reliability Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Prevent transient private-publication failures from permanently disabling saves, identify and remove long transaction gaps, and address the separate web heap crash.

**Architecture:** Preserve the single writer, immutable prepared changes, private finding generations and atomic active-generation switch. Add controlled connection recovery and measurable transaction bounds. Treat web memory remediation as a separate evidence-led change.

**Tech Stack:** Existing Next.js/TypeScript application, Node.js 24, installed `pg` 8.23.1, PostgreSQL 18, Node test runner; no new runtime dependency planned.

**Spec:** `docs/superpowers/specs/2026-10-30-storage-reliability-design.md` (proposed design; not yet implemented).

## Global constraints

- Production investigation remains read-only until implementation/deployment is requested.
- Preserve SQL authority checks, private checkpoints, customer isolation, integrity checks and durable-save acknowledgments.
- A private preparation failure may retry; an uncertain active COMMIT must not.
- Never return a dead client to the pool as healthy, start a second writer, or log secrets/payloads.
- Work on a fresh task branch from the current production-compatible source, preserving all unrelated local/server edits.
- Build before stopping the application. Require PR review and isolated PostgreSQL validation; no direct main push.
- Keep the 90-second idle and 60-second statement safeguards initially; another timeout increase is not the proposed repair.

## Review focus

1. Disconnect arrives between queries and emits two errors: preserve first SQLSTATE and prevent uncaught exceptions (Task 1).
2. Private batch commit succeeded but acknowledgment was lost: resume from durable checkpoint, never double-apply (Task 2).
3. Another writer changes authority during backoff: stop without overwriting it (Task 2).
4. One very large valid record defeats a row-count-only batch limit: prepare and bound encoded bytes outside the transaction (Task 3).
5. A slow or aborted browser request retains a retired snapshot across repeated refreshes: preserve in-flight consistency and release it after completion (Task 5).

## Task 0 — Establish the isolated baseline

**Files:** current production versions of `lib/persist.ts`, `lib/store.ts`, `lib/db/platform-publication.mjs`, `lib/db/platform-records.mjs`, `scripts/runtime-server.mjs`, and existing persistence/reader tests. Evidence: `output/storage-diagnostic-20261030/`.

- [ ] Fetch and inspect the current release ancestry; create an isolated task checkout. Confirm which changes landed after `ca61c6e8f`. Do not implement against the old local `lib/persist.ts` or overwrite its unrelated changes.
- [ ] Read applicable AGENTS files and existing release/test runbooks in that checkout. Record Node/pg/PostgreSQL versions used for tests.
- [ ] Provision a disposable private Unix-socket PostgreSQL instance with no production credentials or vendor access. The existing `tests/platform-generation-postgres.mjs` requires a verified `/home/codex/vuln-recovery/.../socket`, port 55483, a data directory under that scratch root and empty `listen_addresses`. Respect those guards; alternatively adapt them explicitly to a verified isolated runner before use. Do not loosen them to accept a production URL.
- [ ] Run the existing relevant unit suite and generation integration suite to establish baseline. Record failures before making changes.

## Task 1 — Reproduce and contain borrowed-client failure

**Modify:** `lib/db/platform-publication.mjs`, `lib/persist.ts`.
**Create:** `lib/db/publication-client.mjs` for the shared borrowed-client lifecycle handling used by preparation and final commit.
**Create/test:** `tests/platform-publication-recovery.test.mjs`.
**Extend:** `tests/platform-generation-postgres.mjs`.

**Interfaces:** retain `prepareFindingPublication(pool, plan, options)` and `preparePlatformReporting(pool, plan)` signatures. Add `trackPublicationClient(client)` in `lib/db/publication-client.mjs`, returning `{ firstError(): Error | undefined, release(error?: Error): void }`. It retains the first fatal error, remains responsible for error containment throughout borrowed ownership, and releases/destroys exactly once. Use it in both preparation functions and on the separate final active-transaction client in `saveSnapshot`. Cleanup of the observer must not leave a gap before the pool resumes ownership or a failed connection finishes closing.

- [ ] Add failing tests for a checked-out client's asynchronous `25P03`, followed by a generic connection error, with no query pending. Assert original SQLSTATE survives, operation rejects, no uncaught exception occurs, release/destroy happens exactly once, and the pool never receives a healthy release for that connection.
- [ ] Add the real idle-timeout case to the isolated PostgreSQL suite, shortening only the test connection's timeout. Verify the current implementation fails for the expected missing handling.
- [ ] Attach error observation before issuing publication queries; ensure cleanup cannot mask the first error. Handle a dead connection during advisory unlock/rollback and prevent listener leaks on repeated successful borrowing. Keep healthy release behavior unchanged. Cover the final active-transaction client as well as both private-preparation clients.
- [ ] Add tests for an asynchronous disconnect between final-transaction queries, during COMMIT and during cleanup. Assert controlled failure, no uncaught exception, first-error preservation and exactly one destruction. An uncertain active-COMMIT result must block safely without retry, even when its error code is otherwise transient during private preparation.
- [ ] In `saveSnapshot`, include known `25P03` in the private-preparation transient classification. Do not add it to a blanket catch covering active COMMIT. Do not classify malformed input or stale writer errors as transient.
- [ ] Run `node --test tests/platform-publication-recovery.test.mjs tests/platform-generation-writes.test.mjs tests/platform-prepared-save.test.mjs`, then the isolated integration suite. Commit this independently reviewable fix.

## Task 2 — Retry the immutable plan without losing later mutations

**Modify:** `lib/persist.ts`, `lib/store.ts` only where required by retry state, `lib/defender-platform.ts` only if acknowledgment behavior requires adjustment.
**Tests:** Task 1 tests, `tests/platform-generation-postgres.mjs`, and `tests/defender-platform.test.mjs`.

**Interfaces:** existing `saveSnapshot(data, {guard, captureGuard, changes})` remains the caller contract. Retry occurs inside its preparation lifecycle after the plan is frozen; `platform-publication-deferred` remains the exhausted-retry signal. `flushNow({throwOnError:true})` must not resolve successfully without its durable commit.

- [ ] Add failures at private write, checkpoint update, lost private-commit acknowledgment, copying and reporting; separately test stale authority and unknown active-COMMIT outcome.
- [ ] Assert the old generation stays visible until the final successful swap, retry uses the same plan/hash, checkpointed rows are not duplicated, and RAM mutations arriving later remain pending for the next save.
- [ ] Implement three fresh-client retries with 5-, 15- and 60-second backoff, no transaction or failed connection held during the wait, and existing lock/base/authority/checkpoint checks on every attempt. After exhaustion, defer through the current later retry path and retain honest dirty state. Do not promise unchanged progress if a later invocation constructs a different plan.
- [ ] Verify a metadata edit during backoff, a customer-scoped change, duplicate trigger and stale epoch cannot be lost or misapplied. A truly blocked failure must still block subsequent mutations.
- [ ] Run unit tests plus `node --experimental-vm-modules tests/platform-generation-postgres.mjs "$TEST_SOCKET"` against the verified disposable socket. Commit with evidence of recovery and refusal cases.

## Task 3 — Attribute the idle gap and bound transaction work

**Modify:** `lib/db/platform-publication.mjs`, `lib/db/platform-records.mjs`, `lib/persist.ts`, `scripts/runtime-server.mjs` (process metrics).
**Create/test:** `tests/platform-publication-timing.test.mjs`, `tests/platform-publication-load.mjs`.

**Interfaces:** retain existing `upsertPlatformRecords` behavior for its callers. Add an explicit pre-encoded batch path for publication so validation/JSON encoding occurs before BEGIN; the prepared value must contain SQL/parameters/row count/encoded bytes and immutable input. Checkpoint offset advances by the actual batch length, not a hard-coded 500.

- [ ] Add a test that records transaction boundaries and asserts no payload serialization, waits or external work occur inside a private write transaction. Test 500 small rows, a batch crossing 4 MiB, and a singleton near the existing 16 MiB payload limit.
- [ ] Add timestamped per-phase/query measurements and 10-second process samples using built-in `perf_hooks`; reset delay histograms. Log normal batch aggregates at most every 30 seconds, with detailed slow/failure events. Include role/PID, backend PID, phase/offset, bytes, query time, inter-query gap, transaction age and first SQLSTATE; exclude payloads/parameters.
- [ ] Prepare batches to a 500-row and 4 MiB target outside BEGIN, allowing one valid large record as a singleton. Keep row write and checkpoint advancement atomic. Preserve column/identity validation and the 16 MiB payload rejection.
- [ ] Reproduce at least 1.34 million active findings and 856,751 changed findings on the isolated fixture with representative risk scoring, scanner work, concurrent edits and browser reads. Correlate a slow gap with event-loop delay, GC/heap and SQL timing. Use an external observer so a blocked event loop cannot hide its own pause.
- [ ] Fix only the measured CPU/blocking path: add bounded yields with correct version guards, or isolate that specific task using the existing auxiliary-worker model if yielding is insufficient. If transport rather than CPU is implicated, capture server/client timing and fix that demonstrated path. Do not assign blame from overlapping logs alone.
- [ ] Required evidence: max event-loop delay <2 seconds, max client inter-query idle gap <10 seconds, ordinary batch p99 <10 seconds, unchanged active data on failure and successful eventual publication after injected disconnects. These are proposed targets; failed runs require investigation, not silent threshold increases. Commit the attributable transaction/workload change separately from recovery.

## Task 4 — Make persistence and child-process health actionable

**Modify:** `lib/store.ts`, `app/api/health/route.ts`, `components/VulnDashboardPage.tsx`, `scripts/start-app.mjs`.
**Create/test:** `tests/persistence-health.test.mjs`; extend runtime supervisor tests already present in the current checkout.

**Interfaces:** authenticated `storeStatus()` gains `persistenceState` (`healthy|publishing|retrying|blocked`), `lastCommittedRevision`, `lastCommittedAt`, `pendingSince`, `nextRetryAt`, and a sanitized first-error record `{code,phase,at}`. Anonymous health continues exposing only booleans. Derive write readiness from ability to durably accept changes, not just DB ping.

- [ ] Write tests for healthy, in-progress, deferred and permanent-block states, including successful DB ping with unavailable writes and caller requests during backoff. No successful mutation acknowledgment may precede COMMIT.
- [ ] Implement transitions from actual save events. Report elapsed time since pending work made durable progress; do not alert on a legitimately quiet application with nothing dirty. Ensure later successful saves clear transient state.
- [ ] Refresh dashboard health every 15 seconds while mounted. Distinguish retrying from blocked and preserve the warning that uncommitted edits are not yet saved. Test recovery without a browser reload.
- [ ] Add UTC timestamps to child start/exit/restart events and expose child restart/failure to the existing monitoring path. Configure an alert for pending dirty work without durable progress for five minutes, plus unexpected child exits. Do not send new external notifications as part of implementation/testing.
- [ ] Run health/UI/supervisor tests and verify anonymous responses do not disclose identifiers, errors or tenant counts. Commit separately.

## Task 5 — Resolve the web heap failure as a separate change

**Investigate/modify only as demonstrated:** `lib/committed-cache.mjs`, `lib/db/platform-reader.mjs`, `lib/store.ts` (`prepareCommittedView`, `memoRead`), `scripts/runtime-server.mjs` (request context).
**Tests:** `tests/platform-reader.test.mjs`, `tests/platform-retained-runtime.mjs`, and a new `tests/platform-reader-memory.mjs`.

- [ ] Build an isolated memory reproduction with 1.34 million representative findings, broad bucket replacements, overlapping reads, slow/aborted responses and repeated refresh cycles under `--max-old-space-size=8192`. Profile the isolated process only; heap snapshots can contain data and pause the process.
- [ ] Determine whether growth is obsolete-view retention, cache/request references, transient duplicate payloads, or legitimate overlapping full generations. Record retaining paths and before/after heap measurements.
- [ ] Fix the measured retention/duplication while keeping old requests consistent and preserving checksum validation. Reuse unchanged immutable data only where verified safe; release references after request completion/abort.
- [ ] Require web peak heap <6 GiB, no growth after repeated quiescent refresh cycles and no crash during the 48-hour soak. If full valid overlapping generations cannot fit, stop this narrow memory patch and produce a separate bounded SQL-reader design; do not just increase the heap cap.
- [ ] Run reader/runtime tests and memory replay, and commit/review separately from persistence recovery.

## Task 6 — Safe recovery, staged rollout and proof

**Document/update:** the current deployment runbook and `docs/operations/storage-recovery.md` (new if no equivalent exists).

- [ ] Run the change-appropriate unit suites, isolated PostgreSQL fault suite, type check and build in the isolated checkout. Build with production credentials/vendor access absent; use existing scheduler isolation for previews.
- [ ] Before production changes, record release/build ID, current authority/head/checkpoint, source-run durability and pending user mutations. Verify a usable managed-database restore point. Preserve non-replayable RAM edits before stopping the writer; do not assume source-import replay covers user triage/settings.
- [ ] Deploy the reviewed, prebuilt compatible release with one writer. Keep the prior application release ready; do not drop checkpoints, delete active findings, disable integrity checks or restore an old database to fit a rollback binary.
- [ ] Verify recovered writer state, a new durable revision/commit time, expected finding counts and atomic generation visibility. Use a controlled reversible application mutation only when executing the approved recovery, verifying it through both the API and SQL.
- [ ] Run a 48-hour soak spanning two daily import/publication cycles, browser traffic and staged fault injections. Monitor pending-save age, error codes, transaction gaps, event-loop delay, peak heap and child exits. Production fault injection is excluded unless separately designed and authorized.
- [ ] Close the incident only after the acceptance evidence is recorded. If a writer blocks, a count/integrity check fails, a second writer appears or memory exceeds the agreed ceiling, stop rollout, preserve evidence and follow the reviewed application rollback/recovery procedure.

## Current execution status

Only investigation, source/evidence capture, a standalone read-only timeout reproduction and this plan are complete. No repair code, tests modifying application state, production restart or deployment has been performed. The exact initiating idle-gap workload and web OOM retaining path remain open and have explicit investigation/acceptance steps above.

The design received an independent builder check; the final-commit client lifecycle gap it identified is included in Task 1. Plan self-review covered design requirements, recovery/refusal cases, interfaces, isolated-test safeguards and rollout boundaries.
