# Spotlight summary check implementation plan

> Execute inline using superpowers:executing-plans, with one whole-change review before release.

**Goal:** Restore CrowdStrike Top fixes from the retained completed import without downloading it again.

**Architecture:** Validate counts and ownership in the existing bounded source scan, using the source table's primary-key order. Publish only after the scan reconciles with the completed import. Preserve snapshot isolation, vendor scope checks, source-generation fencing and atomic publication.

**Tech stack:** TypeScript, Node, PostgreSQL, existing dedicated summary worker.

**Spec:** User-approved correction of the reproduced 15-second integrity-count timeout and retry of the failed summary.

## Constraints and review focus

- No source-data deletion, new CrowdStrike import, ticket action, schema change or customer reassignment.
- Every row in the run must be checked, including misplaced tenants, duplicate source IDs across tenants and records excluded from displayed counts.
- Missing/extra records, incorrect ownership and changing import pointers must not publish partial summaries.
- Keep query and memory bounds; allow a bounded 15-minute total build and measure the retained large generation before release.
- Existing failed jobs must not silently reset; authorize one targeted retry only after the fix is deployed.

## Task 1: Stream integrity validation

Files: `lib/spotlight-summary-store.ts`, `tests/spotlight-summary-postgres.mjs`, `tests/spotlight-summary-restored.mjs`.

- [x] Add a regression test refusing an upfront full-source count; verify it fails on current code.
- [x] Traverse all run rows by `(tenant_key, source_id)`, using the existing primary key and bounded batches; check ownership per row.
- [x] Reconcile scanned rows against expected and hydrated counts before publication; keep resource bounds and pointer fencing.
- [x] Test multi-batch traversal, missing/extra records, misplaced tenants/company IDs, empty imports, rollback and supersession.
- [ ] Run a read-only build of the retained production generation, capturing performance and output counts without publishing.

## Task 2: Release and recovery

- [x] Run relevant unit/database tests, type checks and worker/app builds; review the complete change.
- [ ] Push a task branch, create/merge a PR and deploy the tested commit, preserving configuration and operator edits.
- [ ] Retry only the failed current-import summary, preserving its prior attempt evidence.
- [ ] Verify completed summary matches current import and Top fixes includes CrowdStrike without the pending warning; check service health.

## Evidence

Initial diagnosis: current import recorded 3,370,395 rows; summary model 4 job failed three times before scanning rows. Exact upfront integrity query reproduced SQLSTATE 57014 at 15,002 ms. Prior summary remains intact. Production code at `750cb23`.

The first read-only batch scan processes roughly 7,000 records/second, making the previous five-minute build deadline insufficient for the new import. Increase only the total deadline to 15 minutes, retaining 15-second query timeouts, memory/record limits, lease heartbeats and cancellation. The added clock-controlled database test failed against the old deadline before changing it.

Validation before release: 16 real PostgreSQL summary checks, nine worker lifecycle checks, 20 focused unit tests, TypeScript and production/worker builds passed. Full suite: 1,003 passed, seven optional database tests skipped, zero failed. Independent review found no blockers; completion of the retained-generation read-only scan remains the release check. The old five-minute budget was also reproduced on real retained data (300,340 ms); each batch query stayed under 1.4 seconds.
