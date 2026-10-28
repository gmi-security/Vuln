# Resumable platform publication

> **For agentic workers:** Use superpowers:executing-plans. The user authorized implementation and deployment after the live incident investigation; do not request approval again for these steps.

**Goal:** Complete large imports without a single 30-minute transaction or a transient staging failure permanently disabling platform saving.

**Architecture:** Keep the existing normalized records, customer boundaries and committed-reader contract. Store large finding generations privately in PostgreSQL, checkpoint their batches, compute reporting hashes before publication, then switch the active generation with metadata/report revisions in one short fenced transaction. Ordinary edits continue to update the active generation. No incomplete generation is visible.

**Tech stack:** Existing Next.js/TypeScript, node-postgres and PostgreSQL; no new dependency.

## Incident and alternatives

The October 25 UTC publication involved 778,868 candidate findings and timed out twice in reporting after approximately 20–22 minutes of writes. The October 23 query optimization is installed. The completed Defender source generation remains saved. Increasing a timeout leaves the all-or-nothing work and full retries intact. Committing changes directly into live findings in smaller transactions would expose partial imports. Use private generations and a final atomic publication instead.

## Constraints and design

- Preserve every current record, source payload, source assignment, ticket, schedule and credential. No provider resync or ticket POST is needed to recover the pending Defender generation.
- Keep `app_findings` as the read interface through a view; move its physical rows to `app_finding_versions` with a generation key. A one-row active-generation pointer selects visible records. Install the conversion explicitly during maintenance, transactionally, with bounded lock waits.
- A publication journal identifies the original authority, frozen plan hash, generation and batch checkpoints. Only an exact plan/base match may resume. A changed plan starts a distinct generation. Ordinary writers remain fenced by the existing epoch/revision protocol.
- Populate changed rows first in small committed batches, then copy unchanged active rows within PostgreSQL, omitting deleted IDs. Copy checkpoints advance from source order even when all records on a page already have replacements. No source payloads are sent back through Node for the copy.
- Reuse the existing reporting digest rules against the staged findings and an SQL overlay of the frozen non-finding changes. Store the completed digests before switching the pointer. Reject changed authority, missing rows, corrupt checkpoints and missing reporting evidence.
- Final transaction switches findings and saves small collections, metadata, audit and reporting revisions together. A lost COMMIT response or stale writer still fails closed. Failures before publication cannot corrupt live data and retain resumable work.
- Before starting another generation, delete obsolete rows in bounded batches; retain the active generation and this exact pending plan. This bounds retained live rows to two generations after cleanup, plus normal PostgreSQL vacuum overhead. Readers with an existing MVCC snapshot retain normal PostgreSQL visibility.
- Use private generations for 10,000 or more changed findings. Smaller deltas prepare their reporting through a read-only SQL overlay before the final write. Ordinary saves remain serialized behind the import; this change does not introduce concurrent platform writers.
- Identify finding progress separately from small-record/report metadata, so a restarted first import can recreate its folder without re-uploading unchanged finding progress. Private transport/cancellation failures retain dirty work and the Defender marker with a 60-second retry cooldown; uncertain final COMMITs still block until reload.
- Keep scheduled imports and tile refresh settings; do not introduce automatic patch drafts.

## Review focus

1. Crash after a committed stage batch; exact retry must not skip or duplicate records.
2. Reader during staging/final rollback; it must retain the full old generation and reports.
3. Later RAM edits and another database writer; neither may be silently overwritten or acknowledged.
4. Deleted/moved findings, equal-order IDs and untouched customers; full independent reporting digests must match.
5. Lost final COMMIT acknowledgement, cleanup, and restart; no blind replay or deletion of current data.

## Tasks

- [x] Add generation schema and shared writer compatibility. Test ordinary edits, rollback, authority fencing and old-generation reader visibility on disposable PostgreSQL.
- [x] Add checkpointed private publication and reporting preparation. Inject interruption between stage batches, resume with a new client, verify all records and independent reporting hashes.
- [x] Integrate large saves and safe retry handling. Preserve ordinary-save behavior and uncertain-COMMIT blocking; record concise stage progress.
- [x] Run the full regression suite, TypeScript, worker and Linux production builds, a production-size synthetic publication and independent code review.
- [ ] Merge through a PR, deploy the tested build/schema, publish the existing completed Defender import, verify later normal commits and current read/write health.

## Execution record

- Investigation complete; no production changes made during diagnosis.
- Existing isolated worktree reused; branch `fix/resumable-platform-publication-20261028` starts at current main `68465ba`.
- Full regression suite: 1,102 passed, seven optional database tests skipped, zero failed; TypeScript passed. Separate private PostgreSQL tests exercise real SQL and the actual TypeScript persistence entrypoint, including private and final COMMIT acknowledgement loss, rollback, restart, cleanup, ownership moves and reporting parity.
- Synthetic scale rehearsal: 1,040,000 findings, 780,002 changed/deleted/moved IDs. Migration preserved all rows and authority in 23.4 seconds. Final atomic commit took 1.49 seconds; independent complete reporting hashes matched after restart. These are private local-PostgreSQL timings, not managed-production latency claims. The logged 22.5-second stage resume measures the remaining reporting work, not the entire import.
- Exact customer/order query used `app_findings_customer_stream_idx` through the view (500 rows, zero heap fetches, 0.53 ms in the synthetic fixture).
- Independent review found and verified fixes for no-code PostgreSQL transport failures, A-to-B-to-A abandoned plan reuse, and dependent Defender risk refresh after deferred publication. No remaining code blocker reported.
- Clean Linux install initially rejected main's React 19.2.4 / React DOM 19.3.1 mismatch. Align React to 19.3.1. Both worker builds and the Next.js webpack production build then passed; the fresh Linux dependency install passed all 1,102 tests (seven optional DB skips). The separate PostgreSQL run passed all ten checks, including forward/reverse maintenance transitions.
- Production ownership was checked read-only: the application role owns `app_findings`; it has no explicit relation grants to copy. No production schema or runtime change has been made yet.

## Deployment and recovery

Build before stopping the existing app. Stop all application writers, then use the existing `install-platform-release-schema.mjs --apply --writers-stopped --env-file /opt/vuln/.env.local` installer with this release. Migration 003 is transactional, has a five-second lock wait and a 15-minute statement budget for rebuilding indexes, and is recorded by the existing checksum ledger. Install the matching build before restarting.

The old binary cannot write through the new `app_findings` view. Do not roll back only the binary after migration. Keep this generation-aware writer or use the tested, explicitly operated SQL-to-legacy authority transition with writers stopped. A failed migration rolls back its schema changes.

After restart, verify read/write readiness, the completed Defender source run equals its platform publication marker, and subsequent ordinary commits advance the authority. A private preparation retry must leave old committed data readable. Actual corruption, stale writers or an uncertain final commit remain fail-closed rather than silently acknowledging an unsaved change.
