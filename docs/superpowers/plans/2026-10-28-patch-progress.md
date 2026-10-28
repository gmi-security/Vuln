# Patch progress implementation

Approved spec: `docs/superpowers/specs/2026-10-28-patch-progress-design.md`.

## Global constraints

Keep the customer selector, worklists, ticket workflow and connector schedule. No ConnectWise writes. No provider requests on page loads. No comparison inside platform publication. Use exact original device/CVE membership and published assessments; missing evidence is unknown. Never infer remediation from a closed ticket or a lower total.

## Tasks

1. **Evidence model** (`lib/patch-progress.ts`, `tests/patch-progress.test.mjs`). Normalize existing single/group ticket scope with exact compact coverage, evaluate positive/covered-negative/unknown observations, aggregate multi-CVE devices and retain reappearance. Test missing and stale evidence, unsupported/mixed sources, incomplete membership and customer mismatch before implementation.
2. **Source adapters and saved history** (`lib/patch-progress-sources.ts`, `lib/patch-progress-store.ts`, `docs/sql/patch-progress.sql`). Read committed Defender, Nessus and reviewed Spotlight evidence in bounded batches. Use source generation and scope identity. Save complete ticket evaluations atomically, idempotently, with paginated details and dated summaries. Capture customer total and source breakdown after completed imports. CrowdStrike follows the user's disappearance-as-Fixed override; other sources require device coverage. Schema is additive and installed through the release manifest.
3. **Background integration and API** (`lib/patch-progress-worker.ts`, `instrumentation.ts`, `app/api/elastic-dashboard/patch-progress/route.ts`). Worker-only, staggered, one run at a time, bounded tickets/records/time. Page requests only read saved results. Preserve failed/pending versus completed distinctions, customer isolation and bounded response size. Do not use legacy automatic ticket closure/reopening jobs.
4. **UI** (`components/PatchProgress.tsx`, `components/CustomerReportingPage.tsx`). Customer Overview shows dated source trends; Tickets shows original devices, still detected, no longer detected, unverified, assessment time and expandable paginated device/CVE evidence. Keep ticket status separate. Show unavailable history and baseline explicitly. New devices are outside the original ticket denominator.
5. **Verification and review**. Run targeted regression tests, TypeScript, build, SQL lifecycle tests with an isolated PostgreSQL database, then a fresh reviewer. Record actual evidence and limitations. No production release before checks pass.

## Interfaces

`ProgressScope` contains customer, ticket identity, original pairs with source/host/CVE/finding ID, baseline time and an optional scope failure. `ProgressObservation` is per pair: state, reason, assessment time and evidence identity. `ProgressSummary` counts devices (not rows), using positive > unknown > clear precedence. Store immutable completed evaluations; API returns only customer-filtered summaries/details. Worker failures retain earlier evidence and mark the latest check pending/failed, never silently reuse it as current.

## Execution record

- Design approved by user on 2026-10-28. Existing isolated branch reused; unrelated scratch files preserved.
- User correction during implementation: CrowdStrike disappearance from the next completed, matching customer import counts as Fixed. Details must say no longer reported by CrowdStrike; partial/failed imports and changed scope remain unverified. This overrides the original design's stricter CrowdStrike absence rule only.
- User addition: track the total open count for every customer's import sources. Overview now combines committed normalized platform findings with the complete saved CrowdStrike summary, excluding CS's legacy platform copy when that summary is used. The chart includes a connector breakdown and explicitly qualifies possible source overlap. It counts open findings, not unique CVEs.
- History starts at the first successful collection. No invented past counts or device-level transitions.
- Tasks 1–4 implemented. No changes to platform save transactions, ticket creation or automatic ticket status changes.
- Independent final review found four important edge cases: raw CrowdStrike CID casing, missing Nessus scope pins, legitimate zero CrowdStrike imports, and an older-created scan completing later. Regression cases failed on the previous implementation and passed after fixes. Final self-review also caught partial trend writes, an older Nessus scope authorizing a newer unpinned scan, and uppercase vendor status normalization; all have verified failure-then-pass SQL tests.

## Validation evidence — 2026-10-28

- Real isolated PostgreSQL 18: saved published Defender evidence; exact original device/CVE membership; reappearance; idempotency; customer isolation; refusal of older writers; failure/retry after staging 500 of 10,001 device rows; bounded 100-row detail pagination; generic customer trend; atomic total/source inserts; out-of-order scan completion; reviewed Nessus scope; case-insensitive CS tenant/status normalization; complete zero CS count; failed-import refusal. Final private database `patch_progress_test_f3` passed all checks. This database uses synthetic data and a private Unix socket; production was not migrated. The private PostgreSQL test service was stopped after verification.
- Read-only production count timing: approximately 2.34 seconds for Footprint's 629,130 open platform findings, inside the worker's five-second per-query budget. This is an observed query timing, not a completed production feature test.
- Browser interaction/visual QA unavailable: the browser inventory returned no available browsers. A local synthetic preview harness was prepared, but no browser result is claimed.
- Final unit/regression suite: `node --experimental-vm-modules --test tests/*.test.mjs` — 1,113 passed, 7 optional database tests skipped, 0 failed (1,120 total). The explicit PostgreSQL tests above ran separately; they are not represented by those optional skips.
- Release migration `--plan` succeeded. The patch-progress migration is additive and uses the existing checksum-tracked installer.
- Final production build: `npm run build -- --webpack` passed, including TypeScript and the new dynamic progress API route. `git diff --cached --check` passed.

## Release behavior and limits

- User clarified disappearance-based CrowdStrike fixes again on 2026-10-28. The whole-import `localPlaceholderRows===0` restriction was incorrectly treating the importer's intentional no-longer-returned tombstones as failed evidence. Remove that restriction for both reviewed and existing legacy generations. Preserve completed/count/customer checks, the import-start-after-ticket requirement, suppression handling, and per-device all-CVE aggregation. Real PostgreSQL regression tests failed before the fix and passed after it for both import formats, including suppression and old-import checks. No source import, finding, ticket or schema is changed by this correction.
- Disappearance correction validation: isolated PostgreSQL regression suite passed after verified before-fix failures; full unit/regression suite passed 1,113 with seven optional DB skips and zero failures; Linux production webpack build passed including TypeScript. The explicit PostgreSQL suite ran separately from the skipped optional tests.

- Deployed PRs #93 and #94 on 2026-10-28. Additive schema installation succeeded; saved trend and comparison results survived the compatibility restart. Authenticated Overview/Tickets HTTP responses, 100-row detail pagination and cross-customer detail isolation passed. Public login and application read/write health passed. Browser interaction/visual QA remains unavailable.
- Live large-ticket checks exposed a missing all-status Spotlight read index: the open-only remediation index cannot serve comparisons that also inspect closed/suppressed rows. `EXPLAIN` selected a generation-wide primary-key scan and comparisons timed out. The explicit concurrent index below completed in 321 seconds without downtime, is valid/ready, and occupies 1,505 MiB. A real 250-pair comparison used the new index and completed in 4.1 ms. Derived failed comparisons were queued for the normal background worker; source findings and ConnectWise tickets were unchanged.

- Live deployment verification found that the production CrowdStrike source still uses checkpoint version 3 and legacy customer-owned summaries, as the existing Top fixes view does. The compatibility follow-up uses that same validated whole-generation CID/count evidence when reviewed routing is disabled. Reviewed routing retains its strict version-4 binding checks. A legacy empty generation without CID evidence remains unverified. Regression tests reproduce the production configuration, verify its counts and ticket evidence, and reject a different ticket CID.

- Apply the additive `patch-progress` SQL through the existing release migration manifest. Install `docs/sql/patch-progress-read-indexes.sql` separately, outside a transaction, on the Spotlight database before enabling comparisons. Then deploy the verified build and restart the separate worker.
- The worker starts six minutes after worker-runtime startup, checks every minute, handles ten customers and at most two ticket comparisons per pass, and revisits a ticket no sooner than 30 minutes. A database lease prevents overlapping workers. Existing scheduler pause settings are respected.
- Pages only read saved history. Refresh does not trigger a provider import or heavy comparison. Overview displays the last 90 recorded points per source. Tickets are paginated 20 at a time; details 100 at a time, within scrollable tables.
- Failed/incomplete imports do not produce a zero improvement. A valid completed zero import does. Total and connector breakdown publish in one atomic statement.
- Customer totals cover normalized vulnerability findings from any connector plus a scoped complete Spotlight generation. Attack-surface-only sources and arbitrary Elastic saved queries are excluded. Different vendors can describe overlapping findings; the UI discloses this rather than claiming an estate-wide unique count.
- Ticket verification supports CrowdStrike, Defender and Nessus. Old Nessus imports lack the new scope pin; a subsequent completed reviewed import is needed for verification. Unsupported ticket sources or inadequate original scope remain unverified/baseline unavailable.
- Original ticket packets over 8 MiB, over 100,000 device/CVE pairs, or customer scan history over 10,000 scans exceed the initial bounded collector. An incomplete comparison keeps prior results and a visible pending/error state. Nessus additional-device counting is not available in this pass.
- Current and previous detail sets are retained; summary and state-transition history remain. Closing a ticket never proves scanner remediation; this feature performs no provider requests or ConnectWise mutations.
