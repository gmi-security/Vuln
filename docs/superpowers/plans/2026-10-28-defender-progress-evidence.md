# Defender progress evidence retention

> Execute inline with superpowers:executing-plans and test-driven development.

**Goal:** Preserve valid earlier Defender disappearance verification as later imports complete, while fresh positive results invalidate that clearance.

**Architecture:** Reuse the existing bounded comparison worker and JSON observations. Reconstruct earlier absence from the source import referenced by the published finding, including customer, connection revision, completion, device check-in and raw CVE absence. Retain that proof with its original date in completed ticket observations so source pruning does not erase it. No new tables or provider calls.

**Tech stack:** TypeScript, PostgreSQL, existing React progress component.

**Spec:** `../specs/2026-10-28-patch-progress-design.md`; approved correction in the October 28 conversation: retain verified fixes, compare evidence rather than import membership alone, detect returns, clarify waiting states, recalculate and test before deployment.

## Constraints and decisions

- Only customer/device/CVE and ticket scope matches may reuse evidence.
- A workflow Resolved label alone never proves remediation.
- A completed matching current publication is required. Connection revision changes invalidate old proof.
- Current positive source records always prevent carrying forward an old clearance, even if fresh device assessment is unavailable.
- Earlier absence requires device evidence after ticket creation, no later than its completed import, and no CVE in that import.
- Preserve original evidence dates; do not present the new comparison date as a new device assessment.
- Keep CrowdStrike/Nessus behavior, ticket contents, source import retention, findings, scheduler and credentials unchanged.
- Prefer saved source evidence plus compact proof over re-downloading data or trusting resolved labels. The user approved this approach.

## Task 1: Evidence and display correction

Files: `lib/patch-progress.ts`, `lib/patch-progress-sources.ts`, `components/PatchProgress.tsx`, `tests/patch-progress-sources.test.mjs`, `tests/patch-progress-postgres.mjs`.

- [x] Add failing tests: older completed source absence survives import changes; stale/pre-ticket/missing device evidence cannot clear; positive reappearance defeats old proof; changed customer/revision/scope and manual resolution cannot clear; retained proof survives pruning and repeat evaluation.
- [x] Extend observations with bounded Defender verification proof and retained-evidence indication. Keep source lookups ticket-sized and transactional.
- [x] Show original evidence dates, identify retained verification, and clarify the waiting state.
- [x] Run targeted tests, real disposable PostgreSQL integration tests, full `node --experimental-vm-modules --test tests/*.test.mjs`, TypeScript and production webpack build.
- [x] Review complete diff and address material issues with regression tests.

## Task 2: Release and recalculate

- [ ] Use a PR merge; verify the merged build before replacing production build output.
- [ ] Preserve runtime configuration; use the existing deployment process.
- [ ] Recalculate saved ticket progress through the worker; verify Footprint counts, dated evidence, CrowdStrike compatibility, API/customer isolation, write readiness and public health.
- [ ] Record actual results and remaining limits here.

## Review focus

Old raw imports may be pruned; a returned CVE must override retained proof; a source configuration change must not reuse foreign evidence; before-ticket negative evidence cannot clear a ticket; repeated reads must remain bounded and idempotent.

## Evidence

Read-only diagnosis: the affected group includes historical completed source negatives with post-ticket device observations. Tests and recalculation will determine the final counts; no status-only bulk reclassification is permitted.

Validation completed October 28:
- 13 targeted tests passed; the full suite passed 1,116 with 7 optional DB skips and zero failures. Separate real PostgreSQL integration checks passed, including 10,001-row retry/pagination, customer isolation, reappearance, incomplete publication, scope changes and source pruning.
- Observed red-to-green failures for original older-import rejection, incomplete-publication replacement, millisecond precision, and cleanup between device deletion and run deletion.
- Independent review identified that cleanup race; matching saved proof now survives the intermediate state, while contradictory positive data still prevents clearance. No other blocking findings reported.
- TypeScript and Linux production webpack build passed.
- Read-only production comparison completed in 157 ms: 373 original devices, 113 detected, 194 clear, 66 unknown; 104 retained earlier verifications. Forty lacked post-ticket device evidence; the other 26 lacked qualifying earlier verification. This was a dry run, not a production write.
- Retained evidence remains dated evidence of source absence, not proof of patch installation or a current device assessment. Browser interaction/visual checks are still pending.
