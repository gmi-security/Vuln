# Completed CrowdStrike reporting implementation plan

> Execute inline with superpowers:executing-plans. Existing isolated worktree; no separate deployment environment.

**Goal:** Replace the misleading 80,000-record overview with this customer's completed Spotlight summary.

**Architecture:** Attach a bounded, tenant-verified saved-source read to both reporting responses. Display its counts, severity, CVEs and completion clock together. Preserve the platform snapshot under explicitly separate details; do not combine its historical CrowdStrike subset with the source summary. No import, schema or authority migration.

**Tech stack:** Existing Next.js, TypeScript, PostgreSQL summary reader and node:test.

**Scope:** Approved reporting correction. Other customer reports, ticket workflow, saved tiles and imports remain unchanged. KEV totals are not available in the saved summary; do not reuse the historical KEV number as current.

## Checks and implementation

- [x] Test customer selection, blocked assignments, wrong-tenant responses, unavailable/pending summaries, failed reads and non-CrowdStrike customers.
- [x] Attach the existing verified saved summary to both report routes. Never call provider APIs or build summaries on page requests.
- [x] Render current CrowdStrike counts and severity from the same generation. Include unique CVEs and affected devices, suppression qualifiers and import time. Preserve platform data separately, including other sources.
- [x] Test rendering: old 80,000 is not the main count; historical timestamps are not presented as import completion; real zero is distinct from unavailable; customer switching cannot reuse prior results.
- [x] Run related reader/report tests, TypeScript and production build; review complete diff.
- [ ] PR, checks, merge and deploy using prebuilt artifacts; verify readiness, Atlas current summary and unaffected Defender reporting.

## Review focus

- A pending summary must not fall back to the old limited CrowdStrike population.
- An assignment change or tenant mismatch must withhold current counts.
- Mixed-source customers retain their platform details without summing overlapping populations.
- The import completion clock does not claim each device was assessed then.
- Failures must not turn missing data into zero or start a new import.

## Evidence

Implemented with the existing operational storedSpotlightContext/proof contract used by Top fixes; the optional saved-source preview registry is disabled in production. No connector or import configuration changed.

- Related reporting, summary, source-scope and Top fixes regression suite: 66 passed, zero failed.
- TypeScript, Next production build and both worker builds passed. Shared response types remain dependency-free for worker compilation.
- Independent review found a no-SQL compatibility case; reproduced and fixed, then reviewed again without further important findings.
- Six browser checks passed: current counts/CVEs/clock, preserved historical details, mobile layout, customer switching, pending summary, no errors or mutations. Desktop/mobile screenshots inspected locally.
- Read-only production-data test of the exact new reader: Atlas available in 382 ms; 2,500,239 open source findings, 108,286 critical, 14,192 unique CVEs, 1,502 affected devices. Import completed 2026-10-29 18:17:56.539 UTC. Footprint returned its existing platform path in 5 ms.
- Counts describe Spotlight instances, not normalized platform findings or a cross-source estate count. The existing empty-import tenant-proof limitation remains; no fabricated zero is shown. KEV totals and executive/platform reports have not been migrated.
- Remaining: PR checks, merge, deployment and post-restart readiness/API verification.
