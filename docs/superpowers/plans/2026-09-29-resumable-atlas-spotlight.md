# Resumable Atlas Spotlight Import Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Resume Atlas Spotlight imports after request failures or app restarts without repeating committed hydration work.

**Architecture:** Persist query IDs and cursor first; hydrate that durable ID set with a second checkpoint. Promote only when the staged ID and full record counts match. The existing active pointer remains unchanged until then.

**Tech Stack:** Next.js 16, TypeScript, `pg`, PostgreSQL, Node test runner.

**Spec:** `docs/superpowers/specs/2026-09-29-resumable-atlas-spotlight-design.md`

## Global Constraints

- Store every distinct CrowdStrike vulnerability source ID and its full raw payload.
- Use `DATABASE_URL`, select the named tenant through its company binding, and exclude the unnamed primary tenant.
- No reporting, ticket, or in-memory scan changes.
- Do not promote partial generations or silently drop an unhydrated ID.
- Keep candidate ID and record batches bounded; no complete tenant collection in Node memory.
- Apply additive schema against a restored database before production rollout.

## Review Focus

- A crash after IDs commit but before a response must not skip a page or duplicate an active record.
- A crash after records commit but before the worker reports progress must resume from the committed cursor.
- A saved `after` token rejected by CrowdStrike must restart discovery without promoting a mixed ID set.
- A missing entity ID must fail the run and preserve the old active pointer.
- A repeated POST after process restart must resume the correct tenant and not start a concurrent competing run.

---

### Task 1: Separate Spotlight discovery and hydration

**Files:** `lib/crowdstrike.ts`, `tests/crowdstrike-sync-resilience.test.mjs`.

**Interfaces:** `createSpotlightSession(config)` returns `queryPage(after)` and `hydrateIds(ids)`, sharing token renewal. The existing streaming generator continues to work through the same session.

- [ ] Add tests for bounded ID pages, matching hydrated source IDs, and token renewal across both operations; observe a failing test.
- [ ] Implement the session and keep existing generator behavior.
- [ ] Run the focused CrowdStrike tests and typecheck.

### Task 2: Durable stage and checkpoints

**Files:** `lib/spotlight-record-store.ts`, `tests/spotlight-record-store.test.mjs`.

**Interfaces:** `beginOrResumeSpotlightRun`, `saveSpotlightIdPage`, `nextSpotlightHydrationIds`, `writeSpotlightHydrationBatch`, `abandonSpotlightDiscovery`, and `completeResumableSpotlightRun`. Add `spotlight_import_ids` and additive checkpoint columns to `spotlight_import_runs`.

- [ ] Add failing tests for resume selection, atomic ID page and cursor, atomic record batch and hydration cursor, and exact promotion.
- [ ] Implement bounded SQL methods and safe pruning of old ID rows.
- [ ] Run focused storage tests; validate SQL against an isolated restored database before production use.

### Task 3: Resume-aware orchestrator and status

**Files:** `lib/spotlight-resumable-import.ts`, `lib/store.ts`, `app/api/crowdstrike/spotlight-import/route.ts`, `tests/spotlight-resumable-import.test.mjs`.

**Interfaces:** `runResumableSpotlightImport(selection, deps, onProgress)` performs discovery, hydration and promotion. A POST resumes a saved run; GET reads durable status if process-local state reset.

- [ ] Add failing tests for interruption during each phase, invalid saved cursor, missing hydrated ID and active-pointer preservation.
- [ ] Implement the orchestrator and route wiring without changing reporting or tickets.
- [ ] Run focused tests and typecheck.

### Task 4: Release gate and operational rehearsal

**Files:** `docs/spotlight-storage-release-gate.md`, `docs/db-migration-inventory.md`.

- [ ] Document checkpoint fields, operator resume steps and exact completion evidence.
- [ ] Run all 31+ test files, typecheck, production build and `git diff --check`.
- [ ] Test additive SQL and a stopped/resumed import against an isolated restored database.
- [ ] Push the branch for deployment only after local verification; keep the first Atlas production run as an explicit operator action.
