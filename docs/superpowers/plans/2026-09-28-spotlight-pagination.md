# Spotlight Pagination Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Collect every Atlas Spotlight page without a fixed finding cap, while failing visibly on broken cursor pagination.

**Architecture:** `spotlightListFindings` remains the single Falcon API boundary used by the app import and diagnostic route. Query IDs by cursor until the API ends the sequence, hydrate small batches with bounded concurrency, and return a complete result or an error; the store must never receive an apparently successful partial collection.

**Tech Stack:** TypeScript, Node test runner, CrowdStrike Spotlight REST API.

**Spec:** The user's Atlas `CO-147284` scan `SCAN-149057` displays exactly 80,000 findings; the former 200-page guard caused that value. CrowdStrike query pagination uses 400 IDs per page and an `after` cursor.

## Global Constraints

- No production credentials are available locally; test API behavior with controlled HTTP responses.
- Preserve the existing company-to-scan import and transactional dashboard database separation.
- An incomplete collection is an error, never a completed scan count.

## Review Focus

- Page 201 must be collected, catching a reintroduced 200-page cap.
- A repeated cursor must fail, catching a non-progressing API.
- An empty page with a continuation cursor must fail rather than silently finish.
- Hydration must not silently omit IDs returned by the query.
- Existing import callers and TypeScript build must remain valid.

---

### Task 1: Complete API pagination

**Files:** Modify `lib/crowdstrike.ts`; test `tests/crowdstrike-sync-resilience.test.mjs`.

**Interfaces:** Preserve `spotlightListFindings(config: FalconTenant): Promise<SpotlightListResult>`.

- [x] Add an Atlas regression fixture with 5,001 cursor pages and verify it fails on the current 5,000-page guard. The old 200-page cap was already removed in commit `524da85`.
- [x] Remove the fixed page count; follow cursors until exhaustion and hydrate in bounded batches.
- [x] Reject repeated or non-progressing cursors and incomplete hydration.
- [x] Run the focused tests and TypeScript check.

### Task 2: Verify app boundary

**Files:** Inspect `lib/store.ts`, `app/api/crowdstrike/spotlight-import/route.ts`, and the scan route; update tests or code only if the result can be marked complete after an API error.

- [x] Confirm failed API collection does not overwrite the existing Atlas scan count or completion time: `importFromCrowdstrikeSpotlight` catches the collection error and skips that tenant before the per-item scan update loop.
- [x] Run the full tests and production build.
- [x] Commit on the current branch; leave production resync to the operator with credentials.
