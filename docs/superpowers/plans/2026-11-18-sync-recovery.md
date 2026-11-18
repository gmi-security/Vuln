# Nightly connector recovery implementation plan

> **For agentic workers:** Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Resume a nightly batch interrupted before Spotlight starts, without duplicate scanner actions.

**Architecture:** Store per-connector progress in the existing background_job_runs result. A PostgreSQL session advisory lock owns the scheduled batch; a restart resumes an existing running batch, including during daytime. Fresh batches retain the 9 PM Phoenix gate. Completed entries are skipped; uncertain started actions are reported as interrupted, except Spotlight, whose saved run and tenant lock support safe recovery.

**Tech stack:** Existing TypeScript, node:test and PostgreSQL. No dependencies or schema changes.

**Scope:** lib/connector-sync-batch.ts owns claims, checkpoint validation and ordered execution; lib/store.ts integrates scheduled launch and Spotlight recovery. Tests cover scheduler integration, real PostgreSQL ownership/restart behavior and provider boundaries. Manual sync keeps its existing behavior. Existing active source pointers and published findings are untouched.

**Approaches:** Replaying the whole batch risks duplicate scanner actions. Recovering only Spotlight leaves other unstarted connectors lost. Persisting a small per-connector checkpoint fixes the batch once and uses existing Spotlight reconciliation.

**Constraints:** Preserve disabled scheduling, nightly fresh-start gate, 25-minute staggering, customer routing and Spotlight tenant locks. On database/lock failure, stop launching work. Do not automatically retry completed provider failures within a nightly batch. Legacy running batches have no per-connector proof: recover Spotlight using saved run timestamps and report other actions as uncertain, without replaying them.

**Review focus:** Crash before provider call, crash after provider accepted but before checkpoint save, concurrent schedulers, database connection loss, legacy null progress and changed configuration.

- [ ] Reproduce daytime restart loss in scheduler test (RED).
- [ ] Implement durable batch claim/runner and store integration; pass scheduler and recovery tests.
- [ ] Verify PostgreSQL concurrent ownership, lock loss and actual reconnect recovery in isolated database.
- [ ] Run affected Spotlight/routing/runtime tests and Linux build; review diff independently.
- [ ] Prepare bounded deployment with pending-save guard, rollback, and concrete narrow permission if needed.
- [ ] Deploy and verify live recovery starts Spotlight; verify completed source and dashboard summary independently.

Ruling: Continue implementation under the user's existing request to fix and complete remediation; no additional design confirmation is needed. Use an isolated worktree to preserve unrelated local edits.

Ruling: Persist the Spotlight company, source connection identity (excluding secret) and approval binding before launch. If these change during restart recovery, report failure instead of redirecting work. Legacy null journals have no scope proof: under this explicitly authorized recovery, resolve the sole currently configured/approved customer, pin it before recovery, compare its saved attempt timestamps, and withhold all other ambiguous legacy actions.

Verification so far: original daytime-restart test failed before implementation; new restart and checkpoint-acknowledgment checks pass. PostgreSQL fixture verifies 12 concurrent claimants, backend termination and re-acquisition, legacy microsecond timestamps, replacement fencing and invalid journal rejection. Full Windows sweep: 1,243 pass, 10 fail, 7 skip; five semantic failures reproduced on unchanged base (Nessus contract, bridge ownership, bridge save, two bridge scheduling fixtures), four require built summary-worker artifacts, and one requires its separate disposable PostgreSQL configuration. Focused tests and TypeScript check pass. Linux production build and final review pending.
