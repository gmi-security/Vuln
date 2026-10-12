# Approved customer consolidation implementation plan

**Goal:** Prepare an explicitly invoked, reversible migration for `CO-9150` → `CO-229336` and `CO-9153` → `CO-229438`, without touching production.

**Spec:** [PR #52 Gate 1 implementation task](https://github.com/gmi-security/Vuln/pull/52#issuecomment-6132414941).

**Architecture:** A guarded maintenance command reads the complete legacy snapshot in one database transaction, checks an immutable operator manifest, transforms only the two approved customers, and either rolls back after producing a verification report or commits to an explicitly named private restore clone. A persistent lineage ledger retains original identities and overlapping asset payloads. Runtime guards prevent the ordinary merge endpoint and implicit Nessus name matching from undoing the consolidation.

**Scope:** No production database, provider API, web server, PM2, scan, import, or ticket action. A future production cutover requires a fresh drain, backup, restore verification, and separate approval.

## Tasks

1. [x] Add focused synthetic tests for ownership, folder and asset collisions, aliases, history presentation, and generated ticket holds.
2. [x] Implement pure snapshot planning and verification with exact source/destination IDs and no unrelated-row changes.
3. [ ] Implement and exercise the private-socket maintenance CLI. Its guards, dry-run/commit transaction paths, manifest checks, ledger and report are coded and local tests pass. The recovery operator must run inspect and dry-run from the separate Vuln-NYC1 terminal; clone commit remains pending until vendor IDs are verified.
4. [x] Guard the unsafe general merge route and prevent implicit Nessus imports from recreating retired records.
5. [x] Present legacy metrics under the canonical selector with the original label and a separate series.
6. [ ] Exercise rollback, rerun, SQL forward/reverse recovery and restart consistency on a disposable clone. The operator has terminal access; Codex SSH is unavailable. External numeric IDs remain unverified. Keep the database commit, rollback, and restart checks pending until operator output is reviewed.
7. [x] Write the operator runbook and review the local diff.

## Review focus

- Mismatched scanner folder ID or ConnectWise identity must stop before any write.
- Source finding and scan IDs must remain stable, with no dangling scan/folder or finding/scan reference.
- Existing Automate asset metadata must survive a CrowdStrike identifier collision unchanged.
- Historical drafts must remain attributable and cannot become auto-created tickets after remapping.
- A second run, stale manifest, unapproved database, or unexpected customer reference must fail closed.
