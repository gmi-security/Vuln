# Defender workflow handoff: writer inventory and offline rehearsal

Reviewed October 10, 2026 against the local Vuln2.0 source after `4995b86`. This is a migration design and executable test rehearsal, not a production maintenance command. No live writer, endpoint, permission, scheduler or publication behavior has changed.

## Finding

The manual edit route calls `updateFinding`, changes the in-memory object and returns success without awaiting a database save. The six-second flusher later saves changed snapshot buckets. Import completion, scan polling, inventory/risk updates and administrative actions can also change findings. A database revision check cannot see an unsaved memory edit. Disabling one button or setting `VULN_DISABLE_SCHEDULER=true` is insufficient to establish exclusive write ownership.

## Current writer inventory

Paths below are source-code entry points, not proof that these jobs are currently running in production. References are function names so they remain useful as line numbers change.

| Writer / trigger | Current path and effect | Required handoff treatment |
| --- | --- | --- |
| Analyst status / assignee | `components/VulnFindingsPage.tsx` sends PATCH `/api/findings/[id]`; route calls `store.updateFinding`. Mutates status, resolution timestamp and assignee; marks dirty; returns before save | Stop admitting edits briefly, finish accepted operations, strictly persist and verify; route future edits through one authoritative writer |
| Defender completed import / retry | `defender-worker.ts` calls `reconcileDefenderPlatform`; `publishDefenderSnapshot` replaces/upserts findings, assets, scan and applied-run marker; reconciliation awaits `flushNow({throwOnError:true})` | Pause source publication and drain existing reconciliation, preserving source run, stable IDs, scan/inventory and marker together |
| Nessus import / scan poll | `importFromNessus`, `refreshVendorScans`, `importVendorFindings`, `correlateFinding` and `closeStaleFindings` in `store.ts` create/update assessment/evidence and resolve eligible absent findings; scan-list/detail reads can trigger polling | Admission control must cover background completion and read-triggered polling, not just POST endpoints |
| Vulners import / bridge completion | `importFromVulners`, `importFromVulnersBridge`, `runVulnersBridgeScanAsync`; findings added/correlated and stale findings resolved | Track the whole async operation through completion; stopping a timer does not cancel a task already awaiting a vendor result |
| Other source finding imports | `importFromSpiderfoot`, `importBurpFindings`, `importNmapScan`, `importFromArtemis`, `runZapScanAsync`; source records and findings created/updated | Include manual uploads, connector routes, sync-all and scan completion. These sources are not all part of the Defender projection |
| Inventory / risk / controls | `rescoreFinding`, `rescoreAllFindings`, `enrichThreatIntel`, compensating-control CRUD, Tidal/Automate/Intune/CrowdStrike inventory imports | Changes can alter the candidate's assessment and even promoted primary CVE; fence the full candidate input, not only status/assignee |
| Customer rename / merge | `updateCompany` changes names on findings/scans; `mergeCompanies` changes ownership, inventory, scans and risk | Serialize cross-customer operations against both scopes, or use a process-wide write pause for the first controlled cutover |
| Scan deletion / demo cleanup | `scanAction(...,"delete")` deletes linked findings; `purgeDemoData` deletes eligible simulated findings/scans | Include destructive lifecycle operations in the writer inventory; do not resurrect deleted records during migration |
| Administrative reset | Token-protected `/api/admin/resync` calls `resyncFromNessus`, clears several maps, imports again and restores a backup on failure | Exclude reset during handoff, including its rollback and delayed persistence |
| Hydration / startup / demo | `deserializeStore`, Defender marker repair, SpiderFoot cleanup, default migration and opt-in demo generation can change state; startup begins persistence and timers | A restart must consult durable ownership before admitting any old writer or loading a writable legacy snapshot |
| Snapshot persistence | `persistSnapshot` serializes saves in a promise chain; `serializeStore` copies collection arrays but retains finding object references; `saveSnapshot` yields while sharding/serializing and commits changed buckets atomically | Drain previous saves, use strict error propagation and compare the durable customer data to a detached capture. Do not treat a dirty boolean or successful default `flushNow()` as a handoff certificate |

The scan, source and assessment helper names above were traced in `lib/store.ts`, `lib/defender-platform.ts`, `lib/defender-worker.ts` and their route callers. Existing exported finding readers return objects from the memory store; mutable references are another reason a cooperative wrapper alone is not proof of complete writer coverage. Ticket request/reference writes remain in their existing SQL services and are outside the finding-workflow handoff; preserving IDs and customer ownership is still required for those links.

Existing access behavior remains unchanged. The finding route is covered by the existing proxy session gate; it does not currently request an expected workflow revision or durable actor/reason audit. A future route must use the existing trusted session and agreed permission policy, not accept actor identity supplied by the browser.

## Rehearsed sequence

The executable protocol lives entirely under `tests/`. It is deliberately unable to grant SQL ownership.

1. Verify both connections are private recovery/test databases before any flush callback runs.
2. Acquire the fixture's exclusive writer-admission hold. Refuse if an operation is still in flight. Hold ownership uses a unique token, so an expired holder cannot release a later hold.
3. Capture a detached, customer-scoped copy of company metadata, findings, inventory, controls and the applied Defender run. This is the complete input scope of the current Defender candidate, not every platform collection.
4. Call the real `store.flushNow({throwOnError:true})` and real PostgreSQL `saveSnapshot` implementation. This waits behind prior saves. Refuse on blocked/unavailable storage or any save error.
5. Compare the baseline read back from PostgreSQL with the memory capture, including every finding field and original resolution timestamp. Missing save acknowledgement is not sufficient: a no-op flush is rejected when memory differs from storage.
6. Build the isolated candidate with existing baseline/source checks. Verify memory again during collection, planning, each write batch and completion. A changed input refuses the rehearsal; an interrupted candidate stays failed/unreadable.
7. Always release the fixture admission hold. Successful results say `rehearsed`, `handoffAllowed:false`, `publicationAllowed:false`. The existing SQL block still rejects refresh publication.

This rehearsal does not convert old decisions into invented analyst audit events. The final saved workflow is preserved as baseline data; new versioned edits retain their explicit actor/reason contract from the preceding checkpoint. Migrated baseline provenance and conflict-review controls must remain distinguishable from a new human decision.

## Failure and rollback behavior

| Event | Rehearsal result / required release behavior |
| --- | --- |
| Active writer or save failure | Refuse before candidate publication; legacy remains owner; a later retry uses current memory |
| Some snapshot bucket writes succeed before another fails | PostgreSQL rolls the transaction back; failed hashes are not recorded as committed; retry saves the pending edits |
| Save succeeds, candidate fails | Keep the newer durable legacy snapshot. Do not restore an older backup over the user's edits. Discard/retain the failed comparison candidate according to later retention policy |
| Edit bypasses the fixture gate | Persistent changes are detected by capture comparisons and cause refusal. This is evidence of detection in tested cases, not proof that all live writers are fenced |
| Process crash before real ownership transfer | Future durable state must keep or restore legacy ownership, and require a fresh verified attempt; the in-memory fixture hold cannot provide this |
| Process crash after real ownership transfer | Future startup guard must prevent legacy writers from restarting. Reversal requires a verified export of subsequent SQL workflow changes; a Git rollback alone would lose them |

## Validation and limits

The real PostgreSQL runner passed 14 groups: the ten previous refresh/workflow groups and four new handoff groups. New cases demonstrate pending edits before flush, preservation of status/assignee/resolution time in the candidate and a fresh database reader, rollback after a final-shard failure, retry, blocked persistence, active writer refusal, rejection of new gate-controlled edits, direct mutation during flush/planning/writing, failed candidate isolation and unchanged publication. The final-shard error in the log is deliberately injected test evidence.

Thirty-nine relevant local tests and `tsc --noEmit` passed. All new code is test-only; production source and build configuration were unchanged, so a new production build was not required for this checkpoint. SQL evidence is private at `handoff-test-7zFj4z7O/fixture-final.log`. Test databases were removed and the private cluster stopped. No external API or ticket calls occurred.

These are small fixtures, not a production pause-duration or full-size memory benchmark. The prior retained-data build took about 160 seconds; holding all writers through such a build could mean minutes of unavailable writes. A shorter prebuild-plus-final-reconciliation design is possible but remains unverified. There is no actual writer-admission integration, cross-process lock, durable ownership record, crash recovery or handoff activation. A direct untracked change that is reverted between capture checks is not detectable by fingerprints; complete writer participation and a durable epoch are still required.

## Next bounded step

The next ownership checkpoint is now implemented offline; see `docs/defender-writer-ownership.md`. It adds durable phases/epochs, participant acknowledgements, same-database transaction locks and reversal preconditions. Eighteen SQL groups, 42 local tests and build/type checks pass. A fresh client retains the paused state, and terminating a backend before commit rolls back state/audit. This does not install an application startup guard or discover unregistered writers.

The thirty-first checkpoint now composes that transaction with the actual isolated editor and binds forward completion to immutable verified candidate evidence. It passes 21 SQL groups and 44 local tests plus build/type checks; see `docs/defender-writer-ownership.md`. Next validate a bounded reverse-export artifact against the legacy snapshot reader. Keep reversal/live routing blocked and do not remove the publication block until the protocol and full consumer coverage are proven.
