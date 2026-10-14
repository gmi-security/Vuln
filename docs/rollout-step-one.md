# Vuln2.0 rollout readiness - October 14, 2026

## Current decision and scope

Step one prepares the candidate for merge review. It does not merge, deploy, reset production tickets, change production settings or contact providers. The final merged commit must still pass its build and required checks before deployment.

The operator's latest decisions supersede conflicting deployment requirements in the older combined-release, customer-consolidation and Gate 3.4 documents:

- New backups and full restore rehearsals are waived, not passed. Existing recovery artifacts remain intact.
- **Keep existing customer records for this rollout**, including GMI Scans and Valor Global Scans. Do not execute their consolidation command or move their records to parent companies. The new layout and SQL authority do not require that optional consolidation.
- Preserve current customer IDs, connector assignments/configuration/credentials, saved tiles and role permissions. Importing configuration evidence does not automatically approve a new operational route.
- Old tickets were deleted in ConnectWise only. Retire local historical requests before starting the new release so those requests cannot be replayed. Automatic ticket creation remains paused.
- The initial rollout includes the Remediation layout and SQL platform store. Saved-report worker activation and reviewed connector routing remain separately scoped, as below.

## Completed preparation

- [x] Read-only production inventory: 40 customers, 431 recorded scans/imports and eight tiles without a recorded customer owner. All 16 saved query definitions remain present. No ownership was guessed or changed.
- [x] Read-only ticket inventory and supported-schema preflight. Production has five single-CVE requests, 156,727 group requests, 19 single-CVE audit records and 187,264 group audit records. These counts are observations, not a frozen deployment manifest.
- [x] Maintenance-only ticket fresh-start command prepared. It moves the four request/audit tables into `patch_ticket_history_vuln2` and creates empty active equivalents in one transaction. Historical rows retain their original table identities; there is no data export or vulnerability-data copy.
- [x] Real PostgreSQL validation passed all 11 test groups: changed-plan refusal, other-session refusal, dependency/unsupported-permission refusal, actual SQL failure rollback, original table identity retention, new writes/indexes/sequences/permissions, configuration preservation, old-ID API refusal and repeat refusal. Provider calls: zero. Production writes: zero.
- [x] Independent targeted review completed. Both Important findings were fixed and regression-tested: inherited database URL ambiguity and unsupported column ACL loss. Identity/customized sequences now fail closed; table/sequence grants, including explicitly revoked owner privileges, are preserved. This was not an exhaustive review of every historical branch change.
- [x] PR #50 dependency reviewed. Both automatic-create entry points respect `ATLAS_AUTO_CREATE_PAUSED = true`. PR #50 remains separate; it must be reviewed/merged before automatic ticket creation is considered for activation. Nothing in this release unpauses it.
- [x] Existing runtime validation retained: TypeScript and production/worker builds, 49 optional database tests, 26 database/integration scripts, four built-app HTTP groups and 29 browser groups. The application runtime is unchanged since the validated `e958198` revision; later changes are recovery tooling/docs/tests and this operator-only addition. Counts overlap and must not be added together.

Fresh regression results and the exact published commit are recorded in the release evidence next to this checkout and in the completion handoff. The current full regression run has 840 passing tests, no failures and seven optional DB tests skipped; the earlier separate DB run covered those optional tests. Skipped cases are not reported as freshly rerun.

The retained built-app HTTP rehearsal used synthetic customer records without customer consolidation. It verified customer-isolated reports, a real analyst edit committed to SQL, app restart, and preservation of that edit after the reverse transition. Prior retained-data migration/reporting checks included all stored source payloads, not only Defender. Those results do not assert current external-provider availability.

## Ticket fresh-start procedure for the later maintenance window

Run from the reviewed release checkout. Stop all application/background writers, freeze mutation ingress and drain their connections first. The session check is point-in-time; it does not stop another process from reconnecting. Do not claim the `--writers-stopped` argument itself proves maintenance isolation.

Inspect in a clean target environment:

```bash
env -u DATABASE_URL -u ELASTIC_VULN_DATABASE_URL node -- scripts/ticket-fresh-start.mjs --inspect --env-file /opt/vuln/.env.local
```

Review the printed database address/name/role/OID, four table counts and configuration hash. Use only the plan hash from that inspection after all earlier maintenance mutations have finished:

```bash
env -u DATABASE_URL -u ELASTIC_VULN_DATABASE_URL node -- scripts/ticket-fresh-start.mjs --apply --writers-stopped --expected-plan REVIEWED_PLAN_HASH --env-file /opt/vuln/.env.local
```

`REVIEWED_PLAN_HASH` is a placeholder, not a runnable value. The command refuses a changed plan, other database sessions, an unexpected owner/schema/dependency, unsupported column permissions or sequences, and repeat use. Any failure before commit rolls back the table moves and replacements. Keep maintenance active after an error; do not remove guards or manually delete the history schema.

The command touches only the four ticket request/audit tables and their replacement indexes/sequences. It fingerprints the configuration/routing/customer metadata it must retain. It makes no ConnectWise calls. Existing historical request IDs become unavailable through the current ticket APIs, including create, reopen, reconcile and attachment retry. Preparing a new request uses a new ID.

## Initial activation scope

| Area | Initial rollout behavior |
| --- | --- |
| Customer records and source credentials | Preserve current records/configuration, including separate GMI Scans and Valor Global Scans records. |
| Remediation layout | Enable `VULN_REMEDIATION_UI=true`; keep existing role/configuration permissions. |
| Platform authority | Switch with the existing verified transition command after schema installation; set `VULN_PLATFORM_STORE=sql` only after it commits. |
| Automatic ticket creation | Keep the existing code pause in place. Do not replay or reconcile retired requests. |
| Reviewed connector routing | No new provider allowlists and no wildcard activation. Existing configured paths remain available; customer ownership review does not silently change routing. |
| Saved reporting reads/worker | Keep `VULN_REPORTING_SQL_READS`, `VULN_REPORTING_WORKER_ENABLED` and `VULN_REPORTING_EXECUTIVE_ENABLED` off initially. Enable only for reviewed customers after a separately configured worker has published matching reports. |
| Source-summary and shadow experiments | Keep `VULN_SAVED_SOURCE_READS` and `VULN_SHADOW_CVE_READS` off. |
| Jobs | Keep schedulers/imports paused during migration/startup checks; resume only reviewed existing jobs afterward. A general scheduler flag alone does not stop every job. |
| Unconfigured connectors | Burp, Nmap, Intune, IntelOwl and n8n remain available but disabled. Previously accepted Artemis/ZAP availability limits remain visible. |

The layout/database release does not depend on creating new customer bindings. Existing explicit assignments are preserved; eight ownerless tiles stay intact and are not automatically attributed to a customer.

## Remaining rollout steps

1. Review and merge PR #52 into `main`. Do not merge PR #50 as an implicit side effect.
2. Build and run the required checks on the **exact merged commit**, in a separate release directory without altering the live `.next` build.
3. During authorized maintenance, verify effective environment/process/job ownership, stop/drain writers, install the additive schema, perform the inspected ticket fresh start and transition the platform authority to SQL. Preserve secrets/configuration in place. No new backup is required under the operator's waiver. **Do not run customer consolidation.**
4. Start one compatible writer with the reviewed flags. Verify hydration, customer counts/source ownership, saved tiles, a durable analyst edit and the empty active historical ticket queue. Resume reviewed jobs and reopen access after application checks.

Deployment-time target identity, epoch/revision, connection drain and current configuration checks cannot be pre-certified while production continues running. They are explicit maintenance preconditions, not missing restore work. If a migration fails, keep the writers stopped and diagnose its actual result.

SQL still feeds the application's RAM compatibility cache; bulk imports can delay compatibility reads. This release does not claim every page is now a direct SQL query. A code rollback after SQL writes requires the compatible reverse transition, not a Git reset alone. Resync cannot recreate analyst edits or configuration, so the waiver is not a claim that every record is replaceable.

Full-data post-consolidation restart/fault/restore exercises remain unverified and outside this rollout because consolidation is deferred. Historical ConnectWise reconciliation remains incomplete; it is not relabeled as passed. The revised fresh-start behavior prevents those local requests being reused instead.
