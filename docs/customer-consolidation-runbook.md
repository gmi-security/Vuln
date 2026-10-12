# GMI and Valor customer consolidation: private clone rehearsal

The approved Vuln mappings are `CO-9150` → `CO-229336` and `CO-9153` → `CO-229438`. The first source owns Vuln folder `FLD-9152` (71 scans); the second owns `FLD-9155` (67 scans). Those `FLD-*` values are **Vuln record IDs**, not Nessus numeric folder IDs. The `CO-*` suffixes are **Vuln IDs**, not proof of ConnectWise numeric company IDs.

## Status and boundaries

- The numeric ConnectWise company IDs and numeric Nessus folder IDs are **unverified**. Keep `externalVerification` null until independent read-only evidence is captured. Never infer vendor IDs from Vuln IDs.
- `scripts/consolidate-approved-customers.mjs` accepts only the private `recovery_merge` Unix socket at `/home/codex/vuln-recovery/merge-rehearsal-26PA6Y/restore-vR3gUb/socket`, port `55483`. It has no `DATABASE_URL` fallback. It never connects to production.
- This command does not call ConnectWise, Nessus, or any other provider; start scans/imports; create tickets; launch the web app; or restart PM2.
- **Do not use the normal company merge route.** The migration does not authorize a production deployment, PR #52 merge, schema transition, or connector activation.

## Gather independent evidence

1. From a read-only ConnectWise `GET /company/companies` response, confirm the numeric `id`, exact name and ownership of `Global Market Innovators, Inc.` and `Valor Global, LLC`. Save a private evidence file and its SHA-256 digest without committing credentials or the full response.
2. From a read-only Nessus `GET /folders` response, confirm the numeric IDs, names and scan ownership of `GMI Scans` and `Valor Global Scans`. Save private evidence and a digest. Confirm the 71 and 67 Vuln scans remain attached to `FLD-9152` and `FLD-9155`.
3. Review the scanner and ConnectWise routing tables. Do not enable a route. Resolve any source-ID references or cross-customer assignments before continuing.

Use this manifest shape with the `observed` object copied exactly from `--inspect`:

```json
{
  "version": 1,
  "mappings": [
    {"sourceId":"CO-9150","sourceName":"GMI Scans","destinationId":"CO-229336","destinationName":"Global Market Innovators, Inc."},
    {"sourceId":"CO-9153","sourceName":"Valor Global Scans","destinationId":"CO-229438","destinationName":"Valor Global, LLC"}
  ],
  "expected": {"copy_the_exact_observed_object_from_inspect": true},
  "externalVerification": null
}
```

After read-only external verification, replace `externalVerification` with two rows, one per destination: `destinationId`, `connectwise` (`numericId`, exact `name`, `observedVia: "GET /company/companies"`, `evidenceSha256`), and `nessus` (`numericFolderId`, exact source `name`, `observedVia: "GET /folders"`, `evidenceSha256`). All IDs must be positive numeric values and the two vendor IDs must be distinct. A dry run can use null; commit rejects null.

## Rehearsal sequence

The verified restore `recovery_application` is an immutable comparison point. Perform the following only against the separately cloned `recovery_merge` database. Keep every application writer, scheduler, import, reporting worker and export stopped during the clone rehearsal. The command also rejects other database sessions.

```sh
node scripts/consolidate-approved-customers.mjs --inspect \
  --socket /home/codex/vuln-recovery/merge-rehearsal-26PA6Y/restore-vR3gUb/socket \
  --database recovery_merge --port 55483 --user REHEARSAL_DB_ROLE > inspect.json

node scripts/consolidate-approved-customers.mjs --dry-run \
  --socket /home/codex/vuln-recovery/merge-rehearsal-26PA6Y/restore-vR3gUb/socket \
  --database recovery_merge --port 55483 --user REHEARSAL_DB_ROLE \
  --manifest private-reviewed-manifest.json > dry-run.json
```

Copy `inspect.json.observed` into the private manifest `expected`; do not copy the wrapper. Compare `dry-run.json` with the reviewed source/destination counts, folder mappings, 93 overlap assets, 55 aliases, 104 history rows and 39,353 pending drafts. The command rejects unexpected SQL customer references, missing scan/finding links, asset collisions outside the reviewed CrowdStrike/Automate case, alias cycles, changed authority, or a changed snapshot. Inspect and dry run roll back their transactions.

If inspection reports `authority: null` or `enforced: false`, stop: the clone does not have the expected writer fence. Prepare and review the additive platform authority schema on another disposable clone, then repeat inspection. Do not install it on production as part of this rehearsal.

Once vendor IDs are independently verified, a separate clone rehearsal can commit the reviewed plan. The exact hash comes from `dry-run.json.planHash` and binds the snapshot, transformed data, lineage, history counts and external evidence. Reinspect immediately before commit; any drift requires a new manifest and review.

```sh
node scripts/consolidate-approved-customers.mjs --commit \
  --socket /home/codex/vuln-recovery/merge-rehearsal-26PA6Y/restore-vR3gUb/socket \
  --database recovery_merge --port 55483 --user REHEARSAL_DB_ROLE \
  --manifest private-reviewed-manifest.json --expect-plan-hash REVIEWED_64_CHARACTER_HASH > commit.json
```

Commit writes the transformed legacy buckets, a `customer_consolidation_runs` lineage/report row and `manualOnly=true` on the 39,353 still-pending original drafts in one transaction. It also adds one quarantine audit event per held draft. Scan and finding IDs stay fixed; overlapping CrowdStrike asset payloads and old-to-new asset IDs are in the ledger. The retained Automate asset also carries a separate CrowdStrike observation, refreshed by later imports without replacing the Automate identity or metadata. Metric rows retain their original company IDs and are displayed separately under the canonical selection. New and reused canonical drafts from both stored-findings reporting and CrowdStrike patch consolidation are marked `manualOnly`. A rerun fails because the source identities and approved snapshot no longer match. Compare the ledger, `commit.json`, counts, folder and finding references, aliases, draft status and metrics with `recovery_application` before any release decision. Exercise the existing SQL authority transition and reverse path on another disposable copy and verify hydration/reporting after restart. Do not run application or worker jobs during this rehearsal.

## Production gate and recovery

Production remains untouched. A production cutover requires a separate reviewed command or target approval, writer drain, a **fresh post-drain backup and successful restore**, independently verified vendor IDs, current route review, a new manifest from that exact snapshot, successful isolated commit and reverse rehearsals, and explicit cutover approval. Initial activation keeps reporting worker, allowlists, shadow mode and connector activation off; no scans or tickets. If a clone transaction fails, it rolls back. For a later production failure after commit, stop writers and restore the fresh post-drain backup; preserve the ledger and report as audit evidence and do not attempt an in-place inverse while writers are active.
