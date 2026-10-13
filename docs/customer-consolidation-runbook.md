# GMI and Valor customer consolidation: private clone rehearsal

The approved Vuln mappings are `CO-9150` → `CO-229336` and `CO-9153` → `CO-229438`. The first source owns Vuln folder `FLD-9152` (71 scans); the second owns `FLD-9155` (67 scans). Those `FLD-*` values are **Vuln record IDs**, not Nessus numeric folder IDs. The `CO-*` suffixes are **Vuln IDs**, not proof of ConnectWise numeric company IDs.

## Status and boundaries

- The numeric ConnectWise company IDs and numeric Nessus folder IDs are **unverified**. Keep `externalVerification` null until independent read-only evidence is captured. Never infer vendor IDs from Vuln IDs.
- `scripts/consolidate-approved-customers.mjs` accepts only the private `recovery_merge` Unix socket at `/home/codex/vuln-recovery/merge-rehearsal-26PA6Y/restore-vR3gUb/socket`, port `55483`. It has no `DATABASE_URL` fallback. It never connects to production.
- This command does not call ConnectWise, Nessus, or any other provider; start scans/imports; create tickets; launch the web app; or restart PM2.
- **Do not use the normal company merge route.** The migration does not authorize a production deployment, PR #52 merge, schema transition, or connector activation.
- As of this handoff, Codex has no SSH access to Vuln-NYC1. The recovery operator runs the commands below through the existing terminal. The private-clone inspect, dry run, commit, rollback, and restart checks have not yet been executed. Do not try an alternative host or production credentials.

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

## Manual Vuln-NYC1 terminal handoff: inspect and dry run only

The verified restore `recovery_application` is an immutable comparison point. Use only the separately cloned `recovery_merge` database. Keep every application writer, scheduler, import, reporting worker and export stopped during this rehearsal. The command also rejects other database sessions. Run the whole block in one Bash session under the recovery operator account. It makes a separate review checkout and writes reports only under a private recovery directory; it does not touch `/opt/vuln`.

```sh
set -euo pipefail
RUN_DIR="$(mktemp -d /home/codex/vuln-recovery/customer-consolidation-XXXXXX)"
chmod 700 "$RUN_DIR"
SOCKET=/home/codex/vuln-recovery/merge-rehearsal-26PA6Y/restore-vR3gUb/socket
test -S "$SOCKET"
git clone --branch Vuln2.0 --single-branch https://github.com/gmi-security/Vuln.git "$RUN_DIR/Vuln"
cd "$RUN_DIR/Vuln"
git checkout --detach fabbd2596b141d7a68bc4664979c077e586ac75a
test "$(git rev-parse HEAD)" = fabbd2596b141d7a68bc4664979c077e586ac75a
npm ci --ignore-scripts --no-audit --no-fund

node scripts/consolidate-approved-customers.mjs --inspect \
  --socket "$SOCKET" --database recovery_merge --port 55483 --user codex \
  > "$RUN_DIR/inspect.json"

node - "$RUN_DIR/inspect.json" "$RUN_DIR/manifest.json" <<'NODE'
const fs = require('node:fs');
const inspect = JSON.parse(fs.readFileSync(process.argv[2], 'utf8'));
if (inspect.mode !== 'inspect' || inspect.observed?.authority?.mode !== 'legacy' ||
    inspect.observed.authority.enforced !== true)
  throw Error('Stop: isolated clone lacks the enforced legacy writer fence.');
const manifest = {
  version: 1,
  mappings: [
    {sourceId:'CO-9150',sourceName:'GMI Scans',destinationId:'CO-229336',destinationName:'Global Market Innovators, Inc.'},
    {sourceId:'CO-9153',sourceName:'Valor Global Scans',destinationId:'CO-229438',destinationName:'Valor Global, LLC'},
  ],
  expected: inspect.observed,
  externalVerification: null,
};
fs.writeFileSync(process.argv[3], JSON.stringify(manifest, null, 2) + '\n', {flag:'wx',mode:0o600});
NODE

node scripts/consolidate-approved-customers.mjs --dry-run \
  --socket "$SOCKET" --database recovery_merge --port 55483 --user codex \
  --manifest "$RUN_DIR/manifest.json" > "$RUN_DIR/dry-run.json"

node scripts/consolidate-approved-customers.mjs --inspect \
  --socket "$SOCKET" --database recovery_merge --port 55483 --user codex \
  > "$RUN_DIR/inspect-after.json"
cmp "$RUN_DIR/inspect.json" "$RUN_DIR/inspect-after.json"

node - "$RUN_DIR/dry-run.json" <<'NODE'
const fs = require('node:fs');
const assert = require('node:assert/strict');
const report = JSON.parse(fs.readFileSync(process.argv[2], 'utf8'));
const sources = ['CO-9150','CO-9153'];
const total = kind => sources.reduce((n,id) => n + report.before.counts[id].source[kind], 0);
assert.equal(report.mode, 'dry-run');
assert.equal(report.externalIdentitiesVerified, false);
assert.equal(total('findings'), 106256);
assert.equal(total('scans'), 206);
assert.equal(report.before.aliasesToMove, 55);
assert.equal(Object.values(report.before.metrics).reduce((a,b) => a+b, 0), 104);
assert.equal(report.before.drafts, 39353);
assert.equal(report.assetCollisions, 93);
assert.equal(report.sourceAssetsArchived, 93);
assert.equal(report.folderMappings.filter(x => x.source.id !== x.destinationId).length, 2);
assert.deepEqual(report.orphans, {scanFolder:0,findingScan:0});
assert.equal(report.after.draftsQuarantined, 39353);
assert.equal(report.after.draftAuditRowsAdded, 39353);
assert.match(report.planHash, /^[a-f0-9]{64}$/);
console.log(JSON.stringify({result:'dry-run-validated',planHash:report.planHash,
  findings:total('findings'),scans:total('scans'),assetCollisions:report.assetCollisions,
  legacyDraftsHeldInPlan:report.after.draftsQuarantined}));
NODE
printf 'Private rehearsal files: %s\n' "$RUN_DIR"
```

The second inspect must match the first byte for byte; this checks that the dry run left the clone unchanged. The command itself rejects unexpected SQL customer references, missing scan/finding links, asset collisions outside the reviewed CrowdStrike/Automate case, alias cycles, changed authority or snapshot, and count drift. Preserve `inspect.json`, `manifest.json`, `dry-run.json`, and `inspect-after.json` privately. Share only the final compact validation line and any redacted error; the files can contain customer metadata.

If inspection reports `authority: null` or `enforced: false`, stop: the clone does not have the expected writer fence. Prepare and review the additive platform authority schema on another disposable clone, then repeat inspection. Do not install it on production as part of this rehearsal. If any command fails, stop and keep the private files for diagnosis; do not proceed to a commit.

## Pending: isolated commit, rollback, and restart

Do not run a database commit now. The numeric vendor IDs and read-only evidence are still unverified. The manifest above deliberately has `externalVerification: null`, and the command rejects `--commit` before connecting with that manifest. The initial dry-run hash is **not** a commit hash: external verification is included in the hash. Once the evidence exists, prepare a new private manifest, reinspect the clone, rerun the dry run with the verified manifest, review its new plan hash, and separately execute the isolated commit and reverse/restart rehearsals. Keep these checks pending until their output has been reviewed.

```sh
node scripts/consolidate-approved-customers.mjs --commit \
  --socket /home/codex/vuln-recovery/merge-rehearsal-26PA6Y/restore-vR3gUb/socket \
  --database recovery_merge --port 55483 --user codex \
  --manifest VERIFIED_MANIFEST_PATH --expect-plan-hash VERIFIED_DRY_RUN_PLAN_HASH > PRIVATE_COMMIT_REPORT_PATH
```

Commit writes the transformed legacy buckets, a `customer_consolidation_runs` lineage/report row and `manualOnly=true` on the 39,353 still-pending original drafts in one transaction. It also adds one quarantine audit event per held draft. Scan and finding IDs stay fixed; overlapping CrowdStrike asset payloads and old-to-new asset IDs are in the ledger. The retained Automate asset also carries a separate CrowdStrike observation, refreshed by later imports without replacing the Automate identity or metadata. Metric rows retain their original company IDs and are displayed separately under the canonical selection. New and reused canonical drafts from both stored-findings reporting and CrowdStrike patch consolidation are marked `manualOnly`. A rerun fails because the source identities and approved snapshot no longer match. Compare the ledger, `commit.json`, counts, folder and finding references, aliases, draft status and metrics with `recovery_application` before any release decision. Exercise the existing SQL authority transition and reverse path on another disposable copy and verify hydration/reporting after restart. Do not run application or worker jobs during this rehearsal.

## Production gate and recovery

Production remains untouched. A production cutover requires a separate reviewed command or target approval, writer drain, a **fresh post-drain backup and successful restore**, independently verified vendor IDs, current route review, a new manifest from that exact snapshot, successful isolated commit and reverse rehearsals, and explicit cutover approval. Initial activation keeps reporting worker, allowlists, shadow mode and connector activation off; no scans or tickets. If a clone transaction fails, it rolls back. For a later production failure after commit, stop writers and restore the fresh post-drain backup; preserve the ledger and report as audit evidence and do not attempt an in-place inverse while writers are active.
