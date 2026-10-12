# Customer primary-source and mirror review

Implemented on `Vuln2.0`; not deployed or activated in production. This records the customer's proposed endpoint source selection before SQL reporting can switch. It does not change current report totals, import routing, source credentials, ticket behavior or member permissions.

## What is recorded

A customer can have multiple configured connectors with different jobs. This review records which reviewed bindings are endpoint primary sources and whether an Elastic dataset is a confirmed copy of a particular primary source. It is separate from the connector binding review and from each adapter's operational approval.

| Customer configuration | Recorded outcome |
| --- | --- |
| One saved Defender connection | One endpoint primary; existing normalized source, workflow and report comparison still required |
| One CrowdStrike source | One endpoint primary; completed reviewed imports and live ownership acceptance still required |
| CrowdStrike plus an Elastic copy of its data | One endpoint primary plus a declared mirror; the proposed endpoint model excludes a second findings contribution |
| Independent Defender and CrowdStrike sources | Two primaries, with finding-level identity/correlation required before calculating combined totals |
| Nessus or another endpoint scanner | Source selection can be recorded, but an unsupported normalized saved-reader contract remains an explicit reporting gate |
| Inventory, OSINT, web findings, enrichment, AppSec or query-only data | Existing domain and role are retained; they are not converted into endpoint counts |

An Elastic `query-only` binding can be linked as a dataset mirror without changing its binding role or invalidating its existing saved-query approval. A binding already marked `mirror` must have a primary link. Every link requires a non-secret evidence reference. This first persisted mirror contract supports exact Elastic datasets copied from a Defender or CrowdStrike endpoint primary for the same customer. Missing targets, mirror-to-mirror/self/cross-customer links, wildcard datasets and unsupported mirror providers are rejected. Independent Elastic findings require a separate importer and lifecycle contract; a query result is not sufficient.

The operator must verify the actual customer/vendor mapping and copy pipeline. An evidence reference can identify the reviewed configuration, change record or mapping document. Equal counts, CVE overlap and customer names do not prove mirroring. The application validates the submitted relationship against reviewed bindings; it does not contact vendors or independently attest the copy pipeline. The persisted `scopeVerified` field represents this operator review, not an automatic live-verification result.

## Database and freshness

The additive [migration](sql/customer-source-selections.sql) uses the application `DATABASE_URL`, after the existing connector draft and binding migrations:

| Table | Purpose |
| --- | --- |
| `customer_source_selections` | One current reviewed or revoked selection per customer, revision, binding-set fingerprint, source evidence and explicit mirror links |
| `customer_source_selection_audit` | Atomic before/after history, actor, revision, decision, note and time |

Source evidence is derived from current metadata and reviewed bindings. It retains source IDs, provider, domain, origin hashes, proposed reader and selection fingerprint. It does not store a credential or copied finding population. Selection changes and their audit record commit together. The shared registry lock serializes binding edits and selection reviews, and expected revisions reject competing operator updates.

The complete non-dismissed binding set contributes to the fingerprint. New or removed bindings, role/scope/revision changes, stale candidate metadata and changed connection configuration invalidate the prior review. All bindings in that set must have current reviews, including separate-domain bindings; this is deliberately conservative. JSON object key order does not affect the fingerprint, including PostgreSQL JSONB round trips. Changes to actual values do.

Changing environment credentials without changing tracked non-secret metadata still needs operational verification; this feature does not introduce secret version tracking. Revocation is allowed even after source configuration becomes stale or disappears. Review/audit data must remain during rollback.

## Operator workflow

Do not run this as a production migration until it is included in the approved combined release. These commands are examples for that reviewed release procedure. No application request initializes these tables.

1. Apply the explicit migration after the existing draft/binding schema, and import fresh connector metadata through the existing registry workflow.
2. Verify and review the customer's bindings using `export-bindings` and `assign`. Keep Elastic query bindings `query-only` where they already serve saved tiles.
3. Export this customer's current source-selection request to a new private file:

```sh
node --experimental-vm-modules scripts/customer-connector-registry.mjs export-sources --env-file /opt/vuln/.env.local --company CO-EXAMPLE --output /private/path/source-review.json
```

The export contains candidate IDs, provider/role/review state, current revision, a binding fingerprint and a `reviewRequest`. It omits tenant IDs, dataset names, endpoints and credentials. Existing mirror evidence references remain in this private export; they never appear in the public customer status.

4. Copy only `reviewRequest` into a new private JSON file. Keep its revision and fingerprint. Add a non-secret note. For each verified mirror, add this shape to `mirrors`, using the IDs from the export:

```json
{
  "candidateId": "<Elastic binding candidate ID>",
  "primaryId": "<CrowdStrike or Defender primary candidate ID>",
  "evidenceRef": "<reference to verified customer and copy-pipeline mapping>"
}
```

Use an empty `mirrors` array when there is no mirror. An existing binding whose role is `mirror` cannot be silently omitted. The input is capped at 32 KiB and contains no credentials, actor field, source counts or proposed activation switch.

5. Record the review:

```sh
node --experimental-vm-modules scripts/customer-connector-registry.mjs review-sources --env-file /opt/vuln/.env.local --input /private/path/review-request.json
```

The actor is derived from the operating-system user and hostname. Exports refuse to overwrite an existing file and use restrictive creation permissions. A successful response confirms the review transaction only; it does not authorize a SQL reporting cutover, import or ticket.

To revoke, export the current revision, set `decision` to `revoked`, `bindingsFingerprint` to null and `mirrors` to an empty array, provide the reason in `note`, and submit through the same command. If another operator changed the revision, export again. No source generation, saved tile or historical ticket is deleted.

## Customer display and release limits

The existing customer Connectors page has an **Endpoint source selection** panel. It displays missing/unreviewed, reviewed, needs-review or revoked status. A current review shows primary and mirror counts and explains whether comparison, record correlation or another reader is needed. It does not expose source identities, evidence references, private audit notes or credentials. The current customer selector, stale-response protection and member permissions are retained; no browser approval control was added.

All returned plans still have `canActivate: false` and no combined platform total. This is a durable prerequisite for the remaining reporting migration. Operational importer/query permissions continue using their existing approvals and switches. Disabling or revoking this selection record alone does not stop those operations, because they do not consume it as authorization yet.

Before reporting switches: verify live customer scopes, resolve independent-source identity/correlation, include current workflow/scanner/exposure/risk context, pass customer-by-customer SQL parity and freshness checks, and complete the writer/recovery and combined deployment rehearsal. Tests and evidence are recorded in the [platform plan](platform-change-proposal.md) and [connector rollout status](connector-rollout-status.md).
