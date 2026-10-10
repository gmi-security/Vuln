# Reviewed customer routing for Spotlight findings

Development on `Vuln2.0` only. No production migration, configuration switch, import or deployment has been run for this change.

## What it does

Spotlight can import vulnerabilities into an explicitly approved existing customer using one Falcon configuration and its verified 32-character CID. Customer names do not choose the destination in this mode. The existing source tables and completed-generation pointer remain the storage path; this does not complete the normalized platform writer migration.

```text
Configured Falcon connection + independently verified customer CID
  -> review findings-primary customer binding
  -> separate Spotlight operational approval (audited)
  -> enable the Spotlight provider switch at release
  -> recheck current assignments and select one approved customer
  -> discover IDs and hydrate records into an unpublished generation
  -> verify returned CIDs, approval and whole-generation identity/counts
  -> atomically replace that customer's completed source pointer
```

Host inventory approval does not grant Spotlight import permission. A binding with `inventory`, `mirror` or `query-only` authority cannot authorize it. Targets and datasets must be empty because this adapter imports the configured tenant's existing open/reopen partitions, not a restricted subset. One active CID and one connection can have only one customer owner. A database guard prevents inventory and Spotlight approvals from assigning that CID or connection to conflicting owners, in either approval direction. This source store supports one active Spotlight generation per customer, so a customer cannot approve two Falcon connections here; combining child tenants requires a separate design.

## Operational behavior

- With `VULN_REVIEWED_SPOTLIGHT_PROVIDERS` empty, the existing named-tenant import selection and saved CVE behavior remain. Empty is **not a kill switch**.
- With `crowdstrike` selected, all enabled Spotlight approvals must be current. Missing storage, stale evidence, unsupported scope, missing customer or conflicting assignments stop the import. There is no fallback to names.
- With multiple approved customers, the request must select a company ID. An unscoped sync-all Spotlight action reports this requirement instead of choosing the first tenant. The existing single-customer action is unchanged.
- Collection rejects missing/foreign CIDs and error-bearing success responses. The source adapter can still generate exact closed placeholders for discovered IDs that no longer resolve. A vendor-supplied placeholder cannot bypass its CID check.
- Publication scans the full staged generation. Each row must belong to the selected company and have the approved CID/source ID, or be an exact local closed placeholder. There must be at least one real CID-bearing record. Empty and placeholder-only results are withheld, preserving prior results; this is an evidence limit, not a claim of zero open findings.
- Existing discovered-ID, record-count and duplicate/extra/missing-record checks still apply. These establish collection consistency, not an atomic CrowdStrike snapshot.
- The importer checks current configuration/binding before publication, then checks approval revisions under the registry advisory lock in the promotion transaction. Revocation or binding changes prevent promotion. In-flight upstream requests are not canceled immediately.
- Concurrent discovery failure now drains the other partition before releasing its worker lock. A sibling cannot keep writing after the worker releases the lock.

The same switch also protects saved CrowdStrike CVE details, manual preparation and new ticket delivery. See [saved CVE evidence and rollout requirements](customer-stored-cve-routing.md). Existing version-1/2/3 generations remain stored but cannot authorize these reviewed operations; complete a version-4 reviewed import first.

Customer Connectors displays inventory and Spotlight approval separately without exposing CIDs, credentials or audit notes. An approved route is not proof of live connectivity or a successful import. Access roles and shared operational controls are unchanged.

## Database and resumability

All tables below use the application `DATABASE_URL`.

| Table | Purpose |
| --- | --- |
| `customer_connector_drafts` / `customer_connector_bindings` | Current sanitized source evidence and reviewed customer scope; their inactive-proposal constraints remain |
| `customer_spotlight_routes` | Separate operational approval pinned to the binding revision/hash, CID and customer |
| `customer_spotlight_route_audit` | Before/after approval state, operator, note and timestamp |
| `spotlight_import_run_scopes` | Immutable source pin for a reviewed import generation |
| Existing Spotlight runs, partitions, IDs and records | Staged source collection and resumable discovery/hydration |
| `spotlight_import_current` | Last completed generation visible to source readers |

Reviewed imports use checkpoint version 4. Its pin includes the candidate, customer, CID, source evidence and binding/approval revisions. Changing that pin starts a fresh generation. Legacy version-3 generations cannot be adopted by the reviewed path, and the updated legacy path cannot resume version 4. Partition keys must also agree. Configuration changes and source ownership transfers require imports to be drained first; this does not move or delete historical customer data.

## Release preparation - do not run in production yet

1. Preserve the recovery point and reconcile running import owners. Install `customer-connector-drafts.sql` and `customer-connector-bindings.sql` if not already installed, then inventory routes v1/v2 and the explicit [Spotlight routing migration](sql/customer-spotlight-routes.sql). The existing Spotlight source schema must already exist. These are ordered migrations, not startup initializers for the routing tables.
2. Use the [registry workflow](customer-connector-registry.md) to import fresh evidence and review the exact Falcon binding. Independently verify its CID and customer. Set `authority` to `findings-primary`, `tenantId` to the 32-character CID, and leave targets/datasets empty.
3. Export existing operational revisions:

```sh
node --experimental-vm-modules scripts/customer-connector-registry.mjs export-spotlight-routes --env-file /opt/vuln/.env.local --company CO-EXAMPLE --output /private/path/spotlight-routes.json
```

4. Create one private approval JSON with exactly these fields, using the current binding revision and current route revision (`0` only if there is no route):

```json
{
  "candidateId": "<source candidate ID from binding export>",
  "companyId": "CO-EXAMPLE",
  "bindingRevision": 1,
  "expectedRevision": 0,
  "enabled": true,
  "note": "Verified this Falcon connection and CID belong to this customer"
}
```

```sh
node --experimental-vm-modules scripts/customer-connector-registry.mjs route-spotlight --env-file /opt/vuln/.env.local --input /private/path/spotlight-approval.json
```

The command derives the provider and CID from the reviewed binding. Do not include secrets or copy the export's extra `provider` field into the input. Approval and audit commit together; concurrent edits require a fresh export. A route can be disabled even when its old source/customer has disappeared.

5. Only during the approved release, enable `VULN_REVIEWED_SPOTLIGHT_PROVIDERS=crowdstrike`, restart using the reviewed deployment procedure, and complete the selected customer's reviewed import before accepting its saved CVE and ticket workflow. Existing legacy source data is retained; it cannot be silently relabeled as reviewed evidence. This is independent of `VULN_REVIEWED_INVENTORY_PROVIDERS`.

## Rollback and limits

Drain workers before changing modes, source ownership or builds. Turning the Spotlight switch off restores legacy selection and starts/resumes only a legacy generation with this updated binary. Keep route audits, source generations, run pins and current pointers; do not delete tables as a rollback shortcut. An older binary predating these guards must not resume or promote version-4 runs: stop those workers and use a compatible rollback build or explicitly reconcile them first.

Saved CrowdStrike CVE and manual ticket guards now share this switch. Live FQL/dashboard patch collection uses its separate query approval; coverage matching, other stored-platform consumers and scanners are not authorized by this Spotlight approval. Live vendor scope checks, production activation, and the authoritative platform SQL writer handoff remain release gates. The new whole-generation validation runs in the background import, not a page request. Its additional JSON validation cost on a multi-million-row generation has not yet been benchmarked; the small fixture tests are correctness evidence only.

Validation is recorded in the [rollout status](connector-rollout-status.md). Database tests use guarded disposable databases on the private recovery cluster; no real source import, scan, ticket or message is used as a test.
