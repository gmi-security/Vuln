# Reviewed customer routing for inventory imports

Development only: implemented on `Vuln2.0`. Not deployed or enabled in production. Intune remains available but disabled for this rollout.

## What changes

Automate and Intune can use an explicitly reviewed source identity to select an existing platform customer. Automate uses its **numeric client ID**, not a client name or the API `ClientId` header. Intune uses the **configured Microsoft tenant UUID**, not the platform company ID. Renaming a customer does not change either route.

The imported assets still use the current platform store and PostgreSQL persistence. This is customer routing, not the authoritative SQL findings migration. Existing assets, findings, tiles, scores, ticket references, permissions and connector configuration are retained.

```text
Existing source configuration
        |
Collect/import sanitized configuration evidence
        |
Review a customer binding (does not enable routing)
        |
Approve that exact binding revision for inventory imports
        |
Enable that provider's runtime routing switch
        |
Import starts -> recheck every approved route -> pin routes for this job
        |
Fetch approved vendor inventory -> existing customer inventory + persistence
```

## Runtime behavior

| Mode | Automate | Intune |
| --- | --- | --- |
| Provider absent from switch | Existing routing, including existing ambiguity checks | Existing routing, including existing ambiguity checks |
| Provider opted in | Read client roster; fetch devices only for explicitly approved client IDs | Require one approved route matching the configured tenant |
| Missing tables, missing approvals, invalid configuration or a stale enabled route | Stop the opted-in import; no fallback to name matching | Stop the opted-in import; no fallback to the internal company |
| Unassigned source client | Count as skipped; no device request and no company creation | Not applicable: one configured tenant per current adapter |
| Approved client missing from roster | Report an error; other valid approved clients can continue | Not applicable |
| Vendor response incomplete or malformed | Existing adapter rejects that client inventory | Existing adapter rejects the inventory |

An opted-in job will not create a destination customer. It rechecks the customer after collection, so a customer deleted during the request is not recreated. Duplicate Automate roster IDs stop the import before device requests. Asset upserts remain customer scoped. Rescoring and the existing optional auto-scan follow-up are limited to successfully imported customers. This does not turn auto-scan on or grant new scanner permissions.

Routes are validated together and pinned at job start. Disabling or changing a route does **not** cancel an already running job. Drain import/sync-all/scheduled work before changing customer ownership or the provider switch. This implementation does not add a distributed writer fence, repair earlier assignments, move historical assets, or roll back a partial vendor import. A source client moved between customers needs an explicit historical-data reconciliation plan.

## Storage

All route tables use the existing application `DATABASE_URL`; they do not use the optional dashboard database.

| Table | Purpose |
| --- | --- |
| `customer_connector_drafts` | Sanitized source evidence and its current fingerprint |
| `customer_connector_bindings` | Independently reviewed customer scope, authority and revision; `enabled=false` remains enforced |
| `customer_inventory_routes` | Separate operational approval pinned to the binding revision/hash and exact source client/tenant |
| `customer_inventory_route_audit` | Before/after route changes, trusted operator identity, note and timestamp |

The new unique partial index allows only one enabled owner per provider/source scope. Approval and its audit record commit in one transaction. Concurrent edits require the expected revision. No request or import creates these tables automatically. Audit is recorded by this service, not an immutable external audit system.

## Operator preparation for the eventual release

These are release instructions, **not a request to run them now**. Keep the runtime switch empty while preparing and reviewing routes.

1. Apply the explicit additive migrations in order: `customer-connector-drafts.sql`, `customer-connector-bindings.sql`, then `customer-inventory-routes.sql`. Check which migrations already exist; these files are not repeatable initializers. Apply with the approved deployment database role and recovery point.
2. Follow [the registry workflow](customer-connector-registry.md) to collect/import fresh evidence and export a customer's bindings.
3. Verify vendor ownership independently. For an Automate binding, put its vendor client ID in `proposal.tenantId`. For Intune, use the configured Microsoft tenant UUID. Use `authority: "inventory"`, `datasets: []`, `targets: []`, and the existing platform `companyId`. Save with `assign`, decision `reviewed`. A reviewed scanner or an inventory binding with target/dataset restrictions cannot be used by this router.
4. Export any existing operational route revisions:

```sh
node --experimental-vm-modules scripts/customer-connector-registry.mjs export-inventory-routes \
  --env-file /opt/vuln/.env.local --company CO-EXAMPLE \
  --output /private/path/customer-inventory-routes.json
```

The private export includes route revision and pinned binding revision. It can include a deleted customer's historical route so it can still be revoked. It is not a customer-existence or import-health check. Existing output paths are never overwritten.

5. Prepare one private JSON approval, using the candidate ID from the binding export and the **latest saved binding revision**. Use `expectedRevision: 0` only if no route exists. Do not copy an entire exported row: `provider` is inferred and is not an accepted input field.

```json
{
  "candidateId": "<64-character source candidate ID>",
  "companyId": "CO-EXAMPLE",
  "bindingRevision": 1,
  "expectedRevision": 0,
  "enabled": true,
  "note": "Verified vendor client ownership for this customer."
}
```

```sh
node --experimental-vm-modules scripts/customer-connector-registry.mjs route-inventory \
  --env-file /opt/vuln/.env.local --input /private/path/one-inventory-approval.json
```

This records approval; it does not fetch inventory, change the server environment or start a worker. Inputs must contain exactly the six fields above. The actor comes from the operator's OS account, not the JSON. Keep exports and notes free of credentials and outside Git/the web root.

6. For the approved release, enable only the reviewed provider, after reconciling its complete client roster:

```dotenv
VULN_REVIEWED_INVENTORY_PROVIDERS=automate
```

The empty default preserves legacy behavior and skips routing database reads. A malformed value fails rather than silently using legacy routing. `automate,intune` is supported in code but **must not be used for this rollout**, because Intune was explicitly left disabled. Merely setting this switch does not provide connector credentials or enable scheduling.

7. Restart through the reviewed deployment process, then observe a deliberate import and verify customer counts and partial-import errors. Local/fixture checks are not proof of live tenant ownership. The Connectors page shows current saved approval plus the running process's routing switch, without exposing raw tenant IDs, source scopes or audit notes. That status does not confirm vendor access or a successful import.

## Revocation and rollback

- Keep the provider switch **on** and save the current route with `enabled: false` to withhold that source from subsequent routed imports. Use its current route revision. Revocation works even when source metadata or customer ownership has become stale.
- Setting the provider switch empty returns to **legacy routing**; it is not a source kill switch. Do not use it as emergency revocation. Stop/drain imports first if ownership is in doubt.
- Code rollback retains the new tables and audit. Do not drop tables or delete source/platform data to roll back this feature. Previously imported assets are not undone by changing a route.
- Environment credentials are not copied or fingerprinted. Non-secret endpoint/client/tenant changes invalidate reviews, but secret-only rotation is not versioned by this implementation. Reverify effective credentials and source access before enabling or restoring imports.

## Validation

The focused local suites exercise real import entrypoints with mocked vendor transports, exact source routing, no fallback, customer deletion, legacy behavior, status redaction and provider-switch parsing. `tests/inventory-routing-postgres.mjs` verifies the actual migrations and operator commands, unique ownership, optimistic revisions, atomic audit rollback, stale reviews, disabling and deleted/demo destinations on a disposable recovery-cluster database. It refuses normal network/production database targets. No real import, scan or ticket is used in these tests.

Remaining connectors still require their own reviewed runtime scope enforcement. This inventory step does not authorize scanner targets, select CrowdStrike tenants, reinterpret Elastic mirrors or replace the platform database writer.
