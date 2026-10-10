# Reviewed customer routing for Nessus

Development on `Vuln2.0` only. No production activation, real scan, source import or deployment was performed for this checkpoint.

## The change

Nessus can select an existing customer by the scanner's numeric folder ID and approved host scope. The folder name no longer determines the customer when reviewed routing is on. The existing platform findings, scan records, correlation, severity/risk calculations and snapshot persistence remain; this is not the authoritative SQL writer cutover.

```text
Configured Nessus scanner
  -> reviewed customer binding: folder ID + targets + findings-primary role
  -> separate audited scanner approval
  -> explicit Nessus runtime switch at release
  -> read only approved folders' scan lists
  -> verify completed scan, all returned hosts and unchanged run
  -> recheck current customer approval
  -> existing findings/correlation and clean-host reconciliation
```

Reviewing a binding alone does not activate it. A separate scanner approval and `VULN_REVIEWED_SCANNER_PROVIDERS=nessus` are required. Empty keeps the legacy behavior; it is not a kill switch. No member/admin permissions were added or changed.

## What is checked

| Operation | Reviewed-mode behavior |
| --- | --- |
| Sync imports | Use approved numeric folder IDs and existing customer IDs. Do not create customers from folder names. Only custom customer folders are accepted. Repeated syncs reuse pending records and recognize the latest already-imported run. |
| Target scope | Exact hostnames, IPv4/IPv6 addresses and CIDR networks. Names are case-insensitive; a trailing DNS dot is ignored. Wildcards, URLs, IP ranges, comma lists, scoped IPv6 and Nessus hostname/IP composite syntax are unsupported and rejected. |
| Result collection | Require a completed run, valid unique host IDs, valid host finding lists and a stable folder/run timestamp before and after collection. Every returned host, including clean hosts, must have an approved alias. Every finding must belong to one of those verified hosts. |
| Application | Recheck the route, binding revision, destination and connection before applying results. Bulk sync stages the complete collected result before adding the scan/findings. A rejected batch does not close old findings. Independent approved folders may still succeed and errors remain visible. |
| Start/rescan | Require explicit approved customer targets, submit the reviewed folder ID, then confirm the newly created scan appears in that folder before launching. Failure to confirm leaves an inactive scanner draft and reports an error; no automatic remote deletion is performed. Imported scan records with no stored targets require an explicit new scan request. |
| Pause/resume/stop | Confirm the existing scanner scan is still in that customer's approved folder before forwarding the control. This verifies ownership, not every setting an operator might have edited directly in Nessus. |
| Polling | Existing native scans pass through the same scope checks. Route metadata is read once per eligible polling pass; folder scan lists are shared within that pass. A page with no active vendor scans does not perform new route reads. The existing four-second polling throttle and page-triggered polling architecture remain unchanged. |

Folder IDs are scanner-native IDs, not platform company IDs. One folder can have only one active customer owner. The current binding key supports one reviewed folder per customer for this single configured Nessus connection. Different customers may have overlapping private IP ranges because their folders provide the tenant boundary. A folder/target review needs independent operational verification; a configuration record is not proof of correct ownership.

Host aliases are source-provided evidence within that verified folder. At least one alias must match the approved scope; this is not DNS ownership verification or a network firewall. A completed empty scan changes no host-based closures because it contains no covered hosts. Existing plugin-detail budget/cache and clean-host interpretation are preserved. Run-timestamp checks do not make the scanner API an atomic snapshot or replace testing against the deployed Nessus version.

## Database and configuration

| Table | Purpose |
| --- | --- |
| `customer_connector_drafts` / `customer_connector_bindings` | Sanitized source configuration evidence and reviewed customer folder/targets; inactive-proposal constraints remain |
| `customer_scanner_routes` | Independent operational approval pinned to the exact binding revision/hash and folder ID |
| `customer_scanner_route_audit` | Before/after state, operator, note, timestamp and route revision |
| Existing platform store/snapshot tables | Current scan records, findings, identities and workflow state |

All use the application `DATABASE_URL`. The route tables are installed only by the explicit [scanner migration](sql/customer-scanner-routes.sql), after the existing connector draft/binding migrations. No source data is migrated by approving a route. The inventory, Spotlight and scanner services now share their approval/audit/transaction implementation, with separate provider policy and separate tables. Existing approval interfaces and constraints are retained.

Nessus endpoint or TLS-mode changes invalidate saved reviews. Credential values are never copied into evidence, exports or the browser; key rotation itself still needs an operational verification step. Customer Connectors displays only safe routing labels, not folder IDs or targets. No extra selector or configuration control was added.

## Preparing an eventual release

Do not run these steps in production yet.

1. Preserve the recovery point and drain affected imports and scanner operations. Install the ordered draft/binding/scanner migrations with the approved deployment role.
2. Collect/import current registry evidence and independently review the Nessus binding. Use the existing platform `companyId`, numeric Nessus folder ID as `proposal.tenantId`, `authority: "findings-primary"`, approved `targets`, and empty `datasets`. Unsupported roles or scope are rejected.
3. Export current operational revisions:

```sh
node --experimental-vm-modules scripts/customer-connector-registry.mjs export-scanner-routes --env-file /opt/vuln/.env.local --company CO-EXAMPLE --output /private/path/scanner-routes.json
```

4. Prepare one private approval with exactly these fields (the candidate ID and binding revision come from the binding export; use the current route revision, or zero for a new route):

```json
{
  "candidateId": "<source candidate ID>",
  "companyId": "CO-EXAMPLE",
  "bindingRevision": 1,
  "expectedRevision": 0,
  "enabled": true,
  "note": "Verified scanner folder and target ownership"
}
```

```sh
node --experimental-vm-modules scripts/customer-connector-registry.mjs route-scanner --env-file /opt/vuln/.env.local --input /private/path/scanner-approval.json
```

Do not copy the export's extra `provider` field into the input. The approval derives folder/targets from the reviewed binding. Exports are private and refuse to overwrite an existing path. Revision conflicts and failed audits roll back the approval transaction. Revocation is still possible when the old customer or configuration no longer exists.

5. Verify the deployed scanner's actual folder filtering, completion/run metadata and create-in-folder behavior. The fixtures are not live API acceptance evidence. Enable only during the approved combined release and verify selected-customer results and scan controls.

Tenable documents the [Nessus folder setting](https://docs.tenable.com/nessus/10_12/Content/BasicSettings.htm). Its [official Nessus API client](https://github.com/tenable/pyTenable/blob/master/tenable/nessus/scans.py) supports listing scans by folder and documents the separate create/launch flow. Actual server-version validation remains a release gate.

## Rollback and remaining limits

Drain import and scan operations before changing assignments, flags or builds. Turning the flag off restores legacy name-based import selection; verify that mapping before doing so. Retain approval/audit tables and all existing source/platform data. Do not drop data to roll back code.

Approvals are rechecked before applying collected findings; application still uses the mutable platform store. Revocation does not cancel an in-flight provider request or roll back an application that has already begun. No distributed write fence or atomic SQL findings publication is claimed. An older binary ignores these routing approvals, so a rollback requires a reviewed compatible build and reconciled writer ownership.

SpiderFoot and Artemis now extend this approval model; see [OSINT routing](customer-osint-routing.md) for their separate source scopes and additive migration. ZAP and Vulners runtime routing remain separate follow-ups. This checkpoint does not enable Burp, Nmap, Intune, IntelOwl or n8n. It does not resolve earlier Artemis/ZAP connectivity failures or complete FQL/patch routing and the platform database migration.

Validation is recorded in the [rollout status](connector-rollout-status.md). Tests use fixture HTTP responses, mocked operational effects and guarded disposable PostgreSQL databases. No real customer scan was launched or import performed.
