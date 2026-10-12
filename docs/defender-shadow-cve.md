# CVE details and patch inputs from the Defender shadow

This compatibility boundary is now used by the disabled read-only comparison endpoint and shared panel described in `shadow-cve-preview.md`. It is not connected to ticket persistence, source APIs or a production database initializer, and has not been deployed or enabled in production.

## Read contract

`readDefenderShadowCve(client, {companyId, projectionId, cve})` requires an explicit customer and a verified version-2 projection. It canonicalizes the requested CVE without changing the stored record. The separate `docs/sql/defender-shadow-cve.sql` migration adds a customer/generation/case-insensitive CVE index to the disposable shadow.

The reader selects the requested **primary CVE**, with Open or In Remediation status, excluding SpiderFoot/Artemis exposures. Web findings are included when present in this cohort, matching the existing customer-CVE model. It preserves saved risk/CVSS ordering and original snapshot order for ties. It reconstructs every field, including correlated scanner evidence, source extensions, workflow, remediation, original finding IDs and legacy asset keys.

| Response | Meaning |
| --- | --- |
| `scope` | `published-defender-cohort`; this is not a complete multi-provider customer view |
| `companyId`, `projectionId`, `projectionModelVersion` | Exact customer and verified snapshot identity |
| `sourceRun`, `snapshotSavedAt` | Publication provenance, not a fresh source assessment |
| `observedAt` | Greatest saved finding `lastSeen`, matching the existing stored-finding path |
| `findingCount` | Number of matching open findings |
| `deviceCount` | Distinct legacy customer/asset keys, matching existing patch identities; not distinct vendor device IDs |
| `hosts` | First 50 finding host entries in existing risk order; this preview may repeat a device |
| `findings` | Complete bounded records for pure patch preparation; not a truncated preview |

Reads use a read-only repeatable-read transaction, 15-second statement limits, two-second lock waits, and an elapsed-time check between operations with a 60-second threshold. A running statement may finish after that threshold before the check rejects the request. At most 10,000 findings are allowed. PostgreSQL measures reconstructed JSON size before returning full payloads; more than 32 MiB fails. This measure includes PostgreSQL JSON formatting, so it is conservatively larger than compact JSON. Full records are fetched in chunks of 500 and checked again for scope, identity, completeness and byte size.

Unknown, failed or wrong-version projections return a conflict. No matching open records returns not found. Oversized input returns a limit error. These states never become empty-success or partially prepared requests. This prototype assumes the verified base is frozen; live immutability and lifecycle updates are still separate release work.

## Patch compatibility

The comparison invokes the existing **pure** `buildCustomerCveGroups` on source-reference records and on reconstructed records. It compares entire group objects, including CSV bytes, ticket text, scores, group IDs, host scopes, device/CVE identities and review rows. It tests no exclusions, one already-ticketed asset plus a foreign-customer key, and all assets excluded.

The existing stored-finding path uses published remediation text, including any correlated scanner text. This change does not invent Defender recommended/minimum remediation categories. The existing CrowdStrike recommended-remediation path remains unchanged and has its own regression tests. Missing required remediation still prevents a partial patch request. Asset lists remain in CSVs; the ticket body retains counts, actions and scores.

The validation loader explicitly forbids application-store initialization and admits only the pure model dependency graph. It does not call `prepareCustomerCve`, save packets, read production tickets, contact ConnectWise or send anything. Preserving exclusion keys is evidence of identity compatibility, not proof of live ticket-reference lookup or deduplicated ticket creation.

## Validation

Run local contract and existing workflow tests:

```text
node --experimental-vm-modules --test tests/defender-shadow-cve.test.mjs tests/customer-cve.test.mjs
```

The existing private PostgreSQL runner accepts `--with-shadow-cve` and optionally `--with-restored-defender`. It requires the isolated restore Unix socket and creates separate disposable databases. The fixture covers more than 1,000 records, multiple retrieval batches, risk ties, case-insensitive matching, correlated sources, older evidence, duplicate asset keys, missing remediation, formula-safe CSV cells and a real oversized database payload.

The restored-data test selects up to two highest-count CVEs per saved severity plus one CVE with older open evidence, reads complete source records only for those CVEs, and compares detail and preparation output. This is a sampled CVE/patch comparison, not exhaustive proof for all CVEs or end-to-end tickets. The base projection still checks full record reconstruction for the entire restored cohort. Aggregate measurements and remaining release gates are recorded in the platform proposal.

The gated comparison integration retains authentication/customer validation and appends saved threat enrichment and existing ticket references. It must still reconcile all customer providers before substituting this cohort reader for the current service; comparison mode preserves the explicit cohort limit.
