# Saved customer reporting sections

## Current status

Checkpoint 54 adds customer bucket selection and retained-data capacity checks. Checkpoint 53 connects the tested SQL sections to Remediation Overview through an explicit per-customer read flag. It adds atomic customer input revisions, stored source-review checks and current connection-metadata validation. The default private comparison mode still rejects production databases; an explicit `published` mode uses migrated tables in the application database. The worker, revision writes and SQL page reads remain disabled in production. No production migration or permission change has occurred. See [configuration and rollback](customer-reporting-worker.md).

This is a small replaceable reporting summary, not another authoritative finding store. The normalized platform record remains the input. Raw CrowdStrike/Defender counts are not substituted for correlated platform findings.

## Data flow

1. Read one consistent, committed application snapshot from PostgreSQL in a read-only repeatable-read transaction.
2. In published mode, verify that the saved customer bucket map matches its input digest, then process only mapped scan, finding and asset buckets. The default private comparison still scans all 88 collection buckets. Process one bucket at a time. Read only fields required by the report.
3. Accumulate counts and bounded ranked lists, keeping the original report's classifications and workflow rules.
4. Save the complete report in `customer_reporting_sections` in a separate target transaction. A per-customer lock prevents competing builders from replacing results out of order.
5. Read the small saved report and verify its source fingerprint, content checksum, customer and age. Changed or expired input produces `stale`; missing output produces `not-ready`. No page-time aggregation or vendor request occurs in this reader.

The current validation target is a disposable database. The retained source database is read-only throughout. A normal application startup never creates this table.

## Preserved report sections

| Section | Behavior preserved |
| --- | --- |
| Finding counts and severity | Open and In Remediation findings; endpoint and web remediation are counted; OSINT is separate |
| Assessment state | No data or a failed scan does not imply a completed clean assessment |
| Priority worklist | Top 25 endpoint findings, risk then CVSS order; stable ties retain persisted map order |
| Web and exposure lists | Separate top 10 lists, with the same ordering as the current report |
| Source activity | Scan state, observations, inventory and saved enrichment provenance; overlapping source observations are not added as unique findings |
| Scans | Exact total and latest 12 saved scan records, including failed and unfinished states |
| Inventory | Inventory totals, source counts and authoritative finding context; no invented scan coverage |
| History | Recorded customer observations within the captured 180-day window; missing count remains null |
| CVE links | Existing finding identifiers and CVE values retained; ticket preparation and evidence collection remain in their existing services |

The comparison uses the unchanged `buildCustomerReportingModel`, with the current store's finding, scan and asset ordering. It compares saved state; it does not execute `tick`, hydrate the application, poll active scans or import vendor changes. An active RAM mutation not yet committed is outside this snapshot. The integrated SQL reader intentionally serves the last committed platform observation, with a visible capture time; it does not promise read-your-write visibility for unsaved RAM changes.

The separate threat-intelligence tile, enrichment database, full executive report, financial calculations, compliance, risk recomputation, SLA clocks and ConnectWise workflows are not replaced by this component. Existing saved source activity is retained; independent live MISP/OpenCTI parity is not newly established here.

## Storage and freshness

`docs/sql/customer-reporting-sections.sql` defines one replaceable row per customer:

- Version, generated snapshot ID and customer ID.
- Captured time, build time, expiry and finding count.
- In published mode, the customer input generation/content digest, reviewed source pin and that customer's history row revisions. The original private comparison keeps its coarse snapshot-row fingerprint.
- Compact report JSON and a canonical SHA-256 checksum that survives PostgreSQL JSONB key reordering.

`customer_reporting_inputs` has one versioned digest/generation per customer. The writer computes it from exactly the JSON it saves, covering report-relevant company, finding/workflow, scan and asset fields. Unchanged bucket contributions are cached only after a successful commit. `customer_reporting_publication` pins the complete set of relevant committed shard revisions. Both metadata tables update in the same transaction as `vuln_store`; they cannot acknowledge an unsuccessful write. A table write lock plus the writer's last-observed manifest detects another writer's changes rather than recertifying stale RAM.

Input format version 2 also stores `bucket_map`: ordered bucket identifiers and their per-customer content digests, committed with the same source snapshot. The reader checks its checksum, complete customer-metadata entry, key allowlist and uniqueness before trusting it. New, moved and last-removed records update the map atomically. Customers without records skip all collection buckets; a dense customer may still use all 64 finding buckets. An incomplete map or old version cannot produce a partial report. Apply `customer-reporting-buckets.sql` after the initial input migration and republish with the updated writer; no source reimport is needed.

The reader checks that the current snapshot still matches its publication marker, then compares only this customer's input revision, source review and history. Thus another customer's tracked update or unrelated bookkeeping no longer invalidates this report. An untracked older-writer update withholds the report. A changed source review, workflow, asset, scan or history invalidates it. A deleted/recreated customer gets a new generation.

This is cache freshness for the existing platform writer, not the final normalized authoritative database-write migration. The current customer IDs, record correlation and source provenance remain the platform's inputs. The worker rejects a report containing a provider outside its reviewed roles, including seen-by and enrichment provenance; it never silently drops those rows. Current tenant/dataset/target configuration is checked by the web service against the reviewed registry. These checks do not independently certify the historic ownership of every retained vendor record. That remains part of source-adapter and combined-release acceptance.

Saved reports expire after 15 minutes or when their oldest included history row leaves the 180-day window, whichever is sooner. This is the current cache freshness limit. The dedicated worker refreshes unchanged reports five minutes before expiry and discovers committed source changes outside page requests. A stale result never becomes a current zero or triggers a full rebuild inside the reader.

## Bounds and failure behavior

- Only a known, non-demo, explicitly selected customer is accepted.
- Complete expected snapshot buckets are required. Meta overrides, malformed tuples, repeated IDs, incorrect hash-bucket placement and invalid finding assessments fail the build.
- At most 50,000 entries per bucket, 32 MiB of projected data per bucket, two million customer findings and 10,000 history rows. Exceeding a limit is an error, not truncation.
- Report output is limited to 2 MiB; top lists are bounded while totals include every accepted record.
- Build statements are limited to 15 seconds, source read statements to five seconds, and a build to five minutes. Both source and saved-report read transactions have a five-second statement limit.
- Atomic replacement preserves the previous complete report on failure. A source commit during construction makes the completed older summary stale on a subsequent read. Concurrent readers see a consistent saved observation, not a promise that upstream data cannot change immediately after the read.
- Checksums detect unexpected saved-content changes. They are integrity checks, not an independent validation of the original source's accuracy.

## Verification

The unit suite compares complete output against the existing report for mixed endpoint scanners, web testing, OSINT, all workflow states, duplicate source observations, enrichment, inventory, history and ordering ties. The 10,000-finding fixture verifies exact totals and bounded output. Related existing reporting tests also pass.

The private PostgreSQL fixture checks full parity, customer isolation, atomic failure recovery, concurrent builds, source/history invalidation, concurrent source commits, expiry, renamed customers, demo/unknown rejection, response size, content integrity, duplicate identities and malformed snapshots.

The retained October 9 restore is also compared for Footprint and Atlas. It contains Defender for Footprint and CrowdStrike/SpiderFoot platform findings for Atlas; these are not fresh vendor tests or the complete live Spotlight dataset. Full results, counts and final timings are recorded in checkpoint 51 of the platform plan. Only aggregate evidence is written to the test logs.

Checkpoint 54 also runs the complete `published` path in a disposable copy of retained report buckets and history. Actual review stores use synthetic connection metadata, including Tidal/Automate inventory, before the real worker/reader are compared with the independent legacy reference. Footprint, Atlas and an empty fixture all matched. Saved reads took 4.3-22.2 ms; their continuous build cycle took 54.207 seconds at 247 MiB peak worker RSS. See the plan for per-customer results and limits. These fixture approvals do not establish live source ownership or all-customer capacity.

Run local pure checks:

```powershell
node --experimental-vm-modules --test tests/reporting-sections.test.mjs tests/reporting-customer-model.test.mjs tests/reporting-metrics.test.mjs tests/reporting-source-activity.test.mjs tests/reporting-insights.test.mjs
```

Database checks require the existing private recovery socket and explicitly create/drop disposable databases:

```bash
node --experimental-vm-modules tests/reporting-publication-postgres.mjs "$private_socket"
node --max-old-space-size=1536 --experimental-vm-modules tests/reporting-publication-restored.mjs "$private_socket"
node --experimental-vm-modules tests/reporting-sections-postgres.mjs "$private_socket"
node --max-old-space-size=1536 --experimental-vm-modules tests/reporting-sections-restored.mjs "$private_socket"
```

These commands are not production deployment instructions. The restored comparison intentionally buffers reference records to run the unchanged old report; its process peak memory is not the new accumulator's isolated memory measurement.

## Integration and recovery still required

The per-customer SQL route, published input revisions and reversible read flags now exist and are tested in disposable PostgreSQL. Before rollout, complete the production customer-review inventory and prepare the explicit migrations and independent worker configuration. Verify source-adapter ownership evidence and refresh capacity for the enabled customer set. Keep Burp, Nmap, Intune, IntelOwl and n8n disabled as agreed.

The full executive report/risk/SLA calculations, scanner polling ownership, authoritative normalized writer handoff/reverse recovery and coordinated release rehearsal remain separate work. This read optimization does not remove application RAM hydration from unrelated pages or replace patch/ticket evidence collection. No source deletion or resync is needed for this change. For rollback, first disable the SQL read flag, then stop the dedicated worker; keep the derived tables and existing data.
