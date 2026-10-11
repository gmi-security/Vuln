# Saved customer reporting sections

## Current status

Checkpoint 51 implements and verifies a derived SQL report for the sections rendered by `CustomerReportSections`. Checkpoint 52 adds the [private dedicated refresh worker](customer-reporting-worker.md) and a lean Overview response over the existing platform store. SQL page reads and the worker remain inactive in production. Both SQL builder and reader refuse databases outside the private recovery cluster. No production migration or permission change has occurred.

This is a small replaceable reporting summary, not another authoritative finding store. The normalized platform record remains the input. Raw CrowdStrike/Defender counts are not substituted for correlated platform findings.

## Data flow

1. Read one consistent, committed application snapshot from PostgreSQL in a read-only repeatable-read transaction.
2. Process the selected customer's saved scans, platform findings and assets one bucket at a time. Read only fields required by the report.
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

The comparison uses the unchanged `buildCustomerReportingModel`, with the current store's finding, scan and asset ordering. It compares saved state; it does not execute `tick`, hydrate the application, poll active scans or import vendor changes. An active RAM mutation not yet committed is outside this snapshot. This boundary must be explicit when the runtime reader is integrated.

The separate threat-intelligence tile, enrichment database, full executive report, financial calculations, compliance, risk recomputation, SLA clocks and ConnectWise workflows are not replaced by this component. Existing saved source activity is retained; independent live MISP/OpenCTI parity is not newly established here.

## Storage and freshness

`docs/sql/customer-reporting-sections.sql` defines one replaceable row per customer:

- Version, generated snapshot ID and customer ID.
- Captured time, build time, expiry and finding count.
- Fingerprint of the source database/relation, 90 relevant snapshot rows and that customer's history row revisions.
- Compact report JSON and a canonical SHA-256 checksum that survives PostgreSQL JSONB key reordering.

The current fingerprint is deliberately conservative: another customer's change in a shared bucket also invalidates this report. PostgreSQL row versions are local database evidence, not portable business generation identifiers. Before activation, replace this coarse check with the authoritative customer publication/workflow revision, include current connector/source-selection evidence, and connect a durable refresh job. Do not simply remove the private-database guards.

Saved reports expire after 15 minutes or when their oldest included history row leaves the 180-day window, whichever is sooner. This is a verification safety limit. The private worker refreshes unchanged reports five minutes before expiry and discovers committed source changes outside page requests. A stale result never becomes a current zero or triggers a full rebuild inside the reader.

## Bounds and failure behavior

- Only a known, non-demo, explicitly selected customer is accepted.
- Complete expected snapshot buckets are required. Meta overrides, malformed tuples, repeated IDs, incorrect hash-bucket placement and invalid finding assessments fail the build.
- At most 50,000 entries per bucket, 32 MiB of projected data per bucket, two million customer findings and 10,000 history rows. Exceeding a limit is an error, not truncation.
- Report output is limited to 2 MiB; top lists are bounded while totals include every accepted record.
- Build statements are limited to 15 seconds, source read statements to five seconds, and a build to five minutes. Private test connection settings also bound target read statements.
- Atomic replacement preserves the previous complete report on failure. A source commit during construction makes the completed older summary stale on a subsequent read. Concurrent readers see a consistent saved observation, not a promise that upstream data cannot change immediately after the read.
- Checksums detect unexpected saved-content changes. They are integrity checks, not an independent validation of the original source's accuracy.

## Verification

The unit suite compares complete output against the existing report for mixed endpoint scanners, web testing, OSINT, all workflow states, duplicate source observations, enrichment, inventory, history and ordering ties. The 10,000-finding fixture verifies exact totals and bounded output. Related existing reporting tests also pass.

The private PostgreSQL fixture checks full parity, customer isolation, atomic failure recovery, concurrent builds, source/history invalidation, concurrent source commits, expiry, renamed customers, demo/unknown rejection, response size, content integrity, duplicate identities and malformed snapshots.

The retained October 9 restore is also compared for Footprint and Atlas. It contains Defender for Footprint and CrowdStrike/SpiderFoot platform findings for Atlas; these are not fresh vendor tests or the complete live Spotlight dataset. Full results, counts and final timings are recorded in checkpoint 51 of the platform plan. Only aggregate evidence is written to the test logs.

Run local pure checks:

```powershell
node --experimental-vm-modules --test tests/reporting-sections.test.mjs tests/reporting-customer-model.test.mjs tests/reporting-metrics.test.mjs tests/reporting-source-activity.test.mjs tests/reporting-insights.test.mjs
```

Database checks require the existing private recovery socket and explicitly create/drop disposable databases:

```bash
node --experimental-vm-modules tests/reporting-sections-postgres.mjs "$private_socket"
node --max-old-space-size=1536 --experimental-vm-modules tests/reporting-sections-restored.mjs "$private_socket"
```

Neither command is a production deployment instruction. The restored comparison intentionally buffers reference records to run the unchanged old report; its process peak memory is not the new accumulator's isolated memory measurement.

## Integration and recovery still required

1. Connect reviewed customer source assignments and current normalized publication/workflow revisions to the builder and reader. Preserve independent sources and approved mirrors without double counting or hiding unresolved ownership.
2. Promote the tested private refresh lifecycle to accepted customer publication/workflow revisions; include scan, asset and history changes, explicit runtime configuration and retention. The dedicated queue, retry and interruption recovery now exist.
3. Integrate a reversible customer-scoped SQL read with visible freshness and tested failure behavior. The Overview response has already been split from the unused executive-report computation; it still uses the existing store.
4. Test the live runtime contract separately from the static snapshot comparison: scanner polling ownership, in-memory changes, source freshness and current connector scope remain material.
5. Complete executive-report/risk/SLA compatibility, authoritative writer handoff and the coordinated release/recovery rehearsal.

No production recovery action is needed for this checkpoint. Derived test databases are dropped after verification. The application continues to use its existing report path; no findings, history, saved tiles, tickets or assignments are removed.
