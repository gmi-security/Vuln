# Saved reads for the Defender platform shadow

These readers remain offline validation code. No page, API route, worker or production database uses them. They target an explicitly selected customer and verified version-2 shadow projection, never whichever customer/source happens to be globally configured.

## What is stored once

`docs/sql/defender-shadow-reads.sql` adds three disposable tables:

| Table | Contents |
| --- | --- |
| `defender_shadow_read_summary` | Validated platform-cohort counts, model version and build time |
| `defender_shadow_priority` | Finding IDs, workflow status and stable priority position; no second copy of complete findings |
| `defender_shadow_cve_pages` | Open primary-CVE groups with worst saved severity, device count, finding count and maximum saved scores |

`buildDefenderShadowReads` computes these rows once after the base projection passes full reconstruction. A customer/generation advisory lock rejects competing builders. It sorts priorities once in a transaction-local staging table and inserts 5,000-row batches. All derived rows and their ready summary commit together; an injected failure rolls everything back. A repeated successful call leaves the existing generation unchanged. The builder refuses targets outside the private disposable database pattern and has 15-second statement limits, two-second lock waits and a 90-second overall check.

The prototype assumes a frozen verified base generation. There is no live mutation/invalidation path, active pointer, production scheduler or retention job. Live immutability and update rules remain release gates; these helpers do not authorize changing platform findings.

## Counting and ordering

- Open means `Open` or `In Remediation`, matching the existing reporting functions. Accepted, false-positive and resolved findings remain stored and can be viewed with explicit workflow filters.
- The remediation summary includes endpoint and web findings and excludes SpiderFoot/Artemis exposures. Separate totals retain those domains. This applies to the selected Defender-evidence cohort, not every source belonging to the customer.
- The default priority list includes open endpoint findings only. Its order is saved real risk descending, then saved CVSS descending, then original snapshot order for ties.
- Shadow model version 2 adds `legacy_order` during projection. It preserves the stable tie behavior of the existing JavaScript report. Version-1 shadows must be rebuilt in the disposable database; there is no production migration or in-place rewrite.
- CVE pages group valid primary CVE identifiers from open endpoint findings. They count distinct Defender device IDs, retain finding counts separately, take the worst saved platform severity, and sort by severity, affected devices and CVE text. They do not substitute current vendor severity for saved platform assessments.
- Global unique CVEs and affected identities are computed directly, never by adding per-severity distinct counts. Legacy asset keys, Defender device IDs, findings and CVEs remain separately named units. Non-CVE endpoint findings can remain in the priority list but do not create CVE groups.
- These results preserve the saved snapshot, including older open findings. They do not recalculate risk or claim that an endpoint was recently assessed. Source generation, snapshot-save time and summary-build time accompany successful reads.

## Bounded reads

`readDefenderShadow` uses read-only repeatable-read transactions. It loads the small saved summary and, when requested, at most 101 rows to return a maximum 100-row page plus a continuation indication. The default is 50. Priority pages use stored ranks and composite-key lookups for the selected rows; CVE pages read the saved groups. Neither path runs a whole-generation aggregation, loads all findings into application memory or calls a vendor.

The opaque continuation token binds customer, projection, view, workflow filter and last position. Tokens from another scope/filter are rejected, along with malformed tokens and excessive page sizes. This is pagination validation, not authentication; any future API must retain the existing authorization and customer-binding checks.

Unknown, failed or version-incompatible base generations fail. A verified base without derived results returns `not-ready`; a verified empty summary returns available zero values and empty pages. Summary arithmetic is validated before use. Snapshot isolation keeps a reader's summary and rows consistent if a separate transaction removes the generation mid-read; a subsequent request fails rather than returning another generation or fabricated zeros.

## Validation and remaining work

Tests use the actual pure reporting model and metrics functions, without importing application initialization. They compare cohort totals, all risk-ordered finding pages, workflow filters, original-order ties and every CVE group with an independent reference. Fixtures also cover non-CVE findings, web/exposure separation, empty results, missing summaries, customer/cursor isolation, build rollback, corrupt summary rejection, and concurrent reads during an uncommitted build or generation deletion.

The full restored comparison passed for all 288,878 findings, all 215,891 open records and all 10,229 CVE groups. The derived build took 24,547 ms; saved summary reads took 2.0-2.6 ms, sampled 100-finding pages 7.7-19.2 ms and sampled 100-CVE pages 1.7-18.5 ms. These are server-local private-restore measurements. Derived tables/indexes allocated about 167 MiB including failed-attempt space and fixture overhead. Exhaustive validation peaked at 468 MiB RSS including its independent reference, not just a page request.

Seventeen local contract/regression checks and six PostgreSQL fixture scenarios passed. Full traversal additionally compared actual reporting semantics and every returned group/order against the independent restored reference. Original source data was read only, all shadow/fixture databases including the retained diagnostic target were deleted afterward, and the private cluster stopped. Validation logs contain aggregate measurements, not host details or record contents.

```sh
node --test tests/defender-shadow-reads.test.mjs
node --experimental-vm-modules --max-old-space-size=768 \
  tests/defender-platform-shadow-postgres.mjs \
  /home/codex/vuln-recovery/baseline-uVic9i/restore-6hXR1M/socket \
  --with-restored-defender --with-shadow-reads
```

The private-cluster harness enforces cleanup and a nine-minute limit for projection plus exhaustive read validation. Base projection limits remain unchanged. Runtime/UI wiring, trusted source activation, other-provider reconciliation, CVE detail/patch-input parity, live generation immutability and deployment remain separate steps.

For diagnosis only, `--keep-failed-shadow` retains a failed run's private target and prints its generated database name. It is off by default and requires explicit cleanup after investigation; the completed validation above left no such target behind.
