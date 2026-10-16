# Manual tickets from the remediation worklist

Date: 2026-10-16

## Behavior

The existing **Remediations by severity and device impact** table has a **Prepare ticket draft** button for members with the existing dashboard-management permission. It uses the page's selected customer. The other tables and CVE links remain available.

For a CrowdStrike row, one draft covers the exact recommended action and target version, its full CVE list, and its affected devices. The host CSV contains one row per unique source device, with its covered CVE count, highest recorded scores and remediation. Device details stay in the CSV rather than the ticket body. Different required action versions remain separate. Platform findings without a shared vendor action retain the existing single-CVE grouping and packet batching.

The action saves a pending manual draft and links to the existing Tickets page. Review, approval and explicit ConnectWise sending remain separate steps. Repeated clicks reuse an equivalent pending draft. An approved overlapping draft must be reviewed before another is prepared. Active-ticket overlap is checked when sending, using the actual ConnectWise destination, destination company, source tenant, action/version and host scope. An old ticket in a different destination does not block draft preparation.

## Data and performance

CrowdStrike summary model 6 builds compact action evidence during the existing streaming summary pass. It stores exact device/CVE membership as bitsets, not a device-by-CVE cross product or millions of duplicate source rows. The ticket request selects just the chosen action from the saved current summary. Normal summary/page reads exclude private ticket evidence in SQL.

Current source generation, customer proof, tenant, counts and CVE coverage are checked before saving. A changed or incomplete source fails explicitly without presenting a partial packet. The existing pre-send scope validation also accepts and verifies the compact representation. Compact ticket exclusions are action-specific so one ticket does not hide a second required action on the same device/CVE. Legacy ticket representation remains supported.

Evidence accumulation and serialization have independent capacity limits, including a check before expanding sparse membership. Exceeding a ticket-evidence limit leaves the regular worklist summary available and reports that smaller CVE requests are needed. No table migration is required. Older summaries remain readable while model 6 is built; whole-remediation preparation reports pending until its evidence is ready. No source re-import is required.

## Verification

- Full Linux suite: **1,022 passed, 7 optional database tests skipped, 0 failed**. Those optional checks are not claimed as run by the unit suite.
- Separate fresh private PostgreSQL cluster: **48 checks passed** across customer CVE/draft transactions (15), summary publication (16), worker lifecycle (9) and retention/read snapshots (8). Includes concurrent draft reuse, transaction rollback, actual selected-action SQL, generation/tenant guards, and real destination/action/host-overlap SQL. Send-boundary cases deliberately stop before queuing or sending.
- **14 browser workflow checks passed**, including the new customer-scoped draft action and Tickets link, existing CVE review, simulated approval/send, customer switching, failure handling and mobile behavior.
- TypeScript and production webpack build passed. Summary and reporting worker builds passed.
- Independent code review found no remaining blockers after fixing destination scoping and capacity handling.
- Read-only scan of **3,370,395 saved source rows** produced complete evidence for all **50** displayed actions in **573.2 seconds**, with measured peak RSS **707 MiB** under a 1 GiB heap limit. Ticket evidence occupied **3,500,285 bytes**. The largest action covered **1,743,190 source findings**; the largest device population was **824**.
- All **50** packets were independently validated against their worklist counts, CVEs, risk and CSV row counts. Maximum in-process packet preparation was **85 ms**, maximum serialized packet **1,220,405 bytes**, and maximum CSV **297,819 bytes**. This measures packet construction from ready evidence, not an end-to-end live HTTP request or ConnectWise latency.

Testing created no production drafts, ConnectWise tickets or provider requests. Live source measurement used read-only database sessions and an in-memory publication adapter. Private host evidence remains outside the repository.

## Operational notes

The deployment must preserve the existing scheduler, source configuration, routing, operator files and environment. Build before stopping the running service. After restart, check read/write readiness, existing customer worklists and model 6 summary completion. Large summary preparation runs in the isolated summary worker; ordinary page requests do not rebuild it. Manual ticket creation remains the only enabled workflow introduced by this change.
