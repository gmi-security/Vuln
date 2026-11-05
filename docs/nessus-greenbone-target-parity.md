# Nessus → Greenbone target coverage parity audit (read-only)

This review introduces an admin-only **scope audit** at `GET /api/admin/scanner-target-parity`.
It deliberately does not schedule, create, start, retry, import, reconcile or close any scan.

## Meaning of the result

- `approved-targets-match`: the independently reviewed Nessus and Vulners route **lists**
  contain the same normalized exact host/IP identities for a single GMI customer.
- `approved-targets-differ`: exact approved targets are missing or unexpected.
  `missingFromVulners` lists the gaps and `notExactNessusTargets` lists additional
  reviewed Vulners hosts. They must be reviewed before changing any routing.
- `unverifiable`: missing/duplicate customer assignment, invalid scope, CIDRs,
  unapproved route, or other ambiguity. Never treat it as an empty clean scan.
- `executedScanParityVerified` is **always false**. This endpoint is *not* live
  proof that Greenbone ran, that Nessus configured scan definitions agree with
  route scope, that either engine completed an occurrence, or that every host
  was reached. CIDRs are not silently expanded into scan jobs.

## Operator read

GMI Vuln production is a **DigitalOcean droplet**, `Vuln-NYC1`
(`178.128.150.245`), serving the site at
`http://178.128.150.245/scanner-telemetry`. Its Next.js installation
is `/opt/vuln`, PM2 process `vuln`, and its app listens on
`127.0.0.1:3000`. Do **not** use the old App Platform URL/spec as the
production target. The **separate** Vulners-v2/Greenbone scanning host has
the `gmi-vuln-api` container under `/opt/gmi-vuln-api`; it is not
the Next.js dashboard droplet.

After merging and deploying separately to **Vuln-NYC1**, run these reads
in an SSH session on that droplet, with the existing `ADMIN_TOKEN`
already set in the local shell:

```bash
curl --fail-with-body -sS \
  -H "Authorization: Bearer ${ADMIN_TOKEN:?set ADMIN_TOKEN locally}" \
  "http://127.0.0.1:3000/api/admin/scanner-target-parity" |
  jq '{mode, executedScanParityVerified, nessusRoutesAvailable, vulnersRoutesAvailable, matchedApprovedScopeCount, unresolvedCompanyCount, statusByCompany: [.companies[] | {companyId, status, nessusExactCount, vulnersExactCount, matchingExactCount, missingCount: (.missingFromVulners | length), extraCount: (.notExactNessusTargets | length), cidrCount: (.nessusNetworksRequiringExpansionReview | length), problems}]}'
```

Do not send admin bearer tokens over the droplet's public **HTTP**
URL; use loopback in SSH (as above) or a validated HTTPS endpoint.
A 403 response to external anonymous requests is not evidence of a
healthy import or target coverage.

The response contains sensitive customer IPs, hostnames and folder IDs: do not
post or commit it. This endpoint is admin-token gated, no-store and fail-closed.
Missing `VULN_REVIEWED_SCANNER_PROVIDERS` flags means approved route reads return
null; the endpoint never falls back to name-based customer matching.

## Live read-only baseline (November 5, 2026)

Operator diagnostics on **Vuln-NYC1**, without scanner writes:

- PM2 `vuln` online; Nessus `ready`; Vulners bridge `Connected`.
- Admin external-scan-plan: `mode=preview-only`,
  `routeStatus=unavailable`, `launchesEnabled=false`,
  `candidates=0`; reports reviewed Vulners customer routing not enabled.
- Verified complete gvmd capacity snapshot: healthy; active, queued,
  and requested tasks were all zero **at the time checked**, not proof
  of absent historical scans.
- `VULN_REVIEWED_SCANNER_PROVIDERS`,
  `VULNERS_BRIDGE_SCHEDULER_ENABLED`,
  `GMI_SCAN_ADMISSION_ENABLED`, and
  `VULN_EXTERNAL_SCAN_DISPATCH_ENABLED` all unset in the environment
  file and PM2 environment.
- Application DB `customer_scanner_routes` returned **zero rows**.
  Legacy Nessus imports may still operate independently.
- Nessus global roster: 33 scan definitions, 31 reported completed,
  2 running; 19 definitions in six custom customer folders
  (17 completed and 2 running). The other 14 definitions were outside
  those six folders.
- Read-only `GET /editor/scan/{id}` showed configured targets at
  `settings.basic.inputs[]` under the `text_targets` input,
  **not** `settings.text_targets`. Initial zero-target diagnostic
  was a parser error. Subsequent audit read **all 19/19** custom-folder
  definitions, with no unreadable definitions, and found **332
  distinct target expression strings** across the six folders.
- Read-only `app_scans` import ownership audit matched **all 19**
  scan definitions, with no missing/conflicting platform assignment:
  folder 7 → `CO-9150` (4 definitions), 11 → `CO-9153` (5),
  114 → `CO-9156` (3), 136 → `CO-9159` (2),
  253 → `CO-9162` (3), 507 → `CO-9165` (2).
  These are **historical imported associations**, not approved
  Greenbone scope. Prior migration documentation warns that the legacy
  GMI/Valor identities can differ from consolidated identities; verify
  active `app_companies` ownership before creating approvals.
- Platform SQL shows all six historical Nessus identities exist:
  `CO-9150` internal and five client customers. Local Vulners scan
  records total **135** across them: **91 Running**, **29 Completed**
  and **15 Failed**. This is application state, **not** gvmd task state.
  Source shows the legacy bridge launches `void
  runVulnersBridgeScanAsync(...)` in-process, and persists
  `bridgeScan:{done:boolean}` rather than a durable remote task ID.
  Local jobs marked Running may survive a restart without their
  in-memory poller. Their ages and remote report IDs require read-only
  reconciliation; **do not bulk-mark them completed, delete them,
  or launch replacements**.
- Follow-up read-only scan-record audit on the **deployed** `de4357c`
  build confirmed all **91 of 91** locally `Running` Vulners records
  were created over 24 hours previously, from **October 6–31, 2026**:
  71 identified as `nessus-offset`, 20 `manual-or-other`,
  all 91 marked `bridgeScan`, **none with `bridgeScan.taskId`
  or `bridgeScan.jobId`**. By customer: `CO-9150` 30,
  `CO-9153` 19, `CO-9156` 16, `CO-9159` 14,
  `CO-9162` 10, `CO-9165` 2. This is conclusive evidence
  of stale *local* state, not a verified remote-task outcome.
- Stored scanner findings across these customers: Nessus
  **53,863**, Vulners **82** (`CO-9150` 27;
  `CO-9153` 55; the remaining four 0).
  Finding-count disparity cannot measure executed host parity.
- Historical legacy task creation in `runVulnersBridgeScanAsync` names
  each Greenbone target `[<local SCAN id>] <target> <scan name>`.
  A read-only exhaustive **gvmd** name/ID/report inventory on
  Vulners-v2 may permit recovery matching using that embedded
  scan ID. First verify gvmd reports and scope; names alone cannot
  confirm a successful or complete scan. The bridge
  `GET /api/v1/scans` endpoint has been observed to truncate large
  inventories, so do not use its result to conclude tasks are absent.
- On `Vulners-v2` (host-reported public IPv4
  `165.245.167.168`), Docker `greenbone-community-edition-gvmd-1`
  and `greenbone-community-edition-pg-gvm-1` were healthy.
  Read-only `gvmd.public.tasks` contained **7,531** records.
  Primary task schema includes numeric `id`, text `uuid`,
  text `name`, integer `run_status`/`target`, and Unix time
  integers `creation_time`/`modification_time`.
  **Endpoint identity resolved:** DigitalOcean control-plane details
  show `165.245.151.124` is the **Reserved IP** of this same
  `Vulners-v2` droplet (primary IPv4 `165.245.167.168`), with
  scanner API exposed on port 8088. The application targets that
  Reserved IP using `GMI_SCANNER`. The scanner's 7,531-task history
  is therefore on the intended droplet. A `0` active-task count
  does not validate remote completion; the authenticated API's
  full inventory should still be cross-checked.
- Read-only scanner DB follow-up found **488** Greenbone tasks
  with names matching `^\\[SCAN-[0-9]+\\]` and **65** distinct
  embedded application scan IDs. Per gvmd's `task_status_t`
  in `src/manage.h`: `1=Done` (451 tagged tasks),
  `2=New` (1), `12=Stopped` (23),
  `13=Interrupted` (13). These statuses are task metadata,
  **not** independently verified complete reports or a match to
  all 91 stale application records. Do not confuse 65 distinct
  IDs with a count of stale IDs recovered.
  Source: https://github.com/greenbone/gvmd/blob/main/src/manage.h
- Read-only `gvmd.reports` join to 488 application-tagged tasks
  confirms every **451 Done** tasks has at least one report with
  `scan_run_status=1` and valid non-zero start/end timestamps.
  These Done tasks represent **61** distinct embedded local `SCAN-*`
  IDs. Among the remaining tagged tasks: 23 Stopped and 13 Interrupted
  have reports but no completed report; 1 New task has no report.
  This is evidence of remote execution and report timestamps, **not**
  proven per-host coverage, report completeness/pagination, or an exact
  join to the **91** stale local scans. Remote task *names* include
  the app `[SCAN-*]` prefix but expose hostnames and must not be
  copied wholesale into reports or GitHub.
- Cross-host **read-only ID reconciliation** (65 remote `SCAN-*`
  names, 488 remote tagged tasks, 451 report-confirmed Done tasks)
  against the six customers' `app_scans` records:
  `Running` **91** → **55** distinct local scans have at least one
  matching remote task with a completed report; **36** have no
  tagged remote task in this inventory; **0** matched only unfinished
  remote tasks. Per company (matched/no tagged task): `CO-9150`
  22/8; `CO-9153` 11/8; `CO-9156` 9/7; `CO-9159`
  8/6; `CO-9162` 3/7; `CO-9165` 2/0.
  `Failed` **15** → **7** tagged matches, **3** with at least one
  completed remote task report. `Completed` **29** → **zero**
  matches in this *name-filtered* remote inventory; historical
  scan/import paths must be independently inspected.
  **3** remote tagged app scan IDs are absent from the selected
  six customers' local records. The counts support recovery triage,
  **not 55 fully completed multi-host scans**: compare expected
  target identities and all remote task/report outcomes before
  any status or finding mutation.
- Verified root-cause design defect in deployed `de4357c`
  `lib/store.ts`: `nessusBridgeTargetsForCompany(companyId)`
  accumulates aliases from **all stored Nessus scans** and asset
  values from **historical Nessus findings** for the customer,
  instead of taking the actual covered host set from the specific
  completed Nessus occurrence. `vulnersBridgeOffsetTick()`
  reuses the accumulated cross-scan list for each due Nessus
  schedule, thereby multiplying overlap and unconstrained active
  bridge work. The old `startScan` starts one asynchronous
  in-process target loop per offset record; remote task IDs are
  not persisted in `bridgeScan`. New scheduling must use a
  single verified occurrence, customer-approved exact target
  intersection, durable per-host task id and independent
  completion/report proof. No automatic restart or legacy
  scheduler reactivation.
- Read-only SQL analysis of all 91 stale local `Running`
  `vulners` records shows **13,310 stored target slots** across
  11 company × origin groups; within those groups, only
  **1,501 grouped distinct target expressions** and **11,809
  repeated target slots** (**88.7%**). These 1,501 grouped
  distinct expressions **must not** be treated as an estate-wide
  union because targets can overlap across origin groups.
  Among the **71 Nessus-offset** records there are
  **11,238 target slots**, **983 grouped distinct expressions**
  and **10,255 repetitions (91.3%)**. The remaining
  **20 manual/other** records have **2,072 target slots**,
  **518 grouped distinct** and **1,554 repetitions (75.0%)**.
  **55 of the 91** stale scans requested more than 100 targets
  (47 offset and 8 other). For `CO-9159` specifically, the
  10 offset scans requested 4,914 target slots but only
  637 distinct target strings within that group.
  Local requested slots do not prove corresponding remote task
  creations, successful executions or host coverage.
- Scanner-side schema inspection identifies direct evidence joins:
  `tasks.target` → `targets.id` (`targets.hosts`,
  `targets.exclude_hosts`), `reports.task` → `tasks.id`,
  `report_hosts.report` → `reports.id` (`host`,
  `hostname`, `start_time`, `end_time`), and
  `results.report` → `reports.id`. The last two carry
  sensitive host identifiers; only share aggregate counts or
  private encrypted evidence across hosts. Audit the **latest
  completed report per task** rather than joining all reports and
  double-counting repeated reports. A done report without a
  `report_hosts` row does not prove zero authorized targets or
  complete host-level coverage; treat as unresolved.
- Latest read-only gvmd host-evidence aggregate: of **451 Done**
  application-tagged tasks with a completed report, **441** tasks
  have timed `report_hosts` rows and **10** have **zero**
  `report_hosts` rows. There are **553** aggregate report-host
  rows across the 451 selected **latest completed report per task**.
  All 488 tagged tasks have a nonempty configured target record;
  no tagged task has nonempty `targets.exclude_hosts`.
  An individual report-host entry is not necessarily an independently
  identified authorized scanned endpoint. Count unique host
  identities only after comparing report-host IP/hostname, the
  configured target and the original approved customer scope.
  In particular, a completed report with zero `report_hosts`
  entries must not be treated as positive coverage or as clean.
- Follow-up strict target/report-host audit on **451** Done,
  report-confirmed tasks: **302** tasks had an exact case-insensitive
  text match between `targets.hosts` and `report_hosts.host` or
  `report_hosts.hostname`; **139** had timed report-host rows
  but no direct text identity match; **10** had no report-host
  rows. The 10 missing-host cases are confined to:
  `SCAN-269452` (2), `SCAN-269453` (3),
  `SCAN-269454` (3), `SCAN-272220` (1),
  `SCAN-276454` (1). The 139 text mismatches
  may reflect hostname→IP representation, DNS aliases, or
  actual mismatched identities. Never count them as
  unauthorized nor successfully covered without an
  independently verifiable host binding. The 302 direct
  matches still do not prove authorization or complete
  multi-host application scans.
- Follow-up classification of all **139** completed tasks with
  report-host rows but no direct target-text identity match:
  every configured target was classified as a **hostname**;
  `report_hosts.hostname` was empty across all of them,
  while `report_hosts.host` contained IPv4 addresses.
  They account for **251 report-host rows** (not deduplicated
  devices or verified historical DNS resolutions). Investigate
  scan-time `report_host_details` hostname metadata and
  `results.hostname` before making any association.
  Do **not** use present-day DNS alone to claim historical
  coverage or silently bind IPs to customer hostnames.
- **Historical hostname identity now fully reconciled for
  report-host-bearing Done tasks:** all **139** tasks whose
  `targets.hosts` hostname did not directly match
  `report_hosts.host/hostname` had an exact scan-time
  hostname match via `report_host_details` entry with
  `lower(name) = 'hostname'` and the configured target.
  `results.hostname` independently matched on **134** of
  these 139 tasks. Thus among 451 Done tasks: **302**
  direct report-host text matches + **139** exact historical
  report-host-detail hostname matches = **441** tasks
  with report-backed configured-target identity; **10**
  tasks still have no report-host rows. Historical hostname
  details support associating each report row's IPv4 to the
  configured hostname at the time of the scan, without a
  present-day DNS assumption. The remaining gates are
  individual scan-scope completeness, task/report findings
  ingestibility, and authorized Nessus occurrence coverage.
- Historical request-to-remote task accounting on the **55** stale
  `Running` app scans with tagged gvmd task matches:
  **9,691** stored requested target expressions across these
  scans (each distinct *within its respective scan*, but often
  repeated across different scans), versus only **456** matching
  remote Greenbone tasks, of which **423** have Done status and
  completed report evidence and **33** do not. Every one of
  the 55 local scans has fewer tagged remote tasks than its
  stored requested target expressions. **41** local scans have
  all their *created* remote tasks Done; the other **14**
  also have incompletely terminated remote tasks. Per company
  `requested / remote / Done` (for linked stale app scans):
  `CO-9150` 3564/294/262;
  `CO-9153` 1339/110/109;
  `CO-9156` 330/22/22;
  `CO-9159` 4418/19/19;
  `CO-9162` 30/9/9;
  `CO-9165` 10/2/2.
  The **9,235** difference between request slots and created
  task counts measures the missing task *assignments*, not
  9,235 independently approved or vulnerable hosts; the
  legacy source targets were overinclusive and repetitive.
  No local scan is eligible for full-success status or
  automatic backfill based on task counts. Keep the
  36 unmatched stale app scans and 15 failed app scans
  visible for further separate investigation.
- Aggregated read-only `gvmd.results` inventory for latest
  confirmed completed reports among all **451** Done
  application-tagged tasks: **441** reports have result rows,
  **285** reports have positive-severity rows, total
  **20,045 result rows**, including **1,625** severity >0,
  **1,048** severity ≥4, and **405** severity ≥7; **zero**
  reports marked `processing_required <> 0`. Compare
  cautiously against the six customers' **82** local
  `vulners` app finding records: results contain recon
  data, can have no CVE, may repeat findings across scans,
  and include some reports linked to local failed or
  unmatched scan IDs. The finding-count difference is a
  strong ingestion-audit lead, **not** a verified number
  of missed actionable vulnerabilities. The deployed
  `vulnersBridgeJobFindings()` code discards result rows
  lacking a nonempty `cves` array and strictly checks
  `r.host === configured exact target` on its reviewed
  path; this may fail hostname-configured targets whose
  reporter uses IPv4 unless historical identity mapping
  is validated in the connector and reflected in its
  scope contract. Read-only inspect scanner CVE reference
  schema, bridge report completeness and API pagination
  before any backfill or status mutation.
- The `gvmd` schema includes `nvts(oid,cve,name,cvss_base)`
  and `result_nvts(id,nvt)` / `results(result_nvt,nvt)`.
  Among **20,045** result rows from the 451 selected latest
  completed GMI-tagged reports, **20,016** have nonempty
  `results.nvt`, representing **956** distinct NVT
  identifiers; **all 20,045** have a nonnull
  `result_nvt` integer. A nonnull foreign-key field
  does not prove successful NVT metadata resolution,
  nor that any NVT maps to a valid CVE; test both
  direct OID and `result_nvts` joins and independently
  validate the presence of CVE identifiers before
  building an importer. `nvts` metadata may be
  updated after historical scans; keep that provenance.
- Read-only `result_nvts` → `nvts` reference audit
  across all **20,045** results in the 451 GMI-tagged Done
  tasks' latest complete reports: **20,045** result-to-NVT
  reference rows resolved, **20,016** results with current
  `nvts` metadata, **0** direct/referenced NVT OID
  disagreements. **2,635** results were associated with a
  `nvts.cve` text field containing a CVE-pattern match,
  including **1,172** positive-severity results of the
  **1,625** positive-severity rows (**72.1%**),
  **901** severity ≥4 and **352** severity ≥7.
  **453** positive-severity results had no matching CVE-pattern
  metadata, and **359** distinct CVE-linked NVT OIDs
  were represented (not 359 distinct CVEs or endpoints).
  These are potential historical recovery candidates, not
  directly importable unique findings. Validate per-result
  target/report-host linkage, CVE parsing, duplicate keys,
  reporting completeness, and current-metadata-vs-scan-time
  provenance; treat non-CVE findings as separate security
  observations instead of silently declaring them clean.
- Direct scan-time target/report host attestation of results
  from the latest completed reports on the **451** GMI-tagged
  Done tasks: **all 1,172** positive-severity result rows with
  CVE-bearing NVT metadata were linked to a
  `report_hosts.host` inside the same report whose
  `report_host_details` hostname or direct
  `report_hosts.host/hostname` matched the task's
  configured Greenbone target; **zero** such rows
  failed this attestation. All **352** high/critical
  CVE-linked rows passed, as did all **453** positive
  severity rows without a matching CVE. This proves
  report-internal host binding to a configured Greenbone
  target, **not** that the historic target had independent
  customer authorization, appeared in a particular
  completed Nessus run, or that any full legacy app scan
  covered all requested hosts. The CVE counts reflect
  NVT metadata as currently stored, not necessarily an
  immutable scan-time snapshot. Deduplicate by customer,
  task/report/result/host/CVE with explicit provenance
  before importing any finding.
- CVE fan-out/dedup read-only audit using latest complete
  Greenbone reports from application-tagged Done tasks and
  the currently stored `nvts.cve`: **2,300** individual
  CVE references across positive-severity result rows,
  **541** distinct CVE identifiers, **1,867** distinct
  `(application scan ID, reported host, CVE)` combinations,
  **157** distinct `(application scan ID, reported host)`
  combinations, **36** scan IDs with CVE-bearing positive
  results, and **1,094** CVE references originating from
  severity ≥7 results. The latter is *not* a count of
  high/critical unique vulnerabilities (one result may
  reference multiple CVEs). This global 36-ID result
  **must still be joined against local Running vs Failed
  vs Completed status**; some app-tagged tasks were outside
  the 55 matched stale Running scans. Current `nvts`
  metadata can change after scan execution; do not pretend
  every CVE was observed in the historical feed version.
  Host identity was validated at report level separately.
  Deduplicate and compare existing app findings before
  any transactional recovery.
- Cross-host scan-status ownership reconciliation of the
  **36** Greenbone app scan IDs with positive-severity CVE
  references: **34** match local `Running` records
  among six customers, contributing **2,260 CVE references**,
  **1,839 distinct within-scan (reported host,CVE) pairs**,
  and **1,070 high/critical CVE references**. The other
  **2** Greenbone scan IDs (**40 CVE references**,
  **28 within-scan host/CVE pairs**, **24 high/critical
  references**) match **no local Vulners record in
  these six customers** and must remain quarantined
  pending provenance/ownership review. `Failed` and
  `Completed` local scan cohorts have no CVE-bearing
  remote tagged data in this audit. Per customer running
  `scan IDs / refs / distinct within-scan host-CVE pairs /
  high-critical refs`: `CO-9150` 21/1869/1454/804;
  `CO-9153` 5/328/328/246;
  `CO-9156` 2/34/28/16;
  `CO-9159` 1/6/6/0;
  `CO-9162` 3/16/16/4;
  `CO-9165` 2/7/7/0. This is *not*
  a count of novel vulnerability records: cross-scan
  host-CVE repeats and preexisting `app_findings`
  still require explicit deduplication. Among the
  55 stale Running scans with Done remote report
  evidence, **21** have no CVE-bearing positive-severity
  references in this audit, which does not prove a
  clean or complete scan.
- Follow-up **all-customer**, read-only local ownership/findings
  audit of Greenbone's **36** CVE-bearing tagged app scan IDs:
  **34** match local `Running` `vulners` records for
  the six companies (**2,260** CVE references,
  **1,839** scan-host-CVE pairs). The other **2** are
  **absent from the entire local `app_scans` table**,
  not merely outside the six-company filter: **40**
  CVE references and **28** scan-host-CVE pairs.
  Preserve these as orphaned provenance, do not
  associate them with any customer or backfill them
  without additional independent ownership proof.
  Among **82** currently persisted `vulners` findings
  in the six customers, **57** (55 at `CO-9153`,
  2 at `CO-9150`) reference one of the 36
  CVE-evidence scan IDs and a locally `Running`
  scan; the other **25** are not attached to those
  36 IDs. All **82** have distinct local
  `(asset,CVE)` pairs **within each customer**,
  and none has an absent local scan foreign
  reference in the query. The 57 proves the
  legacy code ingested *some* partial findings
  despite the parent scan remaining Running;
  **do not** equate the 1,839 remotely deduped
  within-scan pairs minus 57 local findings with
  missing novel findings. A robust comparison
  must normalize scan-time hostname/IP aliases,
  deduplicate across runs per customer and
  compare actual per-host CVE identities and
  provenance, including the remaining 25 findings.
- Per-folder expression counts: folder 7 = 62; 11 = 62;
  114 = 13; 136 = 182; 253 = 10; 507 = 3. Literal
  expressions were not repeated between folders; this is **not**
  proof that CIDR/range networks, DNS aliases, or resolved hosts
  do not overlap.
- Follow-up network classification (read-only): folder 11's **21 distinct IPv4 CIDRs** jointly cover **352 IPv4 addresses** (raw address-space union; no adjustment for network/broadcast or target exclusions). Its other **41** distinct target expressions are not yet reconciled against those CIDRs. Folder 136's **182** distinct target expressions were all classified as **hostnames**, including 55 hyphenated expressions in each of its two running scan definitions. No actual DNS resolution, completed-host evidence, or Nessus-vs-Greenbone run parity was established. The **332 expressions are not 332 effective endpoints**.
- Current `scannerTargetMatcher` and plan preview each limit a
  reviewed customer scope to 100 expressions; the reviewed
  Vulners adapter supports exact hosts/IPs, not range expressions.
  Do **not** bypass these checks or bulk fan out unverified scopes.

**Remaining priority:** classify network and hyphen expression forms,
determine exact effective endpoints, independently review folder-to-company
ownership and approved windows, then implement bounded per-scan targeting
and proof-backed dispatch. Do not activate the legacy inventory sweep.

## Remaining release gates for actual parity

1. Read the current **Nessus scan definitions** for each independently verified
   folder and map configured targets to the exact customer and individual scan,
   including target groups, uploaded files, exclusions and any per-run overrides.
   Treat unknown/complex forms as blockers, not empty scopes. Approved route
   equality alone is not authoritative proof of Nessus configured targets.
2. Independently verify the **latest completed Nessus run**, its historical ID
   and actual covered hosts (including clean hosts); repeat this for each
   recurrence. Do not infer success from a scheduled time or from findings.
3. For each exact covered and independently approved host, create one safely
   reserved Greenbone task at a time, at the permitted window, with live complete
   `gvmd` capacity evidence. Keep all admission flags OFF until the dedicated
   worker and release gates pass.
4. Persist task IDs, verify terminal Greenbone reports (including zero-finding
   reports), validate pagination/host identities, and compare actual verified
   covered host sets by `companyId` and Nessus occurrence.
5. Present per-company `nessusCovered`, `greenboneCovered`,
   `missingGreenboneCoverage`, `failed`, `notYetDue`, `notAuthorized`
   and timestamps. Only report 100% parity when every due, authorized host
   has verified completed Greenbone evidence. Source finding count equality is
   neither required nor a valid proxy.
6. After full live acceptance of the one-host GMI canary, release under approved
   maintenance windows and customer permissions. Never re-enable the legacy
   `VULNERS_BRIDGE_SCHEDULER_ENABLED` inventory-wide sweep as a shortcut.

Run the pure regression with:
```bash
node --experimental-vm-modules --test tests/approved-scanner-target-parity.test.mjs
```

A merge alone does not deploy this endpoint or launch any work.

## Exact historical finding overlap — November 5, 2026 (read-only)

The two-host HMAC audit completed successfully against the six approved
application company *identities* (approval of active targets remains separate).
Its scanner-side evidence baseline was **34** locally stale Running scans,
**2,260** CVE references, **1,839** distinct within-scan reported-host/CVE
pairs, and **1,070** high/critical references. It deduplicated candidate
observations **across repeated scan runs per company and configured target**,
then compared keyed `(company, configured target, CVE)` identities to the
currently stored 82 Vulners application findings. Output:

| Company | Linked stale scan IDs | Historical target/CVE pairs | Already in app | Absent from app |
| --- | ---: | ---: | ---: | ---: |
| CO-9150 | 21 | 812 | 2 | 810 |
| CO-9153 | 5 | 114 | 55 | 59 |
| CO-9156 | 2 | 25 | 0 | 25 |
| CO-9159 | 1 | 2 | 0 | 2 |
| CO-9162 | 3 | 15 | 0 | 15 |
| CO-9165 | 2 | 2 | 0 | 2 |
| **Total** | **34** | **970** | **57** | **913** |

**913** distinct historical, report-backed configured-target/CVE
combinations are absent from the app; only **57** (5.88%) are represented.
The **25** other existing application Vulners findings have HMAC identities
absent from this historical subset and **must be preserved**, not
automatically resolved or deleted. All 34 included scan IDs are currently
stuck in local `Running`; no local app status or findings were changed.
The two remotely tagged CVE-bearing IDs with no `app_scans` owner
anywhere in the database remain **quarantined** and excluded from this
970/913 inventory.

**Interpretation and gates:** 913 is not the number of actively open
vulnerabilities, nor a license to relaunch 9,691 historical target
assignments. It is a vetted, scan-time report-host-attested historical
*comparison candidate* count. Before any import: verify customer ownership
and authorized Nessus occurrence scope for each source target, freeze
immutable Greenbone task/report/result IDs and scan timestamps, validate
CVE provenance (current NVT metadata can differ from scan-time feed),
ensure results pagination and historical host identity, respect existing
app finding states, and build a reversible idempotent dry run.
The per-scan parent record must remain **partial/incomplete**
until its independently verified expected scope is complete.
Do not equate `Completed` remote report with completed local scan.

The HMAC comparison script also supports a follow-up **read-only**
severity rollup of the 913 absent historical candidates, keyed by
their maximum observed severity across repeated remote reports:
critical ≥9; high 7–8.9; medium 4–6.9; low >0–3.9. It fails
closed if these groups do not sum to the verified 913. The
severity histogram is not yet confirmed against production
and is **not** a current active-exposure count. Prioritize
`CO-9150` (810 of 913 absent historical pairs) as an
internally owned recovery test cohort only after independent
source-scope review; do not use recovery work to reactivate
the legacy inventory-wide scanner scheduler.

**Confirmed maximum historical severity (same 913 deduplicated candidate
identities)** from the successful privacy-preserving scanner audit:

| Company | Critical ≥9 | High 7–8.9 | Medium 4–6.9 | Low >0–3.9 | Total |
| --- | ---: | ---: | ---: | ---: | ---: |
| CO-9150 | 62 | 258 | 391 | 99 | 810 |
| CO-9153 | 19 | 24 | 14 | 2 | 59 |
| CO-9156 | 0 | 13 | 7 | 5 | 25 |
| CO-9159 | 0 | 0 | 2 | 0 | 2 |
| CO-9162 | 0 | 4 | 6 | 5 | 15 |
| CO-9165 | 0 | 0 | 2 | 0 | 2 |
| **Total** | **81** | **299** | **422** | **111** | **913** |

The **380 critical/high** missing historical host-CVE pairs are
not 380 *currently open* vulnerabilities or necessarily present-day
risks.

**Confirmed scan-time metadata audit on Vulners-v2 (November 5, 2026):**
The query ran in a read-only transaction and rolled back. Of **1,172**
positive-severity result rows associated with current CVE-bearing NVT
records, all **1,172** have nonblank result NVT versions, result
timestamps no later than the associated report end, and no NVT record
created or modified after scan completion; **zero** are missing NVT
version, created-after-scan or modified-after-scan. Oldest checked
completed report end: **2026-10-10 03:47:41 UTC**; newest:
**2026-11-01 04:07:58 UTC**. **154** latest completed reports contain
these rows: **144** in October (**1,056** result rows), **10**
in November (**116** rows). This 1,172 refers to **result rows, not
2,300 CVE fan-out references or 913 deduped missing combinations**.
Result metadata chronology is a useful corroborating gate, not proof
of immutability or contemporary vulnerability state. All data came
from read-only report queries; no Greenbone or app updates occurred.

The separate read-only scanner-side
`scripts/audit/greenbone-nvt-scan-time-provenance.sql` checks whether
the **current NVT metadata was created or modified after the historical
report end**, counts result-embedded NVT versions, and groups CVE-bearing
completed reports by UTC month. The query is evidence triage only:
`nvts.modification_time > reports.end_time` means current
metadata may not represent what the historical scan originally
knew, while an earlier modification time alone cannot prove that
the historical CVE association was immutable. It must not update
findings or rewrite scan completion states. **320** belong to internal customer CO-9150. Preserve per-result
timestamp, source identity and NVT provenance before representing these
as historical observations; never automatically open, close, or
escalate current remediation tickets based on unreviewed old results.

The temporary HMAC token was pasted into user-facing chat in an earlier
step; its initial one-time secret was also exposed there and was
subsequently rotated. Treat any exposed key as compromised and use
fresh private keys for any new round of comparing hashes. Delete
transient evidence token files and unset shell secrets after auditing;
do not commit tokens, HMAC keys, hosts or CVE mappings.

## Privacy-preserving existing-finding overlap audit (read-only)

Two audit scripts are staged on this branch, **not** connected to production
routes, imports, workers or timers:

- `scripts/audit/prepare-local-vulners-hmac-token.mjs` runs on
  **Vuln-NYC1**. Its read-only app DB transaction loads the 91 locally
  Running scan-ID/customer associations and all 82 existing Vulners
  `(company, asset, CVE)` keys. It HMAC-SHA256 hashes every normalized
  `company + NUL + lower(trim(asset without trailing dot)) + NUL + upper(CVE)`
  tuple with a **one-time 32-byte random key** provided in the local
  `GMI_AUDIT_HMAC_HEX` environment variable. Its gzip-base64 payload
  contains **only** scan IDs and customer identifiers plus keyed hashes
  of existing finding identities. It prints a token, not raw findings.
- `scripts/audit/compare-greenbone-to-app-hmac.py` runs on
  **Vulners-v2**, with the same one-time key and the token manually
  transferred between approved operator terminals. Its read-only
  PostgreSQL query selects each Done tagged task's latest fully ended
  report, joins positive-severity NVT CVE references, and checks
  report-internal host identity against `targets.hosts` using
  direct host fields or historical `report_host_details`.
  It compares candidate `(company, configured target, CVE)` HMACs
  against local existing finding HMACs, aggregates **across repeated
  scans**, and prints only per-company matched and unmatched counts.
  The script fails closed unless the full remote baseline is
  unchanged (34 linked scan IDs, 2,260 CVE references, 1,839
  distinct scan/reported-host/CVE combinations, 1,070 high/critical
  references), and never processes the two globally orphaned IDs.

Neither tool writes to either DB; both require independently controlled
administrative hosts. Key material **must never** be shared in chat,
logs, PRs, or third-party services. Keep it in ephemeral admin shells;
unset immediately after the audit. HMACs are not encryption of
fingerprints if the key is disclosed. Historical NVT CVE metadata
may change, and a remote CVE not present in the application is **only**
a historical candidate, not an automatically importable or
currently open finding. Authoritative customer and completed-Nessus-run
scope and report-ingestion provenance must be verified separately.

## Recovery source-identity preflight (verified below)

`scripts/audit/greenbone-recovery-identity-preflight.sql`
is a scanner-local, read-only PostgreSQL query to identify
available task, report and result immutable UUID columns,
result timestamps, NVT versions and source-NVT metadata
for a provenance-preserving historical import plan.
It emits only aggregate counts and column definitions,
not customer hosts, CVEs or raw IDs. Its results are not
yet verified against the scanner. It intentionally includes
the two remote CVE-bearing orphan IDs in the overall
completed-report baseline; **neither is authorized
for import**. Do not promote any imported observation to
currently `Open` without a separate recent scan
and customer-scope authorization. No write-mode migration,
data transfer or import has been approved or performed.

## Application persistence schema preflight — confirmed November 5, 2026

The app-local read-only preflight completed successfully against production
and confirmed **91** `vulners` scans in `Running` and **82** existing
`vulners` findings, all `Open` (27 at CO-9150 and 55 at CO-9153).

Crucially, `public.app_findings` has **no indexes, primary key,
uniqueness constraints, or other database constraints** in the
schema/index/constraint query. Its `id`, `company_id`,
`scan_id`, `connector`, `status`, `cve`, `asset`,
`payload` and `last_seen` columns are all nullable.
In contrast, `public.app_scans` has a primary key on `id`,
several nonunique indexes, a JSON-object check on `payload`,
and ordering/hash shape constraints. Neither table's DDL
should be changed without a separate migration risk analysis.

**Safety decision:** do NOT bulk insert recovery records directly into
`app_findings`, which would lack database-enforced de-duplication and
could be rewritten/reconciled by the current application store. Instead
design a *separate*, source-UUID-keyed historical observation store
with explicit uniqueness, provenance and quarantine constraints.
Its records must not be counted as live `Open` vulnerabilities,
must not alter remediation state, and must not change any of the
91 `Running` scan rows or 82 existing findings. Start by testing
a standalone offline, no-write preview on synthetic fixtures,
then review a strictly authorized real-data dry run. No database
migration or production writes have occurred.

## Source identity preflight — confirmed November 5, 2026

The scanner-local, read-only identity preflight completed with `ROLLBACK`:

| Check | Result |
| --- | ---: |
| CVE-bearing positive result rows | **1,172** |
| Distinct source Greenbone tasks | **154** |
| Distinct completed reports | **154** |
| Distinct result rows | **1,172** |
| Result rows with task UUID | **1,172** |
| Result rows with report UUID | **1,172** |
| Result rows with result UUID | **1,172** |
| Result rows with NVT version | **1,172** |
| Result rows with valid observation timestamp | **1,172** |
| Result rows with source NVT metadata existing by scan time | **1,172** |
| Result rows without linked source NVT | **0** |

`tasks.uuid`, `reports.uuid`, `results.uuid`, `targets.uuid`
and `nvts.uuid` exist in the observed schema. `report_hosts`
and `report_host_details` support scan-time target-identity checks.
The 154 tasks and 1,172 rows are source-level figures that include the
two orphaned application scan IDs; they are **not** counts of authorized
importable observations. Preserve task/report/result UUIDs, NVT OID and
version, report timestamps and attested configured target before any
idempotent dry run. `913` is the deduplicated historical missing
company-target-CVE count, not the number of result rows or remote tasks.
This check made **no production changes**. The next step is an explicit,
no-write import preview with consented target scope, quarantine of orphaned
provenance, and no lifecycle status changes.

## Standalone historical observation preview (offline, development only)

The branch now contains
`scripts/audit/preview-greenbone-historical-manifest.mjs`
and `scripts/audit/preview-greenbone-historical-manifest.test.mjs`.
This is **offline-only** code that reads three explicit local JSON inputs
and produces **aggregate-only** result counts; it has no database,
scanner API, network or write functionality.

Inputs are versioned objects:

- `--manifest`: `{version:1,observations:[...]}` with customer ID,
  originating local scan ID, exact configured target, CVE, task/target/
  report/result UUIDs, NVT OID/version, severity, three scan-time UTC
  timestamps, complete report statuses, host attestation evidence, and
  `cveProvenance: "report-snapshot"`.
- `--approvals`: `{version:1,approvals:[...]}` with explicit approved
  customer/scan/exact target, unique approval ID, reviewer, Nessus
  occurrence ID, and approved UTC date range.
- `--existing`: `{version:1,findings:[...]}` listing current app
  company/asset/CVE identities in an access-controlled location.

**Important:** the current 913-candidate HMAC analysis does **not**
supply the source report-snapshot CVE attribution or independently
reviewed scope required by this more demanding preview. Until the
source report snapshot evidence and approvals are actually produced,
the offline preview is useful only on synthetic fixtures.
Do not bypass the requirements merely to reach 913, and do
not treat company identifiers from historical imports as approvals.

The preview rejects ambiguous duplicate approvals, conflicting
source UUID/CVE identities and malformed input. It quarantines
unapproved targets, locally orphaned scan IDs, incomplete report
provenance, unknown historical CVE lineage, wrong timestamps, and
out-of-window observations. It deduplicates by immutable source
task/report/result UUID plus CVE, then aggregates distinct
company/configured-target/CVE pairs with **maximum historical**
severity. It prints `wouldStageHistoricalOnly` and counts by company;
both `wouldChangeLiveFindingStatus` and
`wouldChangeAppScanStatus` are invariably zero by construction.

**Tested November 5, 2026 on Vuln-NYC1:** `node --check` succeeded and
`node --test scripts/audit/preview-greenbone-historical-manifest.test.mjs`
passed **4/4 tests, 0 failures**. Tests exercise exact-target authorization,
orphan quarantine, deduplication, conflicting source identities and no-write
status invariants. These are **synthetic inputs**, not proof of source
CVE attribution or active customer approval.

No schema migrations, historical observation tables, production imports,
live finding transitions, jobs, or scans have been deployed.

## Historical CVE lineage diagnostic (staged, read-only)

The schema preflight confirms that local `app_findings` currently lacks
database-enforced uniqueness and that direct historical insertion is
unsafe. The **synthetic** offline preview passed 4/4 tests on
Vuln-NYC1, but its input markers `hostAttestation` and
`cveProvenance` are assertions supplied by an input manifest:
they are **not proofs** unless generated by a separately trusted,
report-reading exporter and checked against scan-time evidence.
Do not make real import decisions from unverified self-declared flags.

`scripts/audit/greenbone-cve-lineage-readonly.sql` is staged to
inspect whether GVM `results` / `result_nvts` have embedded
CVE metadata independent of the mutable current `nvts.cve` table,
and whether recorded result NVT versions match current NVT version
fields. This is a read-only diagnostic with aggregate counts, not
a report snapshot or a proof of a CVE association. Until confirmed,
neither a historical importer nor a historical evidence manifest
may label a present-day NVT CVE lookup `report-snapshot`.

## Original CVE-lineage check — confirmed November 5, 2026

The read-only `scripts/audit/greenbone-cve-lineage-readonly.sql`
completed on Vulners-v2. All **1,172** currently CVE-bearing,
positive-severity rows have a stored observation NVT version.
**Zero** have a separately embedded CVE list in the scanned
`results` or `result_nvts` schema. The current `nvts`
table has no separately identified comparable NVT version field
for the version-comparison query: **zero** rows had a current version
value, meaning there were also zero possible direct version matches
or mismatches. For all **1,172**, current NVT metadata reports a
modification time no later than the historical report end.

**Provenance correction:** a historical result's stored NVT version,
together with a current NVT CVE list and early current
`modification_time`, is *supporting circumstantial evidence*,
not independently frozen scan-time NVT/CVE attribution. In particular,
a zero `differing_observed_and_current_version` count here
**does not** establish matched versions because there is no
comparison field at all. Do not claim a "report-snapshot"
CVE lineage from this source. The **913** missing historical
company/configured-target/CVE pairs remain comparison candidates,
not provenance-cleared historical import rows. All scans and
application finding records are unchanged.

Next inspect only safe read-only, aggregate report/source
capabilities for an immutable original CVE record (e.g.,
a retained exported GVM XML report or archived feed metadata).
Do not create or launch scans, download raw customer reports
into GitHub or chat, or bypass the strict preview's
`cveProvenance: "report-snapshot"` requirement.

## Saved result-text CVE corroboration — staged

A separate scanner-local, no-write query,
`scripts/audit/greenbone-result-text-cve-provenance.sql`,
checks whether *saved per-result description/summary/extra text*
actually mentions CVEs independently of the present-day
`nvts.cve` join. It prints only aggregate counts:
positive CVE results, rows with result text, rows with
any saved CVE references, rows mentioning any or all current
NVT CVEs, and rows with contradictory other-only CVEs.
The query does **not** print saved descriptions, hosts,
CVEs, report UUIDs, or targets, and rolls back.

Even full textual agreement, if present, would be
**corroborating evidence**, not automatic proof that
the text was immutable, sourced from a frozen NVT feed,
or sufficient to label a candidate `report-snapshot`.
If there is no saved CVE text, require an archived trusted
report/feed snapshot, or track provisional CVE associations
in a quarantined historical-only store. No live-finding
ingestion is approved by this audit.

## Saved-result text CVE check — confirmed November 5, 2026

The read-only `scripts/audit/greenbone-result-text-cve-provenance.sql`
finished successfully and rolled back on Vulners-v2.
`results.description` is a stored text field, but **none** of the
**1,172** positive current-NVT-CVE-associated historical rows had a
CVE identifier in saved result text. All 1,172 had non-empty saved
text, but **zero** mentioned any CVE, **zero** matched even one of
the CVEs now listed on their associated NVT, **zero** mentioned all
the currently associated CVEs, and **zero** mentioned only different
CVEs. These zeros are *absence of textual corroboration*, not
evidence of agreement or disagreement.

This corroborates the earlier finding that `results` stores an
observed NVT version and task/report/result UUIDs, but neither
`results` nor `result_nvts` contains an independently saved
original CVE list. The **913** absent company/target/CVE combinations
are therefore **provisional, current-NVT-mapped historical
reconciliation candidates**, not original-scan-time-CVE-proven
observations. The 380 Critical/High severities are *historical
maximum severities* on those candidates, not present-day exposures.
Neither zero postscan NVT modifications nor non-empty report
descriptions fills this proof gap.

**Do not** set `cveProvenance: "report-snapshot"` on a manifest
derived only from this `gvmd` join, backfill the 913 into live
`app_findings`, change the 82 existing finding statuses, complete
the 91 stale scans, or trigger new customer scans. Seek a
trustworthy contemporaneous feed archive or immutable independent
original report. Until then, handle current-feed-derived CVE
associations exclusively as provenance-uncertain historical
evidence candidates with a source lineage label. No production
data were modified by this audit.

## Preview treatment of current-feed CVE mappings — November 5, 2026

The offline preview was tightened on the audit branch. A manifest
row declaring `cveProvenance: "current-nvt-at-recovery"` is
**explicitly quarantined** as
`provisional_current_nvt_cve_mapping` and can **never**
increase `wouldStageHistoricalOnly`, even with all UUIDs,
host-attestation assertions, timestamps and target approval
fields present. Invalid or missing approvals take precedence
and quarantine as `unapproved_exact_target_or_orphan_scan`.
An unsupported lineage label remains
`unverified_scan_time_cve_lineage`. The preview still requires
an independently trusted source reader before accepting an
assertion of `report-snapshot`; JSON input by itself is
not authenticated evidence.

Two synthetic tests were added for fail-closed provisional and
missing-approval cases, bringing the suite to **six** cases.
**All six** synthetic cases passed on Vuln-NYC1 on November 5,
2026, with 0 failures, 0 skipped and 0 cancellations
(Node built-in test runner; ~119 ms elapsed). The additional cases
validate provisional current-NVT quarantine despite valid identifiers
and approved target assertions, plus denial of staging when approval
list is empty. Production records were not changed.
No app DB or Greenbone production code changed.

## Preview strengthening after 6/6 verification — same day

After all six synthetic cases passed, the offline preview was hardened
to bind each accepted observation to the **exact approved finished
Nessus occurrence ID** as well as company/app scan/exact target
and approval time window. A company and approved host alone no
longer suffice. The immutable source-event conflict check also
considers the Greenbone configured target UUID, app scan ID,
Nessus occurrence, host-attestation assertion, report timestamps,
NVT OID/version and evidence provenance, not just the source
result UUID and host/CVE. A reused Greenbone result UUID with
a contradictory target UUID now fails closed.

Two additional synthetic regression tests were added (eight total):
unmatched Nessus occurrence is quarantined, and contradictory
source-target UUID under a reused result UUID throws.
**All eight synthetic tests passed on Vuln-NYC1 on November 5, 2026**, with 0 failures, 0 skipped and 0 cancellations (Node built-in test runner, 116.210844 ms). The suite includes the exact Nessus occurrence and contradictory target UUID cases. No deployment or production mutation was performed. No production records or scan state changed.

The matching fields in a manifest remain self-declared unless
a trusted exporter verifies them against authorized Nessus
occurrence and immutable Greenbone report sources. The current
production evidence does not yet satisfy this provenance contract.

## Independent archive/source inventory — November 5, 2026

GitHub connector inspection of `gmi-security/Vuln` and relevant
`gmi-security` code found a **read-only** Nessus
history/host verifier (`lib/nessus-run-proof.ts`) and an
older application-side archive recorded in
`docs/vuln2-combined-release.md` at
`/home/codex/vuln-recovery/server-local-tools-20261011.tar.gz`.
The archive is explicitly a preservation of two
server-local scripts, **not** verified Greenbone NVT feed
or completed report evidence.

Historical DigitalOcean fleet metadata in
`gmi-security/infra_analysis` for October 10, October 20 and
October 27 records `Vulners-v2` with
`backupEnabled: false` on all three snapshots. This does
not prove that manual Droplet snapshots, on-disk backup
archives or third-party backups do not exist; no
DigitalOcean image listing has been retrieved.

Greenbone's documented Community Container setup maintains
a live VT feed in a `vt_data_vol` Docker volume and its
`get_reports` XML API can include NVT reference metadata
and `scan_nvt_version`. **A newly rendered XML report
may use contemporary NVT reference data:** having a
`<ref type="cve">` in an export made today is not,
by itself, an immutable original-scan-time NVT/CVE
association. Likewise, NASL files in the present-day
VT volume do **not** constitute a preserved October feed.

The branch now includes
`scripts/audit/greenbone-archived-evidence-inventory.py`.
It discovers potential archival files by **metadata only**
within bounded scanner-side directories and enumerates only
known live Greenbone data volumes and explicitly archive-
labeled Docker volumes. It does not read any customer report,
open ZIP/tar contents, mount drives, start scans, change
database rows or contact remote APIs. Its output is aggregate
categories and path hashes rather than raw paths/filenames.
Candidate file existence or old mtime is **not
provenance verification**. No result from this scanner-local
inventory has yet been supplied or verified.

A genuine scan-time attribution source would need a
trusted dated feed revision or independently preserved
original scan/export with demonstrably immutable CVE
references, plus source UUID, timestamp, approved
ownership and exact Nessus-occurrence match. If not
available, maintain the 913 combinations as *provisional
historical CVE associations* and do not bypass the
offline preview's quarantine.

## Scanner-local archive inventory — verified November 5, 2026

On **Vulners-v2**, the read-only bounded metadata inventory
completed successfully and reported only **3 recognized
backup/export directories** under the existing search roots.
No files matching explicitly named feed, report or database
backup categories were identified in that bounded search;
**26 files** were categorized as `other_archive_candidate`
without further metadata classification. Their file types,
contents and relevance are currently **unknown** and must
not be interpreted as 26 genuine historic feed backups.
The initial script only reported a count for these 26,
since no file name matched its reporting keywords.

**Three** recognized live Docker data volumes were detected:
- `live_vt_feed`: 95,105 `.nasl` files, 147 `.inc`
  files and one `.json`; earliest and latest observed NASL/INC
  filesystem modification date both **2026-11-03**.
- `live_gvmd_data`: four `.xml` files.
- `live_data_objects`: 24 `.xml` files.

These volumes have **no independently verified historical
feed revision**. The `.xml` extension alone does not
establish preserved scan report content, and feed file mtimes
are not NVT source revision dates. The historical
CVE-bearing completed report end dates are October 10–
November 1, 2026, preceding the observed live VT file
modification date. This comparison does **not** establish
that the NVT/CVE associations changed after scan time.

**Next audit:** classify metadata of the 26 generic
archive candidates without opening report bodies,
listing sensitive filenames, or altering scanner state;
then evaluate any relevant original report/feed snapshot
under restricted, explicit provenance checks.
Inventory scope was bounded and is not proof no
other backup exists. Preserve all 913 provisional
comparison candidates and the two orphaned scan IDs
quarantined; do not import to `app_findings`.

## Correction: the actual engineering objective is PER-NESSUS-SCAN TARGET PARITY

**Priority, November 5, 2026:** Ignore the separate historical CVE
recovery as a prerequisite for scan-target alignment. The user wants
**each Nessus scan definition / verified completed occurrence** to have
the **same explicitly authorized host/IP target set** scanned by
Vulners-v2/Greenbone. Combining all Nessus scans and old finding
assets for a company is an implementation defect, not intended
operational parity.

Verified source defect in the deployed `de4357c` runtime:
- `nessusBridgeTargetsForCompany(companyId)` unions historic aliases and
  finding assets from ALL customer Nessus scans.
- `vulnersBridgeOffsetTick()` calls that company-wide union on EACH
  Nessus scan's nominal +1h occurrence.
- `POST /api/admin/port-nessus-to-bridge` does the same thing and
  can launch full-company scans unless `dryRun=1`.
- `buildExternalScanPlan` previously selected the earliest company
  schedule and generated candidates against the whole company's
  reviewed route, not the exact configured targets of that
  Nessus definition.

This can launch many duplicate/out-of-scan targets. **Do not enable
the old scheduler or use the legacy port endpoint as a fix.**
An approved customer route is a maximum permission ceiling,
not a substitute for the source scan's target list. Completing
a scan is separately contingent on exact coverage and report identity.

New audit-branch files:
- `scripts/audit/nessus-per-scan-target-parity.mjs`:
  pure deterministic parser of the verified Nessus editor
  `settings.basic.inputs[].id="text_targets"` value,
  bounded IPv4 CIDR expansion, per-definition comparison against a
  reviewed exact target ceiling and proposed Greenbone set. It rejects
  unapproved, missing and unexpected targets; no customer-wide union;
  it never claims executed parity or dispatch permission.
- `scripts/audit/nessus-per-scan-target-parity.test.mjs`:
  synthetic per-scan equality, CIDR, overlap, exclusion and no-live-launch
  cases.
- `scripts/audit/audit-nessus-per-scan-targets.mjs`:
  read-only live `GET /scans?folder_id=` and
  `GET /editor/scan/{id}` against the **six historically known
  customer folders** (19 definitions), printing counts by definition
  only, not customer targets or credentials. It fails closed if
  any folder roster, parser or target expression changes. Historical
  company/folder mappings are NOT authorization to run Greenbone.

**Still needed for real synchronization:** independently reviewed
customer/host authority, a trustworthy exact target set from a
pinned completed Nessus occurrence (and completeness/exclusions),
a durable globally bounded per-target dispatch worker using that
set only, verified Greenbone task/report IDs, and fail-closed
per-source-scan accounting. Nothing has been launched, changed
in the DB or deployed by these audit files.

## Per-scan live editor audit — failed closed November 5, 2026

The synthetic per-scan target parity suite passed **8/8** on
`Vuln-NYC1` with 0 failed or skipped tests, but the *real*
Nessus editor target audit returned **0 of 19 parsed definitions**.
The `GET /scans?folder_id=<id>` roster checks found all **19**
expected scan IDs in six historically mapped folders (4, 5, 3, 2,
3 and 2 definitions respectively). Every single
`GET /editor/scan/<id>` read OR `text_targets` parse returned
the undifferentiated `editor read/parse failed` diagnostic.

**Do NOT interpret `configuredHostSlotsAcrossDefinitions: 0` as
zero Nessus targets**: it is merely the sum of *successfully parsed*
definitions, and none parsed. The prior read-only folder audit had
observed 332 configured target expression strings across these
same 19 definitions. The new audit's editor parser or HTTP read
contract must be diagnosed against the real API response shape;
do not guess, invent empty targets, enable scanning, or import data.

A new single-scan read-only diagnostic
`scripts/audit/diagnose-nessus-editor-target-shape.mjs`
returns only HTTP status, schema-field types and the count/type
of candidate `text_targets` nodes (never target values, scanner
URL, API keys or raw error messages). Use one known definition ID,
such as **9** in historical folder 7, to isolate 401/403/404,
response-shape or target-field encoding issues. Adjust the
parser only after that evidence; all scan launch flags remain
disabled. No production data or customer scans were changed.

## Nessus editor target parsing defect — isolated November 5, 2026

The scanner-side request was not failing: a single live read-only
probe of Nessus definition **9** confirmed HTTP **200**, valid JSON,
`settings`/ `settings.basic` objects, `settings.basic.inputs`
array of seven fields and exactly one `id="text_targets"` node.
That node's `value` field was **missing**; its `default`
field was a **string**, the form used by the installed Nessus
editor API for configured scan targets. The original per-scan
audit read only `.value`, so its **0/19** result was a
**parser defect, not zero target coverage or failed API access**.

Updated the audit-branch per-definition target extractor to use
`text_targets.default` when `.value` is missing/empty,
support `.value` on other variants, and reject non-string
or conflicting dual-field values rather than silently guessing.
Added three synthetic regression tests, for **11 total**.
The new 11-test suite and live 19-definition rerun have **not
yet been verified** on the actual Nessus server. No target
configuration, scanner processes, databases or customer status
were changed. The target-parity design remains strictly read-only.
