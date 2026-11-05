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
