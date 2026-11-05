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
