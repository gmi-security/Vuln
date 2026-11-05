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
