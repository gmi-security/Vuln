# Nessus → Greenbone: exact target parity per scan

## Production deployment (November 6, 2026 UTC)

The fail-closed target-planning and legacy-scheduler retirement source from
PR #123 **is deployed** on Vuln-NYC1 as merge commit
`23ec37532162c90d00e591e189e2ee62d523353f`.
The operator confirmed the new PM2 release is online, anonymous
`/api/health` reports both `readReady` and `writeReady` true,
PostgreSQL SQL authority remains enforced (epoch 2, revision 19587 at
acceptance), and the 23 targeted regression tests all passed.
The existing legacy checkout and cutover recovery directory were preserved.

**This is a deployed safety correction, NOT activation of Greenbone scanning.**
All three scanner launch flags were disabled at cutover. Current approved
routes, GMP capacity, maintenance windows, terminal report evidence and
real host-by-host parity still need production verification. The go-live
readiness audit is `scripts/audit/external-scan-live-readiness.mjs`.

## Purpose

The previous GMI Vuln Bridge path did **not** scan the same targets
as each Nessus scan definition. Its Nessus-offset scheduler used
\`nessusBridgeTargetsForCompany(companyId)\` to union all historically
observed Nessus scanned host aliases and finding assets across every
scan in a company. Then it started a separate multi-target Bridge
run after **each** scheduled Nessus definition. The admin "port
Nessus to Bridge" endpoint launched this same union, and the
nightly sync-all imported from the asset-inventory-wide sweep.

These paths caused overlapping, out-of-definition targets and
made it impossible to demonstrate one-to-one Nessus/Greenbone
target scope. The fix must use **the exact current Nessus scan
definition and a verified completed Nessus occurrence**, not
historical finding assets or a company-level target list.

## Verified baseline on Vuln-NYC1 — November 5, 2026

Read-only Nessus API:
- 19/19 individual definitions in six historically identified
  custom folders returned and parsed successfully;
- 1,650 unique exact target slots when summed **within** the
  19 definitions, NOT portfolio-unique machines or completed
  host assessments;
- 4 duplicates within definitions (IDs 18, 146, 158 and 138),
  accounted for without adding duplicate host jobs;
- zero unresolved target expressions;
- three separate definitions (IDs 14, 166, 169) each contain
  21 IPv4 CIDR expressions, yielding 352 candidate IP
  addresses per definition. An address in a CIDR is not
  proof Nessus actually scanned it, or that GMI has current
  permission to scan it on Greenbone;
- 16/16 synthetic per-definition audit parser tests passed;
- all six original company-to-folder associations are
  **historical**, not active customer route approvals.

**The 19 real configured target sets have NOT been compared with
corresponding completed Greenbone report-host coverage.**
The legacy app scan IDs do not durably link to a specific
completed Nessus historical occurrence. Do not invent that
association or retroactively claim equal scan execution.

## Staged code correction in this PR

1. \`lib/nessus-definition-targets.ts\` reads the actual Nessus
   editor response \`settings.basic.inputs[].id=text_targets\`,
   accepting \`.default\` when \`.value\` is absent. It rejects
   ambiguous/conflicting inputs, malformed expressions, host/IP
   exclusions, oversized networks and scan sets, and returns
   unique bounded exact configured targets.
2. \`nessusConfiguredTargetsForDefinition(scanId)\` uses a
   read-only authenticated \`GET /editor/scan/<id>\`.
3. The admin \`GET /api/admin/external-scan-plan\` requires
   independently approved Nessus **and** Vulners routes,
   checks actual Nessus **global roster** folder ownership
   and reads the configured targets for **each** enabled
   Nessus definition. It constructs no candidates if routes
   are unavailable. A missing, ambiguous or changed
   definition blocks that specific scan.
4. \`buildExternalScanPlan\` emits candidates only for each
   actual Nessus definition's exact configured target set,
   with the original per-definition scan ID and +60m
   nominal occurrence offset. Every target must be
   in the reviewed Nessus scope (including bounded CIDRs)
   **and** the reviewed exact Greenbone route. No partial
   approved subset is accepted as full target parity.
   Extra approved customer assets are **not** scanned merely
   because they are approved. Cross-tenant exact/CIDR
   conflicts block execution. A target repeated across
   different Nessus definitions retains the correct
   per-definition provenance; remote global capacity and
   a per-occurrence deduplication claim ultimately enforce
   one physical scanner job at a time.
5. The legacy admin company-wide port endpoint now returns
   HTTP 409, without calling \`startScan\`. The legacy
   full-inventory/offset scheduling timer is retired even
   if its old flag is accidentally enabled, and
   \`importFromVulnersBridge\` no longer starts an unscoped
   inventory sweep through nightly sync-all. These changes
   are now deployed as part of the fail-closed production release.
6. Test coverage includes exact per-definition source,
   Nessus CIDR scope, dual provider target authorization,
   no partial source target acceptance, historic-host union
   rejection, cross-tenant collision, duplicate/source ID
   rejection, read-only endpoint, and retired scan paths.
   The 23 targeted tests and deployment build passed on Vuln-NYC1.

## Important distinction

- **Configured scope parity**: after reviewer approval, the
  preview has exactly the same candidate host/IP *identities*
  as each Nessus definition. It does not prove physical
  scans occurred on those hosts.
- **Completed/assessed host parity**: requires a pinned
  historical Nessus occurrence (not the mutable editor
  configuration), verification that each intended target
  has a completed bounded Nessus host result, and separately
  a completed Greenbone task/report for the same configured
  target with report-internal host attestation. A missing,
  timed-out, interrupted, unresolved or skipped host is
  **not completed** in either engine.

## Go-live blockers (do not override)

- Production \`customer_scanner_routes\` had **zero rows**
  when last reviewed, so there is no authorized target route.
- The current dispatch runner is **not wired** to a
  trusted per-definition and per-historical-occurrence
  Nessus result adapter or a complete Greenbone terminal
  result consumer. The read-only planner does not start
  tasks. Current launch flags must remain false.
- A 352-address definition must not bypass routing
  limits or use an automatically expanded scan until
  all targets and exclusions are reviewed by the customer.
- The existing 91 stale local Vulners Running records
  must not be set to Completed from partial Greenbone
  reports or newly generated planned target counts.
- There must be a global database-backed capacity claim,
  durable remote Greenbone task ID saved **before** start,
  no duplicate starts after uncertain outcomes, and a
  per-target report/host completion reconciliation.
- Documented customer maintenance windows and independently
  checked Nessus run completion are mandatory.
- A separate historical 913-CVE reconciliation effort is
  **not a prerequisite** to fixing scan-target parity.
  This PR does not import or change historical findings.

## Read-only operator verification

On \`Vuln-NYC1\`, use the pinned audit files:
\`scripts/audit/nessus-per-scan-target-parity.mjs\` and
\`scripts/audit/audit-nessus-per-scan-targets.mjs\`.
They print scan IDs and aggregate counts, not customer
hostnames/IPs or scanner credentials. Do not run the
old \`POST /api/admin/port-nessus-to-bridge\` in production,
and do not enable \`VULNERS_BRIDGE_SCHEDULER_ENABLED\`.
