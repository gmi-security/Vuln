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
