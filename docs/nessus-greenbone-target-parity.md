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

After merging/deploying separately, from an approved admin host with the
existing `ADMIN_TOKEN` in the environment:

```bash
curl --fail-with-body -sS \
  -H "Authorization: Bearer ${ADMIN_TOKEN}" \
  "https://gmi-vuln-opmy8.ondigitalocean.app/api/admin/scanner-target-parity" |
  jq '{mode, executedScanParityVerified, nessusRoutesAvailable, vulnersRoutesAvailable, matchedApprovedScopeCount, unresolvedCompanyCount, companies}'
```

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
