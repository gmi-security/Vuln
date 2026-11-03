# Local Nessus historical response contract probe (read-only)

This stage verifies the **actual Nessus scanner's** historical-run response fields before the proof in `lib/nessus-run-proof.ts` can be connected to production dispatch. The user-approved offset remains **60 minutes after the scheduled Nessus start**, and elapsed time alone never authorizes a scan.

## Invocation

Run on the host or application container that already has `NESSUS_URL`, `NESSUS_ACCESS_KEY` and `NESSUS_SECRET_KEY` configured for the GMI vulnerability application (not necessarily on Vulners-v2).

Choose an **existing, approved** Nessus scan and its exact owning folder from the Nessus UI or reviewed routing. Set only numeric IDs for the probe:

```bash
NESSUS_PROBE_SCAN_ID=123 NESSUS_PROBE_FOLDER_ID=45 \
  node scripts/nessus-historical-shape-probe.mjs
```

Replace the example IDs. **Do not paste API keys or raw Nessus responses into chat.** The script uses the existing environment, makes at most four kinds of `GET` reads (global scan roster (to confirm folder ownership), scan summary, pinned historical scan and one pinned historical host), caps each reply at 6 MiB and timeout at 15 seconds, and never calls a write endpoint, scan launch, stop or export.

If a scan has no completed historical run, the probe reports that no history was selected. If the pinned endpoint or host detail is unsupported, the output shows only the HTTP status and missing field types.

## Output privacy

The probe prints a whitelisted **schema-only JSON summary**, not customer names, hostnames, IP addresses, raw UUIDs/history IDs, vulnerability details, API keys, headers or scanner URLs. It reports fields as `number`, `string`, `array`, `missing`, etc., and Boolean equality checks for the selected history identity. It never emits raw response bodies or network error messages.

Relevant checks: `selectedCompletedHistory.fields.history_id`, `pinnedScan.rootFields.history_id`, `pinnedScan.infoFields.scan_start`, `pinnedScan.infoFields.scan_end`, `pinnedScan.infoFields.incomplete_targets`, `pinnedScan.historyIdMatches`, `pinnedScan.uuidMatches`, `pinnedHost.infoFields.host-fqdn` and `pinnedHost.infoFields.host-ip`.

If a field is missing or a historical identity cannot be confirmed, **the current verifier stays fail-closed**. The correct remedy is to map a safe, documented identity from the actual Nessus response and add positive and negative tests—not to turn off identity verification.

## Deployment safeguards

The script is diagnostic only: no database changes, no API routes, no scheduling, no remote scan calls to Greenbone. It must not run unattended or choose a client's scan on its own. It requires two operator-selected numeric IDs to avoid probing an arbitrary customer.

Separately, Vulners-v2's capacity endpoint has been validated against its 7,531-task inventory. That does **not** mean customer external scans are authorized. Keep `GMI_SCAN_ADMISSION_ENABLED=false`, `VULN_EXTERNAL_SCAN_DISPATCH_ENABLED=false`, `VULNERS_BRIDGE_SCHEDULER_ENABLED=false`; the last one activates a legacy inventory-wide sweep and must not be used.

CI runs only simulated offline responses and verifies that no customer or credential values appear in diagnostic output. The actual Nessus endpoint contract still needs a one-time read-only run and review before production integration.
