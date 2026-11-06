# Greenbone terminal per-host evidence contract (not yet live)

## Why

A completed gvmd task, a row in /findings, and a nonempty or zero-CVE
vulnerability list do **not** establish that Greenbone assessed the same
host as a particular completed Nessus occurrence.

A future trusted scanner-side endpoint must derive this bounded attestation
by reading and verifying the **complete GMP task and report** (not the
legacy Bridge GET /api/v1/scans or /findings list). This document is a
desired contract, NOT an assertion that Vulners-v2 already implements it.

## Pure validation now available

\`lib/greenbone-terminal-proof.ts\` exports
\`verifyGreenboneTerminalTarget(candidate, expectedTaskId, nessusRun, attestation, now)\`.
It accepts **exactly one** host with:
- Known persisted reserved Bridge task ID and an immutable report UUID;
- complete gvmd inventory and report/page evidence, "Done" task **and**
  "Done" report, no skipped/failed host;
- exactly one requested/observed target with an explicitly assessed,
  completed host evidence ID;
- exact target identity agreement with the pinned completed Nessus run;
- Greenbone start after the Nessus occurrence +60 minutes **and** after
  the Nessus run completed;
- valid monotonic start/end times and a fresh attestation timestamp.

A report containing zero CVEs can pass **only if an assessed host is
positively attested**. A completed task with zero hosts must fail.

The module returns an evidence digest for reconciliation; it does not
cryptographically sign the scanner's claim or compare vulnerability counts.
An API server simply setting \`inventoryComplete: true\` without exhaustive
GMP verification is NOT trustworthy. The scanner-side implementation must
be independently checked under a known GMI-only test, including a negative
case with an unreachable/absent host.

## Still missing before enabling launch

1. Scanner-side implementation and independent validation of the
   complete task/report/host attestation. Greenbone report/host payloads and
   pagination behavior must be examined on the actual server.
2. Current, independently reviewed per-customer Nessus + Bridge scopes
   and an approved scan window; the last production audit has no routes.
3. Exact Nessus run evidence pinned to a historical occurrence, with
   explicit host completion, not the mutable editor definition.
4. Controlled single writer/dispatcher integration with existing
   durable reservation and create-then-start client.
5. A single trusted terminal result worker that checks the remote task
   and report, persists report evidence, and releases the global slot
   ONLY after verified remote terminal state and an audited SQL transaction.
   Unknown and interrupted states keep the slot held for reconciliation.
6. A backed-up, reviewed installation of external-scan claim/events tables;
   the live audit found the slot missing or occupied, not which.
7. An accepted real GMI test and explicit operator go-live decision.

\`VULNERS_BRIDGE_SCHEDULER_ENABLED\` stays false permanently.
\`GMI_SCAN_ADMISSION_ENABLED\` and
\`VULN_EXTERNAL_SCAN_DISPATCH_ENABLED\` remain false until all gates
are demonstrated. The pure validator is intentionally not wired to
HTTP POST routes, schedulers or remote scanner operations.
