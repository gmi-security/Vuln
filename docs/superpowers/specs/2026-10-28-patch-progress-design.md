# Patch progress after the next scan

## Intent

Show the engineering team's progress for the selected customer: a vulnerability was detected on known devices, a ticket was created, and later scans show whether it is still detected on those devices. The user wants both customer trends and ticket progress, with a simple presentation.

## Proposed screen

Use the existing customer selector and Remediation layout. Add a compact customer progress chart to Overview and a progress section to the existing ticket review/tracker. Keep the current worklists and ticket workflow.

Each ticket shows its original affected-device count, still detected, no longer detected, not yet verified, last checked and source. Expand it to see the CVE/device rows and observation dates. For a multi-CVE ticket, a device is clear only when all of that device's originally ticketed CVEs are no longer detected. It stays unverified if any required evidence is unavailable.

Example only: a ticket starts with 100 devices. The next scan finds 20 still affected, provides qualifying absence evidence for 70, and did not check 10. Display `20 still detected / 70 no longer detected / 10 not verified`; never show 80 patched. New affected devices found later are separate from the original ticket scope. A later positive finding returns to still detected and is marked as reappeared.

Customer trends show observed open device/CVE findings and their changes after completed imports. Keep source populations separate unless an existing verified device identity links them; do not invent an estate-wide unique count. A CVE remains open for the customer while any covered device still reports it. Ticket progress is evidence about the ticket's original scope, not a claim that its ticket caused remediation.

## Evidence rules

- Use a later, successfully completed and durably published assessment for the same customer, source and scope. Partial/failed imports never count as improvement.
- Record the assessment time and the comparison time separately. An old assessment imported later is not a new verification.
- Still detected means matching positive evidence. No longer detected requires adequate scan coverage; missing/offline devices, removed connectors, changed scopes, suppression/exclusions or unsupported evidence remain not verified, with a reason.
- Defender uses its completed published generation and device observations. Nessus uses completed covered-device assessments and its per-scan observations. CrowdStrike uses the saved complete scoped generation with explicit closure or sufficient device-assessment coverage; disappearance from an open-only list alone does not establish a successful patch.
- Closing a ConnectWise ticket is tracked separately. This feature does not automatically create, close or reopen ConnectWise tickets, or send notes.
- Label the result `No longer detected`, rather than claiming a specific update was installed. Installation proof would require additional endpoint/patch-tool evidence.
- Retain observations so later scans do not overwrite the history. Existing tickets can be included when their saved scope is sufficient. Otherwise show `Baseline unavailable`. Historical totals can be displayed where retained, but never manufacture past device-level transitions.

## Approaches and recommendation

1. Reuse only existing daily totals. Smallest display change, but a lower total cannot identify which ticket/device improved or distinguish patching from lost coverage.
2. Re-query provider APIs when opening each ticket. Fresh checks are possible, but this repeats expensive work and does not automatically preserve the changes after each import.
3. Compare saved completed assessments against the ticket's original scope in background work, and store compact observations and summaries. Recommended: it directly implements the requested next-scan comparison, reuses completed imports, and keeps page requests fast.

The user selected both customer trends and ticket progress and clarified the next-scan comparison. Approach 3 is the implementation recommendation, pending design approval.

## Implementation boundaries

Reuse existing ticket packets, device/CVE coverage, source assignments and source-generation identifiers. Keep comparison work outside the platform's final save transaction. Queue it after successful publication, process bounded batches, and make retries idempotent by ticket and source generation. Publish a complete summary only after every required page has been checked. UI reads saved summaries; source errors must display pending/unverified rather than zero remaining.

Store compact state transitions and summary counts, not another complete copy of scanner payloads. Initial implementation covers CrowdStrike, Defender and Nessus; other sources display unsupported verification until their coverage contract is implemented. Preserve the existing daily sync schedule, manual ticket creation/approval, ticket routing, customer access boundaries and current findings.

## Acceptance checks

1. A later complete covered scan moves the expected original device/CVE rows from still detected to no longer detected, retaining timestamps and source evidence.
2. Failed/partial scans, offline devices, changed source scope and old assessments do not falsely improve progress.
3. Repeat processing does not duplicate history; a crash resumes without exposing partial results.
4. Reappearance and newly affected devices are shown without changing the original ticket denominator.
5. A closed ticket with positive findings stays visibly affected; ticket status never substitutes for scanner evidence.
6. Multi-CVE and multi-source scopes retain exact membership. Customer isolation is enforced in queries and responses.
7. Large comparisons do not run on page requests or extend the platform save transaction. Test pagination and bounded work at production-representative sizes.

## Current status

Design prepared from the current deployed source. No feature code, production schema, worker or UI changes have been made for patch progress. Next step after approval: write the bounded implementation plan and implement the source comparison, stored history and UI with the checks above.
