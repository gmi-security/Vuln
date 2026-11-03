# External scan admission: independent gating, no launch path

This stage adds a pure admission policy to complement the read-only approved target/schedule preview in PR #111. The policy **cannot launch scans** or change Greenbone. Keep both production gates off: `VULNERS_BRIDGE_SCHEDULER_ENABLED=false` in the GMI app and `GMI_SCAN_ADMISSION_ENABLED=false` in the scanner API.

The policy returns `hold` by default. Even if all flags and proofs are supplied, its strongest output is `eligible-for-atomic-claim`: it is not a permit to start a remote scan.

## Required current evidence

A future dispatcher must gather and independently verify all fields from trusted sources, not user-submitted JSON:

1. Exact currently approved customer/target route and revision, no wildcard/CIDR, never from historical findings.
2. Customer-approved maintenance window covering the *current* instant.
3. The specific Nessus scan actually completed on this occurrence, with timing, report ID, and evidence the intended target was covered. A predicted schedule is not evidence that the Nessus job ran.
4. Fresh (within 30 seconds) health and zero active, queued or requested Greenbone jobs. Only one global scan may proceed.
5. A durable cross-process claim keyed by (company, normalized exact target, Nessus scan ID, occurrence timestamp), obtained atomically with a UNIQUE constraint and a lease/fence.
6. Explicit rollout gates for both dispatch and scanner API admission.

## Still required before any real automated scanning

- Schema-backed admission claims and global distributed capacity lease. Do not rely on the preliminary `claimExists=false` read; read-then-write races would double-launch.
- Bind the claims to actual Nessus run IDs and validated scan evidence; choose only currently approved client-specific windows, not nominal +1h alone.
- After atomic claim, recheck route, approval, window and scanner capacity immediately before *both* create and start; cap port/host scope; avoid duplicates by checking the remote scanner on uncertain timeouts. Persist remote task/report IDs and terminal states.
- Validate full report completeness (pagination, QoD, total findings) before ingesting or resolving findings. No retrospective backlog storm; missed windows are skipped.
- Run multi-worker lock tests, chaos tests and production recovery rehearsal. Reconcile deployment commit and local GMI app changes before rolling out. The combined legacy scheduler must stay off.

The first completed live validation on Vulners-v2 (Nov 3) is proof of a working scanner, not proof that all external clients are authorized for recurring scans. No client jobs are scheduled by this PR.