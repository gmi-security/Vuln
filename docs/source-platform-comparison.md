# Retained source and platform comparison

Measured October 9, 2026 against the private restored October 9 backup. This is a migration validation report, not a live health check.

## What the results mean

**Footprint's current Defender import is fully represented in the saved platform findings for the fields checked.** Its 286,068 software-instance rows group into 212,921 device/CVE pairs. Every pair exists in the published generation, with matching severity and CVSS after the existing unknown/null mapping. All are Open and active. There are no missing or duplicate pairs, stale pair generations, or connection-revision differences.

The platform also has **2,970 older open findings** and **72,987 resolved records** absent from the current source import. For the older open findings, device heartbeats precede their saved observations; the existing Defender projection cannot infer a successful patch from that evidence. All 2,970 retain active evidence from an older generation.

Consequently, platform open findings are **215,891**, not 212,921. Building the replacement database solely from the latest source rows would discard meaningful state. Migrate published IDs, workflow, assessment and retained history as well as current source evidence.

| Footprint count | Current source | Published platform |
| --- | --- | --- |
| Open device/CVE findings | 212,921 current pairs | 215,891 open records including retained history |
| Unique open CVEs | 10,215 | 10,229 |
| Affected device measure | 585 source device IDs | 588 endpoint asset keys; not an independently verified identity count |
| Inventory devices | 2,348 | Not compared |

**Atlas has two separately maintained populations.** Its saved platform has 80,000 open CrowdStrike endpoint findings (4,450 CVEs and 142 asset keys), plus 302 separate SpiderFoot exposures. The completed Spotlight import has 2,119,658 rows, including 2,112,296 eligible open instances, 2,094,134 device/CVE pairs, 11,710 CVEs and 1,439 device IDs.

The existing `importFromCrowdstrikeSpotlight` implementation writes dedicated source tables without updating legacy platform findings. A source-generation/identity mapping to the older platform records has not been established. This audit does not explain the historical origin of exactly 80,000 records or prove an import cap. Do not add these populations or substitute source counts for platform totals without reconciling identity, lifecycle, history and risk policy.

## Evidence and boundaries

- One read-only repeatable-read transaction examined all 64 saved finding buckets, containing 510,945 records. Only the two selected customers contributed to reported totals.
- Defender import completed October 8 at 18:39:42 UTC; its generation matches the saved publication marker. Platform metadata was saved October 9 at 09:26:32 UTC.
- Spotlight import completed October 1 at 13:29:08 UTC. Its counts reuse the earlier independent full-source audit after checking the same owned, completed generation. This retained source was already old at the backup date.
- Final run took 14,013 ms. Five new classifier tests and six actual legacy projection/reporting tests passed.
- Aggregate report: `/home/codex/vuln-recovery/source-platform-5i4ua42t/comparison.json`. Hostnames, IP addresses, raw records, remediation contents and credentials are not exported. Finding/device keys used for comparison stay in process memory.
- No risk recalculation, ticket/export parity, historical closure validation or live tenant authorization proof was performed. `currentSourceProjectionMatches` describes only current Defender membership, generation and severity/CVSS checks, not complete platform parity.
- No production reads/writes, deployment, schema changes or application integration were performed. The private restore cluster was stopped after the audit.

## Repeat the audit

The standalone script refuses TCP and verifies the private recovery data directory and disabled network listener. It never loads `.env` or imports application initialization. With the private restore started using the established recovery procedure, stage both audit scripts with access to the installed `pg` dependency, then run:

```sh
node --max-old-space-size=768 scripts/audit-restored-source-platform.mjs \
  /home/codex/vuln-recovery/baseline-uVic9i/restore-6hXR1M/socket \
  /home/codex/vuln-recovery/NEW-PRIVATE-RUN/comparison.json
```

Create the new private output directory first; the report refuses to overwrite an existing file. Stop the private cluster in a `finally`/cleanup handler. This script intentionally targets this backup and its independently audited Spotlight baseline, not arbitrary production databases.

Each statement has a 15-second server timeout, a 20-second client query timeout, and the script checks a five-minute deadline between queries. The operator harness also enforces a 330-second process limit. Caps are 500,000 Defender pairs, 100,000 devices and one million platform records; an exceeded cap fails rather than reporting a partial comparison. Metadata precedence, malformed tuples or an unexpected bucket layout also fail. No database objects are created or changed.

## Next implementation

Build the first disabled normalized-platform shadow projection from Defender's published records, retaining identity, workflow, resolved history, older open findings and saved assessments. Validate it against this baseline before wiring page reads. CrowdStrike reconciliation remains separate; source summary accuracy alone is not platform lifecycle/risk parity.
