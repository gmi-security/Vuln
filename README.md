# Vuln

GMI Vulnerability Console — start scans, manage scans, and quantify
vulnerability risk across the estate. Built in the same look, feel, and stack
as SONAR (Next.js App Router + Tailwind v4, Vibrocentric display font, black /
GMI-red console aesthetic).

## Features

- **Dashboard** (`/dashboard`) — live posture at a glance: open findings,
  criticals, active scans, exposure score, recent scan activity, open-by-severity
  distribution, and top risk assets.
- **Scans** (`/scans`) — launch a scan against any connector with a named
  profile (Discovery, Standard, Credentialed, PCI External, Agent Telemetry
  Sync) and a target list (hosts, IPs, or CIDR). Running scans show live
  progress and can be **paused / resumed / stopped / re-run / deleted**. Scan
  detail (`/scans/:id`) shows status, severity rollups, and per-scan findings.
- **Findings** (`/findings`) — every vulnerability surfaced by scans,
  deduplicated per CVE + asset. Filter by search, severity, status, connector,
  or exploitable-only; open a finding to see description, remediation, CVSS,
  EPSS, NVD link, and to set triage status and assignee.
- **Quantify** (`/quantify`) — risk quantification: exposure score (severity ×
  exploitability × EPSS), SLA posture (Critical 7d / High 30d / Medium 90d /
  Low 180d), 14-day open-backlog trend, asset risk ranking, mean time to
  remediate, and findings by source and workflow status.
- **Connectors** (`/connectors`) — scanner integrations and their
  configuration state.

## Connectors

| Connector | Kind | Status |
|---|---|---|
| **Nessus** (Tenable) | Network vulnerability scanner | Demo mode until `NESSUS_URL`, `NESSUS_ACCESS_KEY`, `NESSUS_SECRET_KEY` are set |
| **Vulners** | Package audit & CVE/exploit intelligence | Demo mode until `VULNERS_API_KEY` is set |
| **CrowdStrike Spotlight** | Endpoint vulnerability telemetry | Demo mode until `FALCON_CLIENT_ID`, `FALCON_CLIENT_SECRET`, `FALCON_CLOUD` are set |
| **Qualys VMDR** | Cloud vulnerability management | Planned |

Without credentials every connector runs in **demo mode**: launched scans
progress in real time and complete with realistic findings drawn from a
curated CVE catalog, so the full workflow (start → monitor → triage →
quantify) works end to end out of the box. `lib/connectors.ts` is the single
integration point where the real vendor API calls plug in.

## Development

```bash
npm install
npm run dev
```

Open [http://localhost:3000](http://localhost:3000). Data is kept in an
in-memory store (`lib/store.ts`) seeded with recent scan history; swap it for
Postgres/Prisma when persistence is needed — API routes only talk to the store
functions.
