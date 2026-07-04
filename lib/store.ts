import { DEMO_ASSETS, DEMO_PORTS, VULN_CATALOG } from "@/lib/catalog";
import { getDemoProfile, isPlanned } from "@/lib/connectors";
import {
  nessusConfig,
  nessusImportFindings,
  nessusLaunchScan,
  nessusScanControl,
  nessusScanStatus,
} from "@/lib/nessus";
import type {
  ConnectorId,
  Finding,
  FindingStatus,
  QuantifyMetrics,
  Scan,
  ScanStatus,
  Severity,
} from "@/lib/types";

// In-memory operational store. Scans progress in real time (progress is a
// function of elapsed wall clock, so it advances between requests without a
// background worker) and completed scans materialize findings. Swap for
// Postgres/Prisma when persistence is needed — the API routes only talk to
// the functions exported here.

type StoreShape = {
  scans: Map<string, InternalScan>;
  findings: Map<string, Finding>;
  seeded: boolean;
  counter: number;
};

type InternalScan = Omit<Scan, "progress" | "status"> & {
  status: ScanStatus;
  durationMs: number;
  progressFrozenAt: number | null; // progress % locked in when paused/stopped
  seed: number;
  // Present when the scan runs on a real scanner instead of the demo engine.
  vendor: { nessusScanId: number; lastPoll: number; imported: boolean } | null;
};

const globalStore = globalThis as unknown as { __vulnStore?: StoreShape };

function store(): StoreShape {
  if (!globalStore.__vulnStore) {
    globalStore.__vulnStore = {
      scans: new Map(),
      findings: new Map(),
      seeded: false,
      counter: 1000,
    };
    seed(globalStore.__vulnStore);
  }
  return globalStore.__vulnStore;
}

// --- deterministic RNG so demo data is stable per scan -----------------

function hashSeed(text: string): number {
  let h = 2166136261;
  for (let i = 0; i < text.length; i++) {
    h ^= text.charCodeAt(i);
    h = Math.imul(h, 16777619);
  }
  return h >>> 0;
}

function mulberry32(seed: number) {
  let a = seed >>> 0;
  return () => {
    a |= 0;
    a = (a + 0x6d2b79f5) | 0;
    let t = Math.imul(a ^ (a >>> 15), 1 | a);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

const SEVERITIES: Severity[] = ["Critical", "High", "Medium", "Low", "Info"];

function emptySeverityCounts(): Record<Severity, number> {
  return { Critical: 0, High: 0, Medium: 0, Low: 0, Info: 0 };
}

// --- scan lifecycle ------------------------------------------------------

function nextId(s: StoreShape, prefix: string): string {
  s.counter += 1;
  return `${prefix}-${s.counter}`;
}

function computeProgress(scan: InternalScan, now: number): number {
  if (scan.vendor) return scan.progressFrozenAt ?? 0;
  if (scan.progressFrozenAt !== null) return scan.progressFrozenAt;
  if (!scan.startedAt) return 0;
  const elapsed = now - new Date(scan.startedAt).getTime();
  return Math.max(0, Math.min(100, Math.round((elapsed / scan.durationMs) * 100)));
}

function generateFindings(s: StoreShape, scan: InternalScan): Finding[] {
  const rand = mulberry32(scan.seed);
  const demo = getDemoProfile(scan.connector);
  const count =
    demo.minFindings + Math.floor(rand() * (demo.maxFindings - demo.minFindings + 1));
  const pool = demo.categories
    ? VULN_CATALOG.filter((v) => demo.categories!.includes(v.category))
    : VULN_CATALOG;
  const assets =
    scan.targets.length > 0 && !scan.targets.some((t) => t.includes("/"))
      ? scan.targets
      : DEMO_ASSETS;
  const completedAt = scan.completedAt ?? new Date().toISOString();
  const created: Finding[] = [];

  for (let i = 0; i < count; i++) {
    const template = pool[Math.floor(rand() * pool.length)];
    const asset = assets[Math.floor(rand() * assets.length)];
    const dedupeKey = `${template.cve}::${asset}`;
    // Same CVE on the same asset seen by a new scan updates lastSeen instead
    // of duplicating the finding.
    const existing = Array.from(s.findings.values()).find(
      (f) => `${f.cve}::${f.asset}` === dedupeKey && f.status !== "Resolved",
    );
    if (existing) {
      existing.lastSeen = completedAt;
      continue;
    }
    created.push({
      id: nextId(s, "VLN"),
      scanId: scan.id,
      connector: scan.connector,
      cve: template.cve,
      title: template.title,
      severity: template.severity,
      cvss: template.cvss,
      epss: template.epss,
      asset,
      port: DEMO_PORTS[Math.floor(rand() * DEMO_PORTS.length)],
      category: template.category,
      description: template.description,
      remediation: template.remediation,
      status: "Open",
      assignee: null,
      firstSeen: completedAt,
      lastSeen: completedAt,
      resolvedAt: null,
      exploitAvailable: template.exploitAvailable,
    });
  }
  for (const f of created) s.findings.set(f.id, f);
  return created;
}

function settleScan(s: StoreShape, scan: InternalScan, now: number): void {
  if (scan.vendor) return; // vendor scans settle via refreshVendorScans()
  if (scan.status !== "Running") return;
  const progress = computeProgress(scan, now);
  if (progress < 100) return;
  scan.status = "Completed";
  scan.completedAt = new Date(
    new Date(scan.startedAt!).getTime() + scan.durationMs,
  ).toISOString();
  scan.progressFrozenAt = 100;
  const findings = generateFindings(s, scan);
  const all = Array.from(s.findings.values()).filter((f) => f.scanId === scan.id);
  scan.findingsCount = all.length || findings.length;
  const counts = emptySeverityCounts();
  for (const f of all) counts[f.severity] += 1;
  scan.severityCounts = counts;
  scan.hostsScanned = new Set(all.map((f) => f.asset)).size || scan.targets.length;
}

function toPublic(scan: InternalScan, now: number): Scan {
  const { durationMs: _d, progressFrozenAt: _p, seed: _s, vendor: _v, ...rest } = scan;
  return { ...rest, progress: computeProgress(scan, now) };
}

function tick(s: StoreShape): void {
  const now = Date.now();
  for (const scan of s.scans.values()) settleScan(s, scan, now);
}

const NESSUS_STATUS_MAP: Record<string, ScanStatus> = {
  running: "Running",
  pending: "Queued",
  paused: "Paused",
  pausing: "Paused",
  resuming: "Running",
  stopping: "Running",
  completed: "Completed",
  canceled: "Stopped",
  stopped: "Stopped",
  aborted: "Failed",
  error: "Failed",
};

// Poll active vendor-backed scans (throttled per scan) and import findings
// when a scan completes on the scanner.
async function refreshVendorScans(s: StoreShape): Promise<void> {
  const now = Date.now();
  for (const scan of s.scans.values()) {
    if (!scan.vendor) continue;
    const active =
      scan.status === "Running" || scan.status === "Paused" || scan.status === "Queued";
    if (!active || now - scan.vendor.lastPoll < 4000) continue;
    scan.vendor.lastPoll = now;
    try {
      const remote = await nessusScanStatus(scan.vendor.nessusScanId);
      scan.progressFrozenAt = remote.progress;
      scan.status = NESSUS_STATUS_MAP[remote.status] ?? scan.status;
      if (
        (scan.status === "Completed" || scan.status === "Stopped") &&
        !scan.completedAt
      ) {
        scan.completedAt = new Date(now).toISOString();
      }
      if (scan.status === "Completed" && !scan.vendor.imported) {
        scan.vendor.imported = true;
        await importVendorFindings(s, scan);
      }
    } catch (err) {
      scan.error = err instanceof Error ? err.message : "Nessus polling failed.";
    }
  }
}

async function importVendorFindings(s: StoreShape, scan: InternalScan): Promise<void> {
  const imported = await nessusImportFindings(scan.vendor!.nessusScanId);
  const completedAt = scan.completedAt ?? new Date().toISOString();
  for (const item of imported) {
    const dedupeKey = `${item.cve}::${item.asset}::${item.title}`;
    const existing = Array.from(s.findings.values()).find(
      (f) => `${f.cve}::${f.asset}::${f.title}` === dedupeKey && f.status !== "Resolved",
    );
    if (existing) {
      existing.lastSeen = completedAt;
      continue;
    }
    s.findings.set(
      `VLN-${(s.counter += 1)}`,
      {
        id: `VLN-${s.counter}`,
        scanId: scan.id,
        connector: scan.connector,
        cve: item.cve,
        title: item.title,
        severity: item.severity,
        cvss: item.cvss,
        epss: 0,
        asset: item.asset,
        port: item.port,
        category: item.category,
        description: item.description,
        remediation: item.remediation,
        status: "Open",
        assignee: null,
        firstSeen: completedAt,
        lastSeen: completedAt,
        resolvedAt: null,
        exploitAvailable: item.exploitAvailable,
      },
    );
  }
  const all = Array.from(s.findings.values()).filter((f) => f.scanId === scan.id);
  scan.findingsCount = all.length;
  const counts = emptySeverityCounts();
  for (const f of all) counts[f.severity] += 1;
  scan.severityCounts = counts;
  scan.hostsScanned = new Set(all.map((f) => f.asset)).size || scan.targets.length;
}

// --- public API -----------------------------------------------------------

export async function listScans(): Promise<Scan[]> {
  const s = store();
  tick(s);
  await refreshVendorScans(s);
  const now = Date.now();
  return Array.from(s.scans.values())
    .map((scan) => toPublic(scan, now))
    .sort((a, b) => (b.createdAt > a.createdAt ? 1 : -1));
}

export async function getScan(id: string): Promise<Scan | undefined> {
  const s = store();
  tick(s);
  await refreshVendorScans(s);
  const scan = s.scans.get(id);
  return scan ? toPublic(scan, Date.now()) : undefined;
}

export async function startScan(input: {
  name: string;
  connector: ConnectorId;
  profile: string;
  targets: string[];
  requestedBy?: string;
}): Promise<Scan | { error: string }> {
  const s = store();
  if (isPlanned(input.connector)) {
    return { error: "Qualys VMDR integration is planned but not yet available." };
  }
  if (!input.targets.length) {
    return { error: "At least one target is required." };
  }

  const name = input.name || `${input.connector} scan`;
  let vendor: InternalScan["vendor"] = null;
  if (input.connector === "nessus" && nessusConfig()) {
    try {
      const launched = await nessusLaunchScan(name, input.targets, input.profile);
      vendor = { nessusScanId: launched.nessusScanId, lastPoll: 0, imported: false };
    } catch (err) {
      return {
        error: err instanceof Error ? err.message : "Failed to launch Nessus scan.",
      };
    }
  }

  const demo = getDemoProfile(input.connector);
  const id = nextId(s, "SCAN");
  const nowIso = new Date().toISOString();
  const seedVal = hashSeed(id + input.connector + input.targets.join(","));
  const rand = mulberry32(seedVal);
  const scan: InternalScan = {
    id,
    name,
    connector: input.connector,
    profile: input.profile,
    targets: input.targets,
    status: vendor ? "Queued" : "Running",
    createdAt: nowIso,
    startedAt: nowIso,
    completedAt: null,
    findingsCount: 0,
    severityCounts: emptySeverityCounts(),
    hostsScanned: 0,
    requestedBy: input.requestedBy || "analyst@gmi.com",
    durationMs:
      demo.minDurationMs + Math.floor(rand() * (demo.maxDurationMs - demo.minDurationMs)),
    progressFrozenAt: vendor ? 0 : null,
    seed: seedVal,
    vendor,
  };
  s.scans.set(id, scan);
  return toPublic(scan, Date.now());
}

export async function scanAction(
  id: string,
  action: "pause" | "resume" | "stop" | "delete" | "rescan",
): Promise<Scan | { error: string } | { deleted: true }> {
  const s = store();
  tick(s);
  const scan = s.scans.get(id);
  if (!scan) return { error: "Scan not found." };
  const now = Date.now();

  // Vendor-backed scans forward lifecycle controls to the scanner; local
  // state converges on the next poll.
  if (scan.vendor && (action === "pause" || action === "resume" || action === "stop")) {
    try {
      await nessusScanControl(scan.vendor.nessusScanId, action);
      scan.status =
        action === "pause" ? "Paused" : action === "resume" ? "Running" : "Stopped";
      if (action === "stop") scan.completedAt = new Date(now).toISOString();
      return toPublic(scan, now);
    } catch (err) {
      return {
        error: err instanceof Error ? err.message : `Nessus ${action} failed.`,
      };
    }
  }
  if (scan.vendor && action === "rescan") {
    try {
      const launched = await nessusLaunchScan(scan.name, scan.targets, scan.profile);
      scan.vendor = { nessusScanId: launched.nessusScanId, lastPoll: 0, imported: false };
      scan.status = "Queued";
      scan.startedAt = new Date(now).toISOString();
      scan.completedAt = null;
      scan.progressFrozenAt = 0;
      return toPublic(scan, now);
    } catch (err) {
      return {
        error: err instanceof Error ? err.message : "Nessus relaunch failed.",
      };
    }
  }

  switch (action) {
    case "pause": {
      if (scan.status !== "Running") return { error: "Only running scans can be paused." };
      scan.progressFrozenAt = computeProgress(scan, now);
      scan.status = "Paused";
      break;
    }
    case "resume": {
      if (scan.status !== "Paused") return { error: "Only paused scans can be resumed." };
      const frozen = scan.progressFrozenAt ?? 0;
      // Rebase startedAt so elapsed time maps back onto the frozen progress.
      scan.startedAt = new Date(now - (frozen / 100) * scan.durationMs).toISOString();
      scan.progressFrozenAt = null;
      scan.status = "Running";
      break;
    }
    case "stop": {
      if (scan.status !== "Running" && scan.status !== "Paused") {
        return { error: "Scan is not active." };
      }
      scan.progressFrozenAt = computeProgress(scan, now);
      scan.status = "Stopped";
      scan.completedAt = new Date(now).toISOString();
      break;
    }
    case "delete": {
      for (const f of Array.from(s.findings.values())) {
        if (f.scanId === id) s.findings.delete(f.id);
      }
      s.scans.delete(id);
      return { deleted: true };
    }
    case "rescan": {
      if (scan.status === "Running" || scan.status === "Paused") {
        return { error: "Scan is already active." };
      }
      scan.status = "Running";
      scan.startedAt = new Date(now).toISOString();
      scan.completedAt = null;
      scan.progressFrozenAt = null;
      scan.seed = hashSeed(scan.id + String(now));
      break;
    }
  }
  return toPublic(scan, now);
}

export function listFindings(filter?: { scanId?: string }): Finding[] {
  const s = store();
  tick(s);
  let all = Array.from(s.findings.values());
  if (filter?.scanId) all = all.filter((f) => f.scanId === filter.scanId);
  const sevRank: Record<Severity, number> = { Critical: 0, High: 1, Medium: 2, Low: 3, Info: 4 };
  return all.sort(
    (a, b) => sevRank[a.severity] - sevRank[b.severity] || b.cvss - a.cvss,
  );
}

export function updateFinding(
  id: string,
  patch: { status?: FindingStatus; assignee?: string | null },
): Finding | { error: string } {
  const s = store();
  const finding = s.findings.get(id);
  if (!finding) return { error: "Finding not found." };
  if (patch.status && patch.status !== finding.status) {
    finding.status = patch.status;
    finding.resolvedAt =
      patch.status === "Resolved" || patch.status === "False Positive"
        ? new Date().toISOString()
        : null;
  }
  if (patch.assignee !== undefined) finding.assignee = patch.assignee || null;
  return finding;
}

// --- quantification -------------------------------------------------------

const SEVERITY_WEIGHT: Record<Severity, number> = {
  Critical: 40,
  High: 20,
  Medium: 8,
  Low: 2,
  Info: 0,
};

const SLA_DAYS: Record<Severity, number> = {
  Critical: 7,
  High: 30,
  Medium: 90,
  Low: 180,
  Info: 365,
};

function isOpen(f: Finding): boolean {
  return f.status === "Open" || f.status === "In Remediation";
}

export function computeMetrics(): QuantifyMetrics {
  const s = store();
  tick(s);
  const all = Array.from(s.findings.values());
  const open = all.filter(isOpen);
  const now = Date.now();

  const severityCounts = emptySeverityCounts();
  for (const f of open) severityCounts[f.severity] += 1;

  const statusCounts: Record<FindingStatus, number> = {
    Open: 0,
    "In Remediation": 0,
    "Risk Accepted": 0,
    "False Positive": 0,
    Resolved: 0,
  };
  for (const f of all) statusCounts[f.status] += 1;

  const scored = open.filter((f) => f.cvss > 0);
  const avgCvss = scored.length
    ? Math.round((scored.reduce((sum, f) => sum + f.cvss, 0) / scored.length) * 10) / 10
    : 0;

  // Exposure score: severity-weighted open findings with an exploit and EPSS
  // multiplier, squashed to 0-100 so it reads like a gauge.
  const rawExposure = open.reduce((sum, f) => {
    const exploitBoost = f.exploitAvailable ? 1.5 : 1;
    const epssBoost = 1 + f.epss;
    return sum + SEVERITY_WEIGHT[f.severity] * exploitBoost * epssBoost;
  }, 0);
  const exposureScore = Math.round(100 * (1 - Math.exp(-rawExposure / 900)));

  const buckets = [
    { label: "Within SLA", count: 0, breach: false },
    { label: "Due in 7 days", count: 0, breach: false },
    { label: "SLA breached", count: 0, breach: true },
  ];
  for (const f of open) {
    const ageDays = (now - new Date(f.firstSeen).getTime()) / 86_400_000;
    const sla = SLA_DAYS[f.severity];
    if (ageDays > sla) buckets[2].count += 1;
    else if (ageDays > sla - 7) buckets[1].count += 1;
    else buckets[0].count += 1;
  }

  const byAsset = new Map<string, { score: number; open: number; worst: Severity }>();
  for (const f of open) {
    const entry = byAsset.get(f.asset) ?? { score: 0, open: 0, worst: "Info" as Severity };
    entry.score += SEVERITY_WEIGHT[f.severity] * (f.exploitAvailable ? 1.5 : 1);
    entry.open += 1;
    if (SEVERITIES.indexOf(f.severity) < SEVERITIES.indexOf(entry.worst)) {
      entry.worst = f.severity;
    }
    byAsset.set(f.asset, entry);
  }
  const assetRisk = Array.from(byAsset.entries())
    .map(([asset, v]) => ({ asset, score: Math.round(v.score), open: v.open, worst: v.worst }))
    .sort((a, b) => b.score - a.score)
    .slice(0, 10);

  const byConnector = new Map<ConnectorId, number>();
  for (const f of open) byConnector.set(f.connector, (byConnector.get(f.connector) ?? 0) + 1);
  const connectorCounts = Array.from(byConnector.entries()).map(([connector, count]) => ({
    connector,
    open: count,
  }));

  const trend: QuantifyMetrics["trend"] = [];
  for (let d = 13; d >= 0; d--) {
    const dayEnd = now - d * 86_400_000;
    const date = new Date(dayEnd).toISOString().slice(0, 10);
    const openAt = all.filter((f) => {
      const seen = new Date(f.firstSeen).getTime() <= dayEnd;
      const resolvedBefore = f.resolvedAt && new Date(f.resolvedAt).getTime() <= dayEnd;
      return seen && !resolvedBefore;
    }).length;
    const resolvedThatDay = all.filter(
      (f) =>
        f.resolvedAt &&
        new Date(f.resolvedAt).getTime() > dayEnd - 86_400_000 &&
        new Date(f.resolvedAt).getTime() <= dayEnd,
    ).length;
    trend.push({ date, open: openAt, resolved: resolvedThatDay });
  }

  const remediated = all.filter((f) => f.status === "Resolved" && f.resolvedAt);
  const meanTimeToRemediateDays = remediated.length
    ? Math.round(
        (remediated.reduce(
          (sum, f) =>
            sum + (new Date(f.resolvedAt!).getTime() - new Date(f.firstSeen).getTime()),
          0,
        ) /
          remediated.length /
          86_400_000) *
          10,
      ) / 10
    : null;

  return {
    totalOpen: open.length,
    severityCounts,
    avgCvss,
    exposureScore,
    exploitableOpen: open.filter((f) => f.exploitAvailable).length,
    slaBuckets: buckets,
    assetRisk,
    connectorCounts,
    statusCounts,
    trend,
    meanTimeToRemediateDays,
  };
}

// --- demo seed -------------------------------------------------------------

function seed(s: StoreShape): void {
  if (s.seeded) return;
  s.seeded = true;
  const now = Date.now();

  const historical: Array<{
    name: string;
    connector: ConnectorId;
    profile: string;
    targets: string[];
    daysAgo: number;
  }> = [
    {
      name: "Weekly External Vulnerability Scan",
      connector: "nessus",
      profile: "standard",
      targets: ["203.0.113.0/28"],
      daysAgo: 12,
    },
    {
      name: "Server Estate Credentialed Audit",
      connector: "nessus",
      profile: "credentialed",
      targets: ["10.10.0.0/24"],
      daysAgo: 8,
    },
    {
      name: "Falcon Spotlight Endpoint Sync",
      connector: "crowdstrike",
      profile: "agent-sync",
      targets: ["ws-fin-114.gmi.local", "ws-eng-207.gmi.local", "ws-ops-052.gmi.local"],
      daysAgo: 5,
    },
    {
      name: "Package Audit — Production Web Tier",
      connector: "vulners",
      profile: "credentialed",
      targets: ["web-prod-01.gmi.com", "web-prod-02.gmi.com", "app-erp-01.gmi.local"],
      daysAgo: 3,
    },
    {
      name: "Weekly External Vulnerability Scan",
      connector: "nessus",
      profile: "standard",
      targets: ["203.0.113.0/28"],
      daysAgo: 1,
    },
  ];

  for (const h of historical) {
    const id = nextId(s, "SCAN");
    const startedAtMs = now - h.daysAgo * 86_400_000;
    const seedVal = hashSeed(id + h.connector + h.name);
    const demo = getDemoProfile(h.connector);
    const rand = mulberry32(seedVal);
    const durationMs =
      demo.minDurationMs + Math.floor(rand() * (demo.maxDurationMs - demo.minDurationMs));
    const scan: InternalScan = {
      id,
      name: h.name,
      connector: h.connector,
      profile: h.profile,
      targets: h.targets,
      status: "Running",
      createdAt: new Date(startedAtMs).toISOString(),
      startedAt: new Date(startedAtMs).toISOString(),
      completedAt: null,
      findingsCount: 0,
      severityCounts: emptySeverityCounts(),
      hostsScanned: 0,
      requestedBy: "chuck@gmi.com",
      durationMs,
      progressFrozenAt: null,
      seed: seedVal,
      vendor: null,
    };
    s.scans.set(id, scan);
    settleScan(s, scan, now);
  }

  // Backdate firstSeen to the owning scan and triage a slice of findings so
  // dashboards, SLA buckets, and MTTR have believable history on first load.
  const findings = Array.from(s.findings.values());
  const triageRand = mulberry32(hashSeed("triage"));
  const analysts = ["chuck@gmi.com", "ash@gmi.com", "jordan@gmi.com"];
  for (const f of findings) {
    const scan = s.scans.get(f.scanId);
    if (scan?.completedAt) {
      f.firstSeen = scan.completedAt;
      f.lastSeen = scan.completedAt;
    }
    const roll = triageRand();
    if (roll < 0.18) {
      f.status = "Resolved";
      f.assignee = analysts[Math.floor(triageRand() * analysts.length)];
      const first = new Date(f.firstSeen).getTime();
      f.resolvedAt = new Date(
        first + (1 + triageRand() * 6) * 86_400_000,
      ).toISOString();
    } else if (roll < 0.34) {
      f.status = "In Remediation";
      f.assignee = analysts[Math.floor(triageRand() * analysts.length)];
    } else if (roll < 0.4) {
      f.status = "Risk Accepted";
    } else if (roll < 0.44) {
      f.status = "False Positive";
      f.resolvedAt = f.lastSeen;
    }
  }
  // Recompute per-scan rollups after triage so severity counts stay accurate.
  for (const scan of s.scans.values()) {
    const scoped = findings.filter((f) => f.scanId === scan.id);
    const counts = emptySeverityCounts();
    for (const f of scoped) counts[f.severity] += 1;
    scan.severityCounts = counts;
    scan.findingsCount = scoped.length;
    scan.hostsScanned = new Set(scoped.map((f) => f.asset)).size;
  }
}
