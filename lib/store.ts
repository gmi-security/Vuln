import { DEMO_ASSETS, DEMO_PORTS, VULN_CATALOG } from "@/lib/catalog";
import { getDemoProfile, isPlanned } from "@/lib/connectors";
import {
  nessusConfig,
  nessusImportFindings,
  nessusLaunchScan,
  nessusListFolders,
  nessusListScans,
  nessusScanControl,
  nessusScanStatus,
} from "@/lib/nessus";
import { classifyAsset, computeRealRisk, isKev } from "@/lib/threat";
import { tidalConfig, tidalListAssets } from "@/lib/tidal";
import type {
  AssetSource,
  Company,
  ConnectorId,
  Finding,
  FindingStatus,
  Folder,
  InventoryAsset,
  QuantifyMetrics,
  Scan,
  ScanStatus,
  Severity,
} from "@/lib/types";

// Threat + environment enrichment for a finding: KEV status, the asset's
// exposure/criticality (from the asset inventory when known, else inferred
// from the hostname), and the composite real-risk score.
function riskFields(
  s: StoreShape,
  input: {
    cve: string;
    cvss: number;
    epss: number;
    exploitAvailable: boolean;
    asset: string;
    companyId: string;
  },
) {
  const kev = isKev(input.cve);
  // Only inherit inventory context from an asset owned by the SAME customer —
  // never cross-attribute one client's asset criticality to another's finding.
  const inventory = lookupAsset(s, input.asset, input.companyId);
  const exposure = inventory ? inventory.exposure : classifyAsset(input.asset).exposure;
  const criticality = inventory
    ? inventory.criticality
    : classifyAsset(input.asset).criticality;
  const assetSource: AssetSource = inventory ? inventory.source : "inferred";
  const { score, priority } = computeRealRisk({
    cvss: input.cvss,
    kev,
    epss: input.epss,
    exploitAvailable: input.exploitAvailable,
    exposure,
    criticality,
  });
  return {
    kev,
    assetExposure: exposure,
    assetCriticality: criticality,
    assetSource,
    realRisk: score,
    riskPriority: priority,
  };
}

// In-memory operational store. Scans progress in real time (progress is a
// function of elapsed wall clock, so it advances between requests without a
// background worker) and completed scans materialize findings. Swap for
// Postgres/Prisma when persistence is needed — the API routes only talk to
// the functions exported here.

type InternalCompany = {
  id: string;
  name: string;
  industry: string;
  contactName: string;
  contactEmail: string;
  createdAt: string;
};

type InternalFolder = {
  id: string;
  companyId: string;
  name: string;
  createdAt: string;
};

type InternalAsset = Omit<InventoryAsset, "openFindings">;

type Settings = {
  // When on, discovering a known-but-unscanned asset (via the coverage diff or
  // a Tidal sync) automatically launches a scan for it.
  autoScanNewAssets: boolean;
};

type StoreShape = {
  companies: Map<string, InternalCompany>;
  folders: Map<string, InternalFolder>;
  scans: Map<string, InternalScan>;
  findings: Map<string, Finding>;
  assets: Map<string, InternalAsset>;
  settings: Settings;
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
      companies: new Map(),
      folders: new Map(),
      scans: new Map(),
      findings: new Map(),
      assets: new Map(),
      settings: { autoScanNewAssets: false },
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

// The demo catalog carries CVSS v3 base scores. Derive a stable, plausible
// CVSS v2 score from the v3 score and CVE id (v2 tends to run slightly lower
// and is capped at 10). Nessus-imported findings use the scanner's real v2/v3.
function deriveCvssV2(v3: number, key: string): number {
  if (v3 <= 0) return 0;
  const delta = ((hashSeed(`v2:${key}`) % 16) / 10) - 0.9; // -0.9 .. +0.6
  return Math.max(0, Math.min(10, Math.round((v3 + delta) * 10) / 10));
}

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
      companyId: scan.companyId,
      companyName: scan.companyName,
      connector: scan.connector,
      cve: template.cve,
      title: template.title,
      severity: template.severity,
      cvss: template.cvss,
      cvssV3: template.cvss,
      cvssV2: deriveCvssV2(template.cvss, template.cve),
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
      ...riskFields(s, {
        cve: template.cve,
        cvss: template.cvss,
        epss: template.epss,
        exploitAvailable: template.exploitAvailable,
        asset,
        companyId: scan.companyId,
      }),
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
        companyId: scan.companyId,
        companyName: scan.companyName,
        connector: scan.connector,
        cve: item.cve,
        title: item.title,
        severity: item.severity,
        cvss: item.cvss,
        cvssV3: item.cvssV3,
        cvssV2: item.cvssV2,
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
        ...riskFields(s, {
          cve: item.cve,
          cvss: item.cvss,
          epss: 0,
          exploitAvailable: item.exploitAvailable,
          asset: item.asset,
          companyId: scan.companyId,
        }),
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

// --- companies & folders ---------------------------------------------------

const EXPOSURE_WEIGHT: Record<Severity, number> = {
  Critical: 40,
  High: 20,
  Medium: 8,
  Low: 2,
  Info: 0,
};

// Exposure score (0-100): severity-weighted open findings boosted by
// exploit availability and EPSS, squashed with a decay curve so it reads
// like a gauge. Shared by global metrics and per-company rollups.
function exposureOf(open: Finding[]): number {
  const raw = open.reduce((sum, f) => {
    const exploitBoost = f.exploitAvailable ? 1.5 : 1;
    const epssBoost = 1 + f.epss;
    return sum + EXPOSURE_WEIGHT[f.severity] * exploitBoost * epssBoost;
  }, 0);
  return Math.round(100 * (1 - Math.exp(-raw / 900)));
}

function companyRollup(s: StoreShape, companyId: string) {
  const scans = Array.from(s.scans.values()).filter((sc) => sc.companyId === companyId);
  const findings = Array.from(s.findings.values()).filter((f) => f.companyId === companyId);
  const open = findings.filter(isOpen);
  const inventoryAssets = Array.from(s.assets.values()).filter(
    (a) => a.companyId === companyId,
  ).length;
  const withInventory = open.filter(
    (f) => f.assetSource === "tidal" || f.assetSource === "manual",
  ).length;
  return {
    folderCount: Array.from(s.folders.values()).filter((f) => f.companyId === companyId)
      .length,
    scanCount: scans.length,
    activeScans: scans.filter(
      (sc) => sc.status === "Running" || sc.status === "Paused" || sc.status === "Queued",
    ).length,
    openFindings: open.length,
    criticalOpen: open.filter((f) => f.severity === "Critical").length,
    exposureScore: exposureOf(open),
    inventoryAssets,
    inventoryCoverage: open.length
      ? Math.round((withInventory / open.length) * 100)
      : -1,
  };
}

function toPublicCompany(s: StoreShape, c: InternalCompany): Company {
  return { ...c, ...companyRollup(s, c.id) };
}

function toPublicFolder(s: StoreShape, f: InternalFolder): Folder {
  return {
    ...f,
    scanCount: Array.from(s.scans.values()).filter((sc) => sc.folderId === f.id).length,
  };
}

export function listCompanies(): Company[] {
  const s = store();
  tick(s);
  return Array.from(s.companies.values())
    .map((c) => toPublicCompany(s, c))
    .sort((a, b) => a.name.localeCompare(b.name));
}

export function getCompany(id: string): Company | undefined {
  const s = store();
  tick(s);
  const c = s.companies.get(id);
  return c ? toPublicCompany(s, c) : undefined;
}

export function createCompany(input: {
  name: string;
  industry?: string;
  contactName?: string;
  contactEmail?: string;
}): Company | { error: string } {
  const s = store();
  const name = input.name.trim();
  if (!name) return { error: "Company name is required." };
  if (
    Array.from(s.companies.values()).some(
      (c) => c.name.toLowerCase() === name.toLowerCase(),
    )
  ) {
    return { error: "A company with that name already exists." };
  }
  const id = nextId(s, "CO");
  const company: InternalCompany = {
    id,
    name,
    industry: (input.industry ?? "").trim(),
    contactName: (input.contactName ?? "").trim(),
    contactEmail: (input.contactEmail ?? "").trim(),
    createdAt: new Date().toISOString(),
  };
  s.companies.set(id, company);
  // Every company starts with a default folder so scans always have a home.
  ensureFolder(s, id, "General");
  return toPublicCompany(s, company);
}

export function updateCompany(
  id: string,
  patch: {
    name?: string;
    industry?: string;
    contactName?: string;
    contactEmail?: string;
  },
): Company | { error: string } {
  const s = store();
  const company = s.companies.get(id);
  if (!company) return { error: "Company not found." };
  if (patch.name !== undefined) {
    const name = patch.name.trim();
    if (!name) return { error: "Company name cannot be empty." };
    if (
      Array.from(s.companies.values()).some(
        (c) => c.id !== id && c.name.toLowerCase() === name.toLowerCase(),
      )
    ) {
      return { error: "A company with that name already exists." };
    }
    company.name = name;
    // Keep denormalized names on scans and findings in sync.
    for (const sc of s.scans.values()) if (sc.companyId === id) sc.companyName = name;
    for (const f of s.findings.values()) if (f.companyId === id) f.companyName = name;
  }
  if (patch.industry !== undefined) company.industry = patch.industry.trim();
  if (patch.contactName !== undefined) company.contactName = patch.contactName.trim();
  if (patch.contactEmail !== undefined) company.contactEmail = patch.contactEmail.trim();
  return toPublicCompany(s, company);
}

export function deleteCompany(id: string): { deleted: true } | { error: string } {
  const s = store();
  const company = s.companies.get(id);
  if (!company) return { error: "Company not found." };
  const hasScans = Array.from(s.scans.values()).some((sc) => sc.companyId === id);
  if (hasScans) {
    return { error: "Delete or move this company's scans before removing it." };
  }
  for (const f of Array.from(s.folders.values())) {
    if (f.companyId === id) s.folders.delete(f.id);
  }
  s.companies.delete(id);
  return { deleted: true };
}

export function listFolders(companyId?: string): Folder[] {
  const s = store();
  tick(s);
  return Array.from(s.folders.values())
    .filter((f) => !companyId || f.companyId === companyId)
    .map((f) => toPublicFolder(s, f))
    .sort((a, b) => a.name.localeCompare(b.name));
}

function ensureFolder(s: StoreShape, companyId: string, name: string): InternalFolder {
  const trimmed = name.trim() || "General";
  const existing = Array.from(s.folders.values()).find(
    (f) => f.companyId === companyId && f.name.toLowerCase() === trimmed.toLowerCase(),
  );
  if (existing) return existing;
  const id = nextId(s, "FLD");
  const folder: InternalFolder = {
    id,
    companyId,
    name: trimmed,
    createdAt: new Date().toISOString(),
  };
  s.folders.set(id, folder);
  return folder;
}

export function createFolder(
  companyId: string,
  name: string,
): Folder | { error: string } {
  const s = store();
  if (!s.companies.get(companyId)) return { error: "Company not found." };
  if (!name.trim()) return { error: "Folder name is required." };
  return toPublicFolder(s, ensureFolder(s, companyId, name));
}

export function deleteFolder(id: string): { deleted: true } | { error: string } {
  const s = store();
  const folder = s.folders.get(id);
  if (!folder) return { error: "Folder not found." };
  const hasScans = Array.from(s.scans.values()).some((sc) => sc.folderId === id);
  if (hasScans) return { error: "Move this folder's scans before deleting it." };
  s.folders.delete(id);
  return { deleted: true };
}

// Ensures a fallback company + folder exists for scans launched without an
// explicit company selection.
function ensureUnassigned(s: StoreShape): { company: InternalCompany; folder: InternalFolder } {
  let company = Array.from(s.companies.values()).find((c) => c.name === "Unassigned");
  if (!company) {
    const result = createCompany({ name: "Unassigned" });
    if ("error" in result) throw new Error(result.error);
    company = s.companies.get(result.id)!;
  }
  const folder = ensureFolder(s, company.id, "General");
  return { company, folder };
}

// --- asset inventory (Tidal.io) --------------------------------------------

// Match a finding's asset string to an inventory asset by identifier,
// hostname, or any of its IP addresses (case-insensitive). When companyId is
// given, only assets owned by that customer are considered — this keeps
// customer linkage honest (no cross-tenant attribution).
function lookupAsset(
  s: StoreShape,
  assetStr: string,
  companyId?: string,
): InternalAsset | undefined {
  const key = assetStr.trim().toLowerCase();
  if (!key) return undefined;
  for (const a of s.assets.values()) {
    if (companyId && a.companyId !== companyId) continue;
    if (a.identifier.toLowerCase() === key) return a;
    if (a.hostname && a.hostname.toLowerCase() === key) return a;
    if (a.ipAddresses.some((ip) => ip.toLowerCase() === key)) return a;
  }
  return undefined;
}

function toPublicAsset(s: StoreShape, a: InternalAsset): InventoryAsset {
  const openFindings = Array.from(s.findings.values()).filter(
    (f) =>
      (f.status === "Open" || f.status === "In Remediation") &&
      (f.asset.toLowerCase() === a.identifier.toLowerCase() ||
        f.asset.toLowerCase() === a.hostname.toLowerCase() ||
        a.ipAddresses.some((ip) => ip.toLowerCase() === f.asset.toLowerCase())),
  ).length;
  return { ...a, openFindings };
}

export function listAssets(filter?: { companyId?: string }): InventoryAsset[] {
  const s = store();
  tick(s);
  return Array.from(s.assets.values())
    .filter((a) => !filter?.companyId || a.companyId === filter.companyId)
    .map((a) => toPublicAsset(s, a))
    .sort((a, b) => a.identifier.localeCompare(b.identifier));
}

export type CoverageRow = {
  identifier: string;
  companyId: string;
  companyName: string;
  exposure: string | null;
  criticality: string | null;
  owner: string | null;
  source: string | null; // inventory source, or null for scanned-only
  openFindings: number;
  worstRisk: number;
};

export type AssetCoverage = {
  summary: {
    known: number;
    scanned: number;
    matched: number;
    knownNotScanned: number;
    scannedNotKnown: number;
  };
  matched: CoverageRow[];
  knownNotScanned: CoverageRow[];
  scannedNotKnown: CoverageRow[];
};

// Reconcile the asset inventory (what we KNOW exists, from Tidal/manual)
// against the assets that actually show up in scan results (what we've
// SCANNED). Matching is per-customer so linkage stays honest.
export function assetCoverage(filter?: { companyId?: string }): AssetCoverage {
  const s = store();
  tick(s);

  // Assets seen in findings, grouped per company by lowercased identifier.
  const scanned = new Map<
    string,
    Map<string, { identifier: string; open: number; worstRisk: number }>
  >();
  for (const f of s.findings.values()) {
    if (filter?.companyId && f.companyId !== filter.companyId) continue;
    const perCompany = scanned.get(f.companyId) ?? new Map();
    const key = f.asset.trim().toLowerCase();
    const entry = perCompany.get(key) ?? {
      identifier: f.asset,
      open: 0,
      worstRisk: 0,
    };
    if (f.status === "Open" || f.status === "In Remediation") entry.open += 1;
    entry.worstRisk = Math.max(entry.worstRisk, f.realRisk);
    perCompany.set(key, entry);
    scanned.set(f.companyId, perCompany);
  }

  const matched: CoverageRow[] = [];
  const knownNotScanned: CoverageRow[] = [];

  const knownAssets = Array.from(s.assets.values()).filter(
    (a) => !filter?.companyId || a.companyId === filter.companyId,
  );
  for (const a of knownAssets) {
    const perCompany = scanned.get(a.companyId);
    const keys = [a.identifier, a.hostname, ...a.ipAddresses]
      .map((k) => k.trim().toLowerCase())
      .filter(Boolean);
    let hitKey: string | undefined;
    if (perCompany) hitKey = keys.find((k) => perCompany.has(k));
    const base: CoverageRow = {
      identifier: a.identifier,
      companyId: a.companyId,
      companyName: a.companyName,
      exposure: a.exposure,
      criticality: a.criticality,
      owner: a.owner,
      source: a.source,
      openFindings: 0,
      worstRisk: 0,
    };
    if (hitKey && perCompany) {
      const entry = perCompany.get(hitKey)!;
      matched.push({ ...base, openFindings: entry.open, worstRisk: entry.worstRisk });
      perCompany.delete(hitKey); // consume so it isn't counted as shadow
    } else {
      knownNotScanned.push(base);
    }
  }

  // Whatever scanned assets remain unconsumed are not in the inventory.
  const scannedNotKnown: CoverageRow[] = [];
  for (const [companyId, perCompany] of scanned) {
    const company = s.companies.get(companyId);
    for (const entry of perCompany.values()) {
      scannedNotKnown.push({
        identifier: entry.identifier,
        companyId,
        companyName: company?.name ?? "—",
        exposure: null,
        criticality: null,
        owner: null,
        source: null,
        openFindings: entry.open,
        worstRisk: entry.worstRisk,
      });
    }
  }

  matched.sort((a, b) => b.worstRisk - a.worstRisk);
  knownNotScanned.sort((a, b) => a.companyName.localeCompare(b.companyName));
  scannedNotKnown.sort((a, b) => b.worstRisk - a.worstRisk);

  return {
    summary: {
      known: knownAssets.length,
      scanned: matched.length + scannedNotKnown.length,
      matched: matched.length,
      knownNotScanned: knownNotScanned.length,
      scannedNotKnown: scannedNotKnown.length,
    },
    matched,
    knownNotScanned,
    scannedNotKnown,
  };
}

export function getSettings(): Settings {
  return { ...store().settings };
}

export function updateSettings(patch: Partial<Settings>): Settings {
  const s = store();
  s.settings = { ...s.settings, ...patch };
  return { ...s.settings };
}

export type AutoScanResult = {
  scansLaunched: number;
  assetsQueued: number;
  companies: number;
};

// Launch scans for every known-but-unscanned asset, one scan per customer
// into an "Auto-Scan" folder, targeting that customer's gap assets. Naturally
// idempotent: once an asset has findings it leaves the gap and won't re-scan.
export async function autoScanGaps(): Promise<AutoScanResult> {
  const s = store();
  const coverage = assetCoverage();
  const byCompany = new Map<string, string[]>();
  for (const row of coverage.knownNotScanned) {
    const list = byCompany.get(row.companyId) ?? [];
    list.push(row.identifier);
    byCompany.set(row.companyId, list);
  }

  let scansLaunched = 0;
  let assetsQueued = 0;
  for (const [companyId, targets] of byCompany) {
    if (!targets.length) continue;
    const folder = ensureFolder(s, companyId, "Auto-Scan");
    const result = await startScan({
      name: "Auto-scan: newly discovered assets",
      connector: "nessus",
      profile: "discovery",
      targets,
      companyId,
      folderId: folder.id,
      requestedBy: "auto-scan",
    });
    if (!("error" in result)) {
      scansLaunched += 1;
      assetsQueued += targets.length;
    }
  }
  return { scansLaunched, assetsQueued, companies: byCompany.size };
}

// Recompute a finding's environmental context + real risk against the current
// inventory. Used after an inventory sync so existing findings reprice.
function rescoreFinding(s: StoreShape, f: Finding): void {
  Object.assign(
    f,
    riskFields(s, {
      cve: f.cve,
      cvss: f.cvss,
      epss: f.epss,
      exploitAvailable: f.exploitAvailable,
      asset: f.asset,
      companyId: f.companyId,
    }),
  );
}

function upsertAsset(
  s: StoreShape,
  input: Omit<InternalAsset, "id" | "lastSynced"> & { id?: string },
): InternalAsset {
  const nowIso = new Date().toISOString();
  // Match an existing asset by external id or identifier within the company.
  const existing = Array.from(s.assets.values()).find(
    (a) =>
      (input.externalId && a.externalId === input.externalId) ||
      (a.companyId === input.companyId &&
        a.identifier.toLowerCase() === input.identifier.toLowerCase()),
  );
  if (existing) {
    Object.assign(existing, input, { lastSynced: nowIso });
    return existing;
  }
  const id = input.id ?? nextId(s, "AST");
  const asset: InternalAsset = { ...input, id, lastSynced: nowIso };
  s.assets.set(id, asset);
  return asset;
}

export type TidalImportResult = {
  companiesCreated: number;
  assetsUpserted: number;
  findingsRescored: number;
  autoScan?: AutoScanResult;
};

// Pull the Tidal asset inventory, map each asset's customer to a company
// (match by name, create if missing), upsert the asset, then reprice every
// finding so real risk reflects the authoritative environment.
export async function importFromTidal(): Promise<
  TidalImportResult | { error: string }
> {
  if (!tidalConfig()) {
    return {
      error:
        "Tidal is not configured. Set TIDAL_API_URL and TIDAL_API_KEY to sync the asset inventory.",
    };
  }
  const s = store();
  let assets;
  try {
    assets = await tidalListAssets();
  } catch (err) {
    return {
      error: err instanceof Error ? err.message : "Failed to reach the Tidal API.",
    };
  }

  let companiesCreated = 0;
  let assetsUpserted = 0;
  for (const t of assets) {
    const customer = t.customer.trim() || "Unassigned";
    let company = Array.from(s.companies.values()).find(
      (c) => c.name.toLowerCase() === customer.toLowerCase(),
    );
    if (!company) {
      const created = createCompany({ name: customer });
      if ("error" in created) continue;
      company = s.companies.get(created.id)!;
      companiesCreated += 1;
    }
    const identifier = t.hostname || t.ipAddresses[0] || t.externalId;
    if (!identifier) continue;
    upsertAsset(s, {
      identifier,
      hostname: t.hostname,
      ipAddresses: t.ipAddresses,
      companyId: company.id,
      companyName: company.name,
      exposure: t.exposure,
      criticality: t.criticality,
      os: t.os,
      owner: t.owner,
      tags: t.tags,
      source: "tidal",
      externalId: t.externalId,
    });
    assetsUpserted += 1;
  }

  let findingsRescored = 0;
  for (const f of s.findings.values()) {
    const before = f.realRisk;
    rescoreFinding(s, f);
    if (f.realRisk !== before || f.assetSource === "tidal") findingsRescored += 1;
  }

  // If auto-scan is enabled, scan any newly-known assets that have no
  // coverage yet.
  let autoScan: AutoScanResult | undefined;
  if (s.settings.autoScanNewAssets) {
    autoScan = await autoScanGaps();
  }

  return { companiesCreated, assetsUpserted, findingsRescored, autoScan };
}

export type NessusImportResult = {
  companiesCreated: number;
  companiesMatched: number;
  scansImported: number;
  findingsImported: number;
  skipped: number;
};

// Import the scanner's folder structure as companies: each Nessus folder
// becomes (or matches, by name) a Vuln company, and the scans inside it are
// imported into that company's "Nessus" folder. Completed scans also pull
// their findings. Idempotent — re-running only adds what's new.
export async function importFromNessus(): Promise<
  NessusImportResult | { error: string }
> {
  if (!nessusConfig()) {
    return {
      error:
        "Nessus is not configured. Set NESSUS_URL, NESSUS_ACCESS_KEY, and NESSUS_SECRET_KEY to import.",
    };
  }
  const s = store();

  let folders;
  try {
    folders = await nessusListFolders();
  } catch (err) {
    return {
      error: err instanceof Error ? err.message : "Failed to list Nessus folders.",
    };
  }

  // Map each importable Nessus folder to a Vuln company (match by name,
  // create if missing). Skip Nessus's built-in folders — Trash, the default
  // "My Scans" (type "main"), and the virtual "All Scans" view — since those
  // aren't clients.
  const BUILTIN_FOLDERS = new Set(["my scans", "all scans", "trash"]);
  const folderToCompany = new Map<number, string>();
  let companiesCreated = 0;
  let companiesMatched = 0;
  for (const folder of folders) {
    if (folder.type === "trash" || folder.type === "main") continue;
    if (BUILTIN_FOLDERS.has(folder.name.trim().toLowerCase())) continue;
    const existing = Array.from(s.companies.values()).find(
      (c) => c.name.toLowerCase() === folder.name.toLowerCase(),
    );
    let companyId: string;
    if (existing) {
      companyId = existing.id;
      companiesMatched += 1;
    } else {
      const created = createCompany({ name: folder.name });
      if ("error" in created) continue;
      companyId = created.id;
      companiesCreated += 1;
    }
    folderToCompany.set(folder.id, companyId);
    ensureFolder(s, companyId, "Nessus");
  }

  let scans: Awaited<ReturnType<typeof nessusListScans>>;
  try {
    scans = await nessusListScans();
  } catch {
    scans = [];
  }

  let scansImported = 0;
  let findingsImported = 0;
  let skipped = 0;
  for (const summary of scans) {
    const companyId = folderToCompany.get(summary.folderId);
    if (!companyId) {
      skipped += 1;
      continue;
    }
    // Skip scans already linked to a Vuln scan record.
    const already = Array.from(s.scans.values()).some(
      (sc) => sc.vendor?.nessusScanId === summary.id,
    );
    if (already) {
      skipped += 1;
      continue;
    }
    const company = s.companies.get(companyId)!;
    const folder = ensureFolder(s, companyId, "Nessus");
    const status = NESSUS_STATUS_MAP[summary.status] ?? "Completed";
    const nowIso = new Date().toISOString();
    const completedAt =
      status === "Completed" || status === "Stopped"
        ? summary.lastModified
          ? new Date(summary.lastModified * 1000).toISOString()
          : nowIso
        : null;
    const id = nextId(s, "SCAN");
    const scan: InternalScan = {
      id,
      name: summary.name,
      companyId: company.id,
      companyName: company.name,
      folderId: folder.id,
      folderName: folder.name,
      connector: "nessus",
      profile: "imported",
      targets: [],
      status,
      createdAt: nowIso,
      startedAt: completedAt ?? nowIso,
      completedAt,
      findingsCount: 0,
      severityCounts: emptySeverityCounts(),
      hostsScanned: 0,
      requestedBy: "imported@nessus",
      durationMs: 1,
      progressFrozenAt: status === "Completed" ? 100 : 0,
      seed: hashSeed(id + summary.name),
      vendor: { nessusScanId: summary.id, lastPoll: Date.now(), imported: false },
    };
    s.scans.set(id, scan);
    scansImported += 1;
    if (status === "Completed") {
      try {
        await importVendorFindings(s, scan);
        scan.vendor!.imported = true;
        findingsImported += scan.findingsCount;
      } catch {
        // leave imported=false so a later poll retries the findings import
      }
    }
  }

  return {
    companiesCreated,
    companiesMatched,
    scansImported,
    findingsImported,
    skipped,
  };
}

// Resolve the company + folder a new scan belongs to from loose input.
function resolveScanLocation(
  s: StoreShape,
  input: { companyId?: string; folderId?: string; folderName?: string },
): { company: InternalCompany; folder: InternalFolder } {
  const company = input.companyId ? s.companies.get(input.companyId) : undefined;
  if (!company) return ensureUnassigned(s);
  if (input.folderId) {
    const folder = s.folders.get(input.folderId);
    if (folder && folder.companyId === company.id) return { company, folder };
  }
  if (input.folderName && input.folderName.trim()) {
    return { company, folder: ensureFolder(s, company.id, input.folderName) };
  }
  return { company, folder: ensureFolder(s, company.id, "General") };
}

// --- public API -----------------------------------------------------------

export async function listScans(filter?: {
  companyId?: string;
  folderId?: string;
}): Promise<Scan[]> {
  const s = store();
  tick(s);
  await refreshVendorScans(s);
  const now = Date.now();
  return Array.from(s.scans.values())
    .filter((scan) => !filter?.companyId || scan.companyId === filter.companyId)
    .filter((scan) => !filter?.folderId || scan.folderId === filter.folderId)
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
  companyId?: string;
  folderId?: string;
  folderName?: string;
  requestedBy?: string;
}): Promise<Scan | { error: string }> {
  const s = store();
  if (isPlanned(input.connector)) {
    return { error: "Qualys VMDR integration is planned but not yet available." };
  }
  if (!input.targets.length) {
    return { error: "At least one target is required." };
  }
  const { company, folder } = resolveScanLocation(s, input);

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
    companyId: company.id,
    companyName: company.name,
    folderId: folder.id,
    folderName: folder.name,
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

export function listFindings(filter?: { scanId?: string; companyId?: string }): Finding[] {
  const s = store();
  tick(s);
  let all = Array.from(s.findings.values());
  if (filter?.scanId) all = all.filter((f) => f.scanId === filter.scanId);
  if (filter?.companyId) all = all.filter((f) => f.companyId === filter.companyId);
  // Default to real-risk order so the most dangerous findings surface first.
  return all.sort((a, b) => b.realRisk - a.realRisk || b.cvss - a.cvss);
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

export function computeMetrics(filter?: { companyId?: string }): QuantifyMetrics {
  const s = store();
  tick(s);
  const all = Array.from(s.findings.values()).filter(
    (f) => !filter?.companyId || f.companyId === filter.companyId,
  );
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

  const byCompany = new Map<string, { name: string; open: Finding[] }>();
  for (const f of open) {
    const entry = byCompany.get(f.companyId) ?? { name: f.companyName, open: [] };
    entry.open.push(f);
    byCompany.set(f.companyId, entry);
  }
  const companyBreakdown = Array.from(byCompany.entries())
    .map(([companyId, v]) => ({
      companyId,
      companyName: v.name,
      open: v.open.length,
      critical: v.open.filter((f) => f.severity === "Critical").length,
      exposureScore: exposureOf(v.open),
    }))
    .sort((a, b) => b.exposureScore - a.exposureScore || b.open - a.open);

  const riskPriorityCounts = {
    Critical: 0,
    High: 0,
    Medium: 0,
    Low: 0,
    Info: 0,
  };
  for (const f of open) riskPriorityCounts[f.riskPriority] += 1;

  const topRisks = [...open]
    .sort((a, b) => b.realRisk - a.realRisk)
    .slice(0, 12)
    .map((f) => ({
      id: f.id,
      cve: f.cve,
      title: f.title,
      asset: f.asset,
      companyName: f.companyName,
      realRisk: f.realRisk,
      riskPriority: f.riskPriority,
      kev: f.kev,
      exposure: f.assetExposure,
    }));

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
    companyBreakdown,
    kevOpen: open.filter((f) => f.kev).length,
    riskPriorityCounts,
    topRisks,
  };
}

// --- demo seed -------------------------------------------------------------

function seed(s: StoreShape): void {
  if (s.seeded) return;
  s.seeded = true;
  const now = Date.now();

  // Client companies we run scans for, each with Nessus-style folders.
  const seedCompanies: Array<{
    name: string;
    industry: string;
    contactName: string;
    contactEmail: string;
    folders: string[];
  }> = [
    {
      name: "Northwind Retail",
      industry: "Retail / eCommerce",
      contactName: "Dana Ruiz",
      contactEmail: "dana.ruiz@northwind.example",
      folders: ["External", "Internal", "PCI"],
    },
    {
      name: "Cascade Health",
      industry: "Healthcare",
      contactName: "Dr. Omar Feld",
      contactEmail: "ofeld@cascadehealth.example",
      folders: ["External", "Endpoints", "Servers"],
    },
    {
      name: "Meridian Financial",
      industry: "Financial Services",
      contactName: "Priya Anand",
      contactEmail: "panand@meridianfin.example",
      folders: ["External", "Internal"],
    },
  ];

  const companyByName = new Map<string, InternalCompany>();
  for (const c of seedCompanies) {
    const created = createCompany({
      name: c.name,
      industry: c.industry,
      contactName: c.contactName,
      contactEmail: c.contactEmail,
    });
    if ("error" in created) continue;
    const company = s.companies.get(created.id)!;
    companyByName.set(c.name, company);
    for (const folderName of c.folders) ensureFolder(s, company.id, folderName);
  }

  // Sample manually-known asset inventory. Marked source "manual" — this is
  // NOT a Tidal sync; connecting Tidal.io replaces/extends it with the real
  // per-customer inventory. Coverage is deliberately partial, so some
  // findings resolve to inventory context and the rest fall back to inferred.
  const seedAssets: Array<{
    company: string;
    identifier: string;
    ips: string[];
    exposure: InternalAsset["exposure"];
    criticality: InternalAsset["criticality"];
    os: string;
    owner: string;
  }> = [
    { company: "Northwind Retail", identifier: "web-prod-01.gmi.com", ips: ["203.0.113.11"], exposure: "Internet-facing", criticality: "Crown Jewel", os: "Ubuntu 22.04", owner: "Platform" },
    { company: "Northwind Retail", identifier: "web-prod-02.gmi.com", ips: ["203.0.113.12"], exposure: "Internet-facing", criticality: "High", os: "Ubuntu 22.04", owner: "Platform" },
    { company: "Northwind Retail", identifier: "sql-prod-01.gmi.local", ips: ["10.10.0.21"], exposure: "Internal", criticality: "Crown Jewel", os: "Windows Server 2022", owner: "DBA" },
    { company: "Cascade Health", identifier: "mail.gmi.com", ips: ["203.0.113.25"], exposure: "Internet-facing", criticality: "High", os: "Exchange 2019", owner: "IT Ops" },
    { company: "Cascade Health", identifier: "esxi-01.gmi.local", ips: ["10.20.0.5"], exposure: "Internal", criticality: "Crown Jewel", os: "VMware ESXi 8", owner: "Infra" },
    { company: "Cascade Health", identifier: "ws-fin-114.gmi.local", ips: ["10.20.5.114"], exposure: "Internal", criticality: "Low", os: "Windows 11", owner: "Finance" },
    { company: "Meridian Financial", identifier: "vpn.gmi.com", ips: ["198.51.100.9"], exposure: "Internet-facing", criticality: "Crown Jewel", os: "FortiOS 7.4", owner: "NetSec" },
    { company: "Meridian Financial", identifier: "dc02.gmi.local", ips: ["10.30.0.10"], exposure: "Internal", criticality: "Crown Jewel", os: "Windows Server 2022", owner: "Directory" },
  ];
  for (const a of seedAssets) {
    const company = companyByName.get(a.company);
    if (!company) continue;
    upsertAsset(s, {
      identifier: a.identifier,
      hostname: a.identifier,
      ipAddresses: a.ips,
      companyId: company.id,
      companyName: company.name,
      exposure: a.exposure,
      criticality: a.criticality,
      os: a.os,
      owner: a.owner,
      tags: [],
      source: "manual",
      externalId: "",
    });
  }

  const historical: Array<{
    name: string;
    company: string;
    folder: string;
    connector: ConnectorId;
    profile: string;
    targets: string[];
    daysAgo: number;
  }> = [
    {
      name: "Weekly External Vulnerability Scan",
      company: "Northwind Retail",
      folder: "External",
      connector: "nessus",
      profile: "standard",
      targets: ["203.0.113.0/28"],
      daysAgo: 12,
    },
    {
      name: "PCI External Scan",
      company: "Northwind Retail",
      folder: "PCI",
      connector: "nessus",
      profile: "pci",
      targets: ["203.0.113.16/28"],
      daysAgo: 6,
    },
    {
      name: "Server Estate Credentialed Audit",
      company: "Cascade Health",
      folder: "Servers",
      connector: "nessus",
      profile: "credentialed",
      targets: ["10.10.0.0/24"],
      daysAgo: 8,
    },
    {
      name: "Falcon Spotlight Endpoint Sync",
      company: "Cascade Health",
      folder: "Endpoints",
      connector: "crowdstrike",
      profile: "agent-sync",
      targets: ["ws-fin-114.gmi.local", "ws-eng-207.gmi.local", "ws-ops-052.gmi.local"],
      daysAgo: 5,
    },
    {
      name: "Package Audit — Production Web Tier",
      company: "Meridian Financial",
      folder: "Internal",
      connector: "vulners",
      profile: "credentialed",
      targets: ["web-prod-01.gmi.com", "web-prod-02.gmi.com", "app-erp-01.gmi.local"],
      daysAgo: 3,
    },
    {
      name: "Weekly External Vulnerability Scan",
      company: "Meridian Financial",
      folder: "External",
      connector: "nessus",
      profile: "standard",
      targets: ["198.51.100.0/28"],
      daysAgo: 1,
    },
  ];

  for (const h of historical) {
    const company = companyByName.get(h.company)!;
    const folder = ensureFolder(s, company.id, h.folder);
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
      companyId: company.id,
      companyName: company.name,
      folderId: folder.id,
      folderName: folder.name,
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
