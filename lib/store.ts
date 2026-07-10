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
import {
  classifyAsset,
  computeRealRisk,
  fetchEpss,
  fetchNvd,
  isKev,
  isKevRansomware,
  refreshKevFromCisa,
} from "@/lib/threat";
import {
  tidalConfig,
  tidalListAssets,
  type TidalAsset,
  type TidalProgress,
} from "@/lib/tidal";
import { intuneConfig, intuneListAssets } from "@/lib/intune";
import { falconConfig, falconListAssets, spotlightListFindings } from "@/lib/crowdstrike";
import { defenderConfig, defenderListFindings } from "@/lib/defender";
import { burpConfig, burpListIssues, type BurpFinding } from "@/lib/burp";
import {
  nmapConfig,
  nmapListHosts,
  nmapServiceFindings,
  type NmapHost,
} from "@/lib/nmap";
import { buildRisk, grcConfig, grcUpsertRisk, riskCode } from "@/lib/grc";
import {
  vulnersConfig,
  vulnersEnrichCves,
  vulnersBridgeConfig,
  vulnersBridgeScanHost,
  type VulnersCveData,
  type VulnersBridgeFinding,
} from "@/lib/vulners";
import {
  spiderfootConfig,
  spiderfootImportFindings,
  spiderfootListScans,
  spiderfootStartScan,
} from "@/lib/spiderfoot";
import {
  artemisAddTargets,
  artemisConfig,
  artemisImportFindings,
  type ArtemisFinding,
} from "@/lib/artemis";
import {
  evaluateFramework,
  FRAMEWORKS,
  type ComplianceSignals,
} from "@/lib/compliance";
import { dueInfo, ssvc, type SsvcDecision } from "@/lib/ssvc";
import { loadSnapshot, persistenceEnabled, saveSnapshot } from "@/lib/persist";
import type {
  AssetSource,
  AttackEntry,
  AttackHop,
  AttackPathResult,
  CompliancePosture,
  ComplianceRequirement,
  ComplianceResult,
  ComplianceStatus,
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
  const ransomware = kev && isKevRansomware(input.cve);
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
    ransomware,
  });
  return {
    kev,
    ransomware,
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
  kind: "internal" | "client";
  industry: string;
  contactName: string;
  contactEmail: string;
  createdAt: string;
};

// GMI is our own organization — treat any company named GMI as internal.
function inferCompanyKind(name: string): "internal" | "client" {
  return /\bgmi\b/i.test(name) ? "internal" : "client";
}

// Demo/test companies (e.g. "SplashWorks Services, Inc. (Testing)") exist so the
// tool can be shown without real customer data. They stay fully usable in the
// console but are EXCLUDED from production reporting and GRC push so they never
// pollute real metrics or compliance posture. A company is demo when its name
// carries a test/demo/sandbox marker, or it's listed in the DEMO_COMPANIES env
// var (comma-separated names or ids).
function isDemoName(name: string): boolean {
  return /\(test(?:ing)?\)|\b(?:demo|sandbox)\b/i.test(name);
}

function demoCompanyIds(s: StoreShape): Set<string> {
  const allow = new Set(
    (process.env.DEMO_COMPANIES ?? "")
      .split(",")
      .map((x) => x.trim().toLowerCase())
      .filter(Boolean),
  );
  const ids = new Set<string>();
  for (const c of s.companies.values()) {
    if (isDemoName(c.name) || allow.has(c.name.toLowerCase()) || allow.has(c.id.toLowerCase())) {
      ids.add(c.id);
    }
  }
  return ids;
}

export function isDemoCompany(company: { id: string; name: string }): boolean {
  const allow = new Set(
    (process.env.DEMO_COMPANIES ?? "")
      .split(",")
      .map((x) => x.trim().toLowerCase())
      .filter(Boolean),
  );
  return (
    isDemoName(company.name) ||
    allow.has(company.name.toLowerCase()) ||
    allow.has(company.id.toLowerCase())
  );
}

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
  // Stable reference to an external source scan (e.g. "spiderfoot:<id>") so
  // pull-based imports stay idempotent. Absent for native/demo scans.
  externalRef?: string;
  // Set when the scan is running via the Vulners Bridge (nmap active scanner).
  // Mutually exclusive with vendor — bridge scans self-manage their lifecycle.
  bridgeScan?: { done: boolean };
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

// --- snapshot persistence --------------------------------------------------

function serializeStore(s: StoreShape) {
  return {
    companies: [...s.companies.entries()],
    folders: [...s.folders.entries()],
    scans: [...s.scans.entries()],
    findings: [...s.findings.entries()],
    assets: [...s.assets.entries()],
    settings: s.settings,
    counter: s.counter,
  };
}

function deserializeStore(obj: {
  companies?: [string, InternalCompany][];
  folders?: [string, InternalFolder][];
  scans?: [string, InternalScan][];
  findings?: [string, Finding][];
  assets?: [string, InternalAsset][];
  settings?: Settings;
  counter?: number;
}): StoreShape {
  return {
    companies: new Map(obj.companies ?? []),
    folders: new Map(obj.folders ?? []),
    scans: new Map(obj.scans ?? []),
    findings: new Map(obj.findings ?? []),
    assets: new Map(obj.assets ?? []),
    settings: obj.settings ?? { autoScanNewAssets: false },
    seeded: true,
    counter: obj.counter ?? 1000,
  };
}

const persistGlobal = globalThis as unknown as {
  __vulnHydrated?: boolean;
  __vulnHydrating?: Promise<void>;
  __vulnFlusher?: ReturnType<typeof setInterval>;
  __vulnFlushing?: Promise<void> | null;
  __vulnDrainHooked?: boolean;
  // Set when hydration could not read an existing snapshot: the app serves
  // from memory but all snapshot writes are disabled so a transient DB outage
  // can never overwrite good stored data with a freshly seeded store.
  __vulnPersistBlocked?: boolean;
  // Set by mutations, cleared by a successful snapshot save, so the interval
  // flusher can skip serializing an unchanged store.
  __vulnDirty?: boolean;
};

// True when persistence is fail-closed after a hydration failure. Lib callers
// (health endpoints, admin UI) can surface this state.
export function persistenceBlocked(): boolean {
  return Boolean(persistGlobal.__vulnPersistBlocked);
}

// Record that the in-memory store changed since the last snapshot save.
function markDirty(): void {
  persistGlobal.__vulnDirty = true;
}

// Serialize all snapshot writes through a single in-flight promise so an
// interval tick and a flushNow() (or two mutations) can never commit out of
// order and let a stale snapshot clobber a newer one.
function persistSnapshot(): Promise<void> {
  if (
    !persistenceEnabled() ||
    persistGlobal.__vulnPersistBlocked ||
    !globalStore.__vulnStore
  ) {
    return Promise.resolve();
  }
  const run = (persistGlobal.__vulnFlushing ?? Promise.resolve()).then(async () => {
    if (!globalStore.__vulnStore || persistGlobal.__vulnPersistBlocked) return;
    // Clear the dirty flag before serializing so mutations that land during
    // the save re-mark it and get picked up by the next flush.
    persistGlobal.__vulnDirty = false;
    try {
      await saveSnapshot(serializeStore(globalStore.__vulnStore));
    } catch (err) {
      persistGlobal.__vulnDirty = true;
      console.error("[persist] snapshot save failed:", err);
    }
  });
  persistGlobal.__vulnFlushing = run.finally(() => {
    if (persistGlobal.__vulnFlushing === run) persistGlobal.__vulnFlushing = null;
  });
  return run;
}

// On graceful shutdown (DO sends SIGTERM before a redeploy/restart) drain any
// pending in-memory writes so mutations in the last few seconds aren't lost.
function hookDrainOnce(): void {
  if (persistGlobal.__vulnDrainHooked || !persistenceEnabled()) return;
  persistGlobal.__vulnDrainHooked = true;
  const drain = () => {
    void persistSnapshot();
  };
  process.once("SIGTERM", drain);
  process.once("SIGINT", drain);
  process.once("beforeExit", drain);
}

// Hydrate the store from the DB snapshot once per process (or seed if empty),
// then start the background flusher. Every store-touching route awaits this
// before reading/writing, so a request never seeds an empty store ahead of a
// pending snapshot load.
export async function ensureHydrated(): Promise<void> {
  if (persistGlobal.__vulnHydrated) return;
  if (!persistGlobal.__vulnHydrating) persistGlobal.__vulnHydrating = doHydrate();
  await persistGlobal.__vulnHydrating;
}

const HYDRATE_ATTEMPTS = 3;

async function doHydrate(): Promise<void> {
  if (persistenceEnabled()) {
    // A transient DB error here must never be treated as "empty DB" — that
    // path would seed a fresh store and overwrite the good snapshot. Retry,
    // and if the snapshot still can't be read, fail closed: serve from
    // memory with all snapshot writes disabled. A load that succeeds and
    // returns null (no row yet) is a genuinely empty DB, where seeding and
    // saving is correct.
    let snap: unknown | null = null;
    let loadFailed = true;
    for (let attempt = 1; attempt <= HYDRATE_ATTEMPTS; attempt += 1) {
      try {
        snap = await loadSnapshot();
        loadFailed = false;
        break;
      } catch (err) {
        console.error(
          `[persist] hydrate attempt ${attempt}/${HYDRATE_ATTEMPTS} failed:`,
          err,
        );
        if (attempt < HYDRATE_ATTEMPTS) {
          await new Promise((r) => setTimeout(r, 1000 * attempt));
        }
      }
    }
    if (loadFailed) {
      persistGlobal.__vulnPersistBlocked = true;
      console.error(
        "[persist] PERSISTENCE BLOCKED: could not load the snapshot after " +
          `${HYDRATE_ATTEMPTS} attempts. Serving from an in-memory store; ` +
          "all snapshot writes are disabled until restart so the stored data " +
          "is never overwritten by a fresh seed.",
      );
    } else if (snap) {
      globalStore.__vulnStore = deserializeStore(snap as never);
    }
  }
  store(); // seed if still uninitialized
  persistGlobal.__vulnHydrated = true;
  startFlusher();
  // Kick off an initial persist in the background — the flusher covers it
  // anyway and we must not block the first request waiting for a DB write.
  // (No-op while persistence is blocked.)
  void persistSnapshot();
}

function startFlusher(): void {
  if (
    !persistenceEnabled() ||
    persistGlobal.__vulnPersistBlocked ||
    persistGlobal.__vulnFlusher
  ) {
    return;
  }
  hookDrainOnce();
  persistGlobal.__vulnFlusher = setInterval(() => {
    // Skip this tick if a save is already in flight — persistSnapshot chains
    // writes so nothing overlaps or commits out of order.
    if (persistGlobal.__vulnFlushing) return;
    // Nothing changed since the last save: skip the (large) serialization.
    if (!persistGlobal.__vulnDirty) return;
    void persistSnapshot();
  }, 6000);
}

// Non-sensitive counts + a stable seed marker, for the health endpoint. The
// oldest company's createdAt stays constant if data was hydrated from the DB,
// but changes if the store was re-seeded — so it proves persistence.
export async function storeStatus(): Promise<{
  hydrated: boolean;
  persistBlocked: boolean;
  counts: { companies: number; scans: number; findings: number; assets: number };
  oldestCompanyCreatedAt: string | null;
}> {
  await ensureHydrated();
  const s = globalStore.__vulnStore!;
  const oldest = Array.from(s.companies.values())
    .map((c) => c.createdAt)
    .sort()[0];
  return {
    hydrated: Boolean(persistGlobal.__vulnHydrated),
    persistBlocked: persistenceBlocked(),
    counts: {
      companies: s.companies.size,
      scans: s.scans.size,
      findings: s.findings.size,
      assets: s.assets.size,
    },
    oldestCompanyCreatedAt: oldest ?? null,
  };
}

// Force an immediate snapshot write (used right after large imports).
export async function flushNow(): Promise<void> {
  await persistSnapshot();
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

// Demo-only stand-in for Tenable VPR (0-10): base CVSS nudged up for real-world
// threat (KEV / EPSS / public exploit). Real Nessus findings carry the true VPR.
function deriveVpr(
  cvss: number,
  epss: number,
  kev: boolean,
  exploit: boolean,
): number {
  if (cvss <= 0) return 0;
  const boost = (kev ? 1.2 : 0) + (exploit ? 0.6 : 0) + epss * 1.5;
  return Math.max(0, Math.min(10, Math.round((cvss * 0.85 + boost) * 10) / 10));
}

function emptySeverityCounts(): Record<Severity, number> {
  return { Critical: 0, High: 0, Medium: 0, Low: 0, Info: 0 };
}

// --- scan lifecycle ------------------------------------------------------

// Production posture: the demo scan simulator is OPT-IN. With DEMO_SCANS unset
// (the production default) an unconfigured connector can never fabricate
// findings — scans only run against real, configured scanners.
function demoScansEnabled(): boolean {
  return process.env.DEMO_SCANS === "true";
}

function nextId(s: StoreShape, prefix: string): string {
  s.counter += 1;
  markDirty(); // every entity creation funnels through here
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
    const dedupeKey = `${scan.companyId}::${template.cve}::${asset}`;
    // Same CVE on the same asset seen by a new scan for the same customer
    // updates lastSeen instead of duplicating the finding.
    const existing = Array.from(s.findings.values()).find(
      (f) =>
        `${f.companyId}::${f.cve}::${f.asset}` === dedupeKey &&
        f.status !== "Resolved",
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
      vpr: deriveVpr(template.cvss, template.epss, isKev(template.cve), template.exploitAvailable),
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
  if (scan.bridgeScan) return; // bridge scans self-manage via runVulnersBridgeScanAsync
  if (!demoScansEnabled()) return; // production: never fabricate demo findings
  if (scan.status !== "Running") return;
  const progress = computeProgress(scan, now);
  if (progress < 100) return;
  markDirty();
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
      markDirty();
      if (
        (scan.status === "Completed" || scan.status === "Stopped") &&
        !scan.completedAt
      ) {
        scan.completedAt = new Date(now).toISOString();
      }
      if (scan.status === "Completed" && !scan.vendor.imported) {
        // Mark imported only after the import succeeds, so a transient
        // Nessus failure leaves it false and the next poll retries.
        await importVendorFindings(s, scan);
        scan.vendor.imported = true;
      }
    } catch (err) {
      scan.error = err instanceof Error ? err.message : "Nessus polling failed.";
      markDirty();
    }
  }
}

async function importVendorFindings(s: StoreShape, scan: InternalScan): Promise<void> {
  const imported = await nessusImportFindings(scan.vendor!.nessusScanId);
  const completedAt = scan.completedAt ?? new Date().toISOString();
  for (const item of imported) {
    // Company-scoped dedupe: customers can share asset strings (10.x IPs,
    // DESKTOP-XXXX), so one client's finding must never swallow another's.
    const dedupeKey = `${scan.companyId}::${item.cve}::${item.asset}::${item.title}`;
    const existing = Array.from(s.findings.values()).find(
      (f) =>
        `${f.companyId}::${f.cve}::${f.asset}::${f.title}` === dedupeKey &&
        f.status !== "Resolved",
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
        cves: item.cves,
        title: item.title,
        severity: item.severity,
        cvss: item.cvss,
        cvssV3: item.cvssV3,
        cvssV2: item.cvssV2,
        vpr: item.vpr,
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

const COMPOSITE_SLA_DAYS: Record<Severity, number> = {
  Critical: 7,
  High: 30,
  Medium: 90,
  Low: 180,
  Info: 365,
};

function compositeBand(
  score: number,
): "Low" | "Guarded" | "Elevated" | "High" | "Critical" {
  if (score >= 80) return "Critical";
  if (score >= 60) return "High";
  if (score >= 40) return "Elevated";
  if (score >= 20) return "Guarded";
  return "Low";
}

// Composite security-posture score (0-100, higher = worse). Blends four
// normalized signals with weights; when a signal is unavailable (e.g. no
// inventory to measure coverage against), its weight is redistributed so the
// score stays comparable.
function computeComposite(
  open: Finding[],
  coverage: { known: number; scanned: number } | null,
) {
  const now = Date.now();
  const exposure = exposureOf(open); // 0-100 severity×exploit×EPSS load
  const kevPressure = open.length
    ? Math.round((open.filter((f) => f.kev).length / open.length) * 100)
    : 0;
  const breached = open.filter(
    (f) =>
      (now - new Date(f.firstSeen).getTime()) / 86_400_000 >
      COMPOSITE_SLA_DAYS[f.severity],
  ).length;
  const slaBreach = open.length ? Math.round((breached / open.length) * 100) : 0;

  const hasCoverage = coverage && coverage.known > 0;
  const coverageGap = hasCoverage
    ? Math.round((1 - coverage!.scanned / coverage!.known) * 100)
    : 0;

  const weights: Record<string, number> = {
    exposure: 0.4,
    kevPressure: 0.25,
    slaBreach: 0.2,
    coverageGap: 0.15,
  };
  // Drop coverage weight when we can't measure it, and renormalize.
  if (!hasCoverage) delete weights.coverageGap;
  const totalWeight = Object.values(weights).reduce((a, b) => a + b, 0);
  const values: Record<string, number> = {
    exposure,
    kevPressure,
    slaBreach,
    coverageGap,
  };
  let score = 0;
  for (const [k, w] of Object.entries(weights)) score += values[k] * (w / totalWeight);
  score = Math.round(score);

  return {
    score,
    band: compositeBand(score),
    components: { exposure, kevPressure, slaBreach, coverageGap },
  };
}

// Scan coverage (known vs scanned inventory assets) for a company, cheaply.
function companyCoverage(
  s: StoreShape,
  companyId: string,
): { known: number; scanned: number } {
  const known = Array.from(s.assets.values()).filter((a) => a.companyId === companyId);
  const findingAssets = new Set(
    Array.from(s.findings.values())
      .filter((f) => f.companyId === companyId)
      .map((f) => f.asset.trim().toLowerCase()),
  );
  let scanned = 0;
  for (const a of known) {
    const keys = [a.identifier, a.hostname, ...a.ipAddresses].map((k) =>
      k.trim().toLowerCase(),
    );
    if (keys.some((k) => findingAssets.has(k))) scanned += 1;
  }
  return { known: known.length, scanned };
}

function companyRollup(s: StoreShape, companyId: string) {
  const scans = Array.from(s.scans.values()).filter((sc) => sc.companyId === companyId);
  const findings = Array.from(s.findings.values()).filter((f) => f.companyId === companyId);
  // Two stories per customer: vulnerability posture (CVE-based scan findings)
  // and attack-surface exposure (OSINT). The security-posture rollup is
  // vuln-based; exposure is counted alongside it, not blended in.
  const open = findings.filter((f) => isOpen(f) && isRemediationFinding(f));
  const openExposure = findings.filter((f) => isOpen(f) && isOsintFinding(f)).length;
  const inventoryAssets = Array.from(s.assets.values()).filter(
    (a) => a.companyId === companyId,
  ).length;
  const withInventory = open.filter(
    (f) => f.assetSource === "tidal" || f.assetSource === "manual",
  ).length;
  const composite = computeComposite(
    open,
    inventoryAssets > 0 ? companyCoverage(s, companyId) : null,
  );
  return {
    folderCount: Array.from(s.folders.values()).filter((f) => f.companyId === companyId)
      .length,
    scanCount: scans.length,
    activeScans: scans.filter(
      (sc) => sc.status === "Running" || sc.status === "Paused" || sc.status === "Queued",
    ).length,
    openFindings: open.length,
    exposureFindings: openExposure,
    criticalOpen: open.filter((f) => f.severity === "Critical").length,
    exposureScore: exposureOf(open),
    inventoryAssets,
    inventoryCoverage: open.length
      ? Math.round((withInventory / open.length) * 100)
      : -1,
    compositeScore: composite.score,
    compositeBand: composite.band,
  };
}

function toPublicCompany(s: StoreShape, c: InternalCompany): Company {
  return { ...c, ...companyRollup(s, c.id), isDemo: isDemoCompany(c) };
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
    // Our own organization (GMI) sorts first, then clients alphabetically.
    .sort(
      (a, b) =>
        (a.kind === "internal" ? 0 : 1) - (b.kind === "internal" ? 0 : 1) ||
        a.name.localeCompare(b.name),
    );
}

export function getCompany(id: string): Company | undefined {
  const s = store();
  tick(s);
  const c = s.companies.get(id);
  return c ? toPublicCompany(s, c) : undefined;
}

export function createCompany(input: {
  name: string;
  kind?: "internal" | "client";
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
    kind: input.kind ?? inferCompanyKind(name),
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
  markDirty();
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
  markDirty();
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
  markDirty();
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

// Company ids owning any inventory asset that matches one of the given
// strings. Lets importers detect when an asset string is ambiguous across
// customers (shared 10.x IPs, DESKTOP-XXXX) instead of trusting whichever
// asset an unscoped lookup happens to hit first.
function assetOwners(s: StoreShape, ...assetStrs: string[]): Set<string> {
  const keys = assetStrs.map((x) => (x ?? "").trim().toLowerCase()).filter(Boolean);
  const owners = new Set<string>();
  if (!keys.length) return owners;
  for (const a of s.assets.values()) {
    const ids = [a.identifier, a.hostname, ...a.ipAddresses]
      .filter(Boolean)
      .map((x) => x.toLowerCase());
    if (keys.some((k) => ids.includes(k))) owners.add(a.companyId);
  }
  return owners;
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
  markDirty();
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

// Wipe all data and repopulate purely from the real Nessus scanner. Used to
// clear demo/stub data and go live on real scan results. Inventory (Tidal /
// manual) is preserved unless clearInventory is set.
export async function resyncFromNessus(options?: {
  clearInventory?: boolean;
}): Promise<NessusImportResult | { error: string }> {
  await ensureHydrated();
  const s = store();
  // Back up the current state before wiping — if Nessus is unreachable the
  // import fails and we must restore instead of persisting an empty store.
  const backup = serializeStore(s);
  s.companies.clear();
  s.folders.clear();
  s.scans.clear();
  s.findings.clear();
  if (options?.clearInventory) s.assets.clear();
  markDirty();
  let result: NessusImportResult | { error: string };
  try {
    result = await importFromNessus();
  } catch (err) {
    result = { error: err instanceof Error ? err.message : "Nessus import failed." };
  }
  if ("error" in result) {
    globalStore.__vulnStore = deserializeStore(backup);
    markDirty();
    // Re-persist the restored state in case the interval flusher wrote the
    // wiped store while the import was in flight.
    await flushNow();
    return result;
  }
  await flushNow();
  return result;
}

// --- executive report (per-client board one-pager) -------------------------

// Single-loss-expectancy per finding by severity (order-of-magnitude, breach-
// cost flavored) and annual rate of occurrence driven by exploitation signal.
// ALE = SLE x ARO summed over open findings. Assumptions are shown on the page.
const SLE_BY_SEVERITY: Record<Severity, number> = {
  Critical: 250_000,
  High: 75_000,
  Medium: 15_000,
  Low: 2_000,
  Info: 0,
};

function annualRate(f: Finding): number {
  let p = 0.05;
  if (f.kev) p = 0.6;
  else if (f.exploitAvailable || f.epss >= 0.3) p = 0.3;
  if (f.assetExposure === "Internet-facing") p += 0.1;
  if (f.assetCriticality === "Crown Jewel") p += 0.1;
  return Math.min(0.9, p);
}

export type ExecReport = {
  generatedAt: string;
  company: { id: string; name: string; industry: string };
  posture: { compositeScore: number; compositeBand: string; exposureScore: number };
  findings: { open: number; critical: number; high: number; kevOpen: number };
  ssvc: { act: number; attend: number; overdue: number; kevOverdue: number };
  compliance: { framework: string; overall: string; score: number }[];
  attackSurface: {
    total: number;
    exposedAssets: number;
    leakedCredentials: number;
    webVulnerabilities: number;
  };
  financial: { ale: number };
  topRisks: {
    cve: string;
    title: string;
    asset: string;
    realRisk: number;
    decision: SsvcDecision;
    kev: boolean;
  }[];
};

export function computeExecReport(companyId: string): ExecReport | null {
  const s = store();
  tick(s);
  const company = s.companies.get(companyId);
  if (!company) return null;

  const metrics = computeMetrics({ companyId });
  const priorities = computePriorities({ companyId, limit: 5000 });
  const surface = computeAttackSurface({ companyId });
  const surfaceSummary = surface.summary;

  const open = Array.from(s.findings.values()).filter(
    (f) => f.companyId === companyId && isOpen(f),
  );
  const ale = Math.round(
    open.reduce((sum, f) => sum + SLE_BY_SEVERITY[f.severity] * annualRate(f), 0),
  );

  const compliance = FRAMEWORKS.map((fw) => {
    const p = computeCompliance({ companyId, framework: fw.id }).companies[0];
    return { framework: fw.name, overall: p?.overall ?? "Pass", score: p?.score ?? 100 };
  });

  return {
    generatedAt: "",
    company: { id: company.id, name: company.name, industry: company.industry },
    posture: {
      compositeScore: metrics.composite.score,
      compositeBand: metrics.composite.band,
      exposureScore: metrics.exposureScore,
    },
    findings: {
      open: metrics.totalOpen,
      critical: metrics.severityCounts.Critical,
      high: metrics.severityCounts.High,
      kevOpen: metrics.kevOpen,
    },
    ssvc: {
      act: priorities.summary.act,
      attend: priorities.summary.attend,
      overdue: priorities.summary.overdue,
      kevOverdue: priorities.summary.kevOverdue,
    },
    compliance,
    attackSurface: {
      total: surfaceSummary.total,
      exposedAssets: surfaceSummary.exposedAssets,
      leakedCredentials: surfaceSummary.byCategory["Leaked Credentials"],
      webVulnerabilities: surfaceSummary.byCategory["Web Vulnerabilities"],
    },
    financial: { ale },
    topRisks: priorities.items.slice(0, 5).map((i) => ({
      cve: i.cve,
      title: i.title,
      asset: i.asset,
      realRisk: i.realRisk,
      decision: i.decision,
      kev: i.kev,
    })),
  };
}

// Purge every demo/simulated scan and its findings. Only the demo engine
// (seed() and DEMO_SCANS runs) fabricates scans with no external linkage at
// all: no scanner binding (`vendor`), no import provenance (`externalRef`),
// and no bridge lifecycle (`bridgeScan`). Connector syncs that create
// synthetic scan records without those markers (Defender) are real data and
// must survive the purge. Real connector data and companies are untouched.
export async function purgeDemoData(): Promise<{
  scansRemoved: number;
  findingsRemoved: number;
}> {
  const s = store();
  const demoScanIds = new Set<string>();
  for (const [id, sc] of s.scans) {
    if (sc.vendor || sc.externalRef || sc.bridgeScan) continue;
    if (sc.connector === "defender") continue;
    demoScanIds.add(id);
  }
  let findingsRemoved = 0;
  for (const [fid, f] of s.findings) {
    if (demoScanIds.has(f.scanId)) {
      s.findings.delete(fid);
      findingsRemoved += 1;
    }
  }
  let scansRemoved = 0;
  for (const id of demoScanIds) {
    s.scans.delete(id);
    scansRemoved += 1;
  }
  await flushNow();
  return { scansRemoved, findingsRemoved };
}

// Refresh live threat intelligence and re-score every finding: pull the full
// CISA KEV catalog + live EPSS for all real CVEs, then recompute kev / epss /
// real-risk / SSVC inputs. This is the engine that makes prioritization real
// instead of running on the bundled baseline. Best-effort, never throws.
export async function enrichThreatIntel(): Promise<{
  kevAdded: number;
  cvesWithEpss: number;
  cvssFilled: number;
  ransomwareLinked: number;
  findingsUpdated: number;
  findingsScanned: number;
  realCveFindings: number;
}> {
  const s = store();
  const kevAdded = await refreshKevFromCisa();

  const cveRe = /^CVE-\d{4}-\d{4,}$/i;
  // Every CVE a finding covers (a scanner plugin often maps to several).
  const effectiveCves = (f: Finding): string[] => {
    const list = f.cves && f.cves.length ? f.cves : [f.cve];
    return Array.from(
      new Set(list.map((c) => c.toUpperCase()).filter((c) => cveRe.test(c))),
    );
  };

  const allCves = new Set<string>();
  const missingCvss: string[] = [];
  let realCveFindings = 0;
  for (const f of s.findings.values()) {
    const ec = effectiveCves(f);
    if (!ec.length) continue;
    realCveFindings += 1;
    for (const c of ec) allCves.add(c);
    if (!f.cvss || f.cvss <= 0) missingCvss.push(ec[0]);
  }

  // Open-source enrichment: EPSS (exploit probability) for every real CVE, and
  // NVD to fill in a CVSS base score where a finding arrived without one.
  const epss = await fetchEpss([...allCves]);
  const nvd = await fetchNvd(missingCvss);

  let findingsUpdated = 0;
  let findingsScanned = 0;
  let cvssFilled = 0;
  let ransomwareLinked = 0;
  for (const f of s.findings.values()) {
    findingsScanned += 1;
    const beforeKev = f.kev;
    const beforeEpss = f.epss;
    const beforeRisk = f.realRisk;
    const ec = effectiveCves(f);
    if (ec.length) {
      // Promote the displayed primary to a KEV (ransomware-preferred) CVE so
      // the KEV/ransomware signal isn't hidden behind CVE ordering.
      const promoted = ec.find(isKevRansomware) ?? ec.find(isKev) ?? ec[0];
      if (promoted && promoted !== f.cve.toUpperCase()) f.cve = promoted;
      // Worst-case EPSS across every CVE the finding covers.
      let bestEpss = 0;
      for (const c of ec) {
        const e = epss.get(c);
        if (e !== undefined && e > bestEpss) bestEpss = e;
      }
      f.epss = bestEpss;
      const n = nvd.get(f.cve.toUpperCase());
      if (n && n.cvss > 0 && (!f.cvss || f.cvss <= 0)) {
        f.cvss = n.cvss;
        if (!f.cvssV3) f.cvssV3 = n.cvss;
        cvssFilled += 1;
      }
    }
    rescoreFinding(s, f); // recomputes kev/ransomware + real-risk from refreshed intel
    if (f.ransomware) ransomwareLinked += 1;
    if (f.kev !== beforeKev || f.epss !== beforeEpss || f.realRisk !== beforeRisk) {
      findingsUpdated += 1;
    }
  }
  await flushNow();
  return {
    kevAdded,
    cvesWithEpss: epss.size,
    cvssFilled,
    ransomwareLinked,
    findingsUpdated,
    findingsScanned,
    realCveFindings,
  };
}

// --- attack surface (external OSINT posture: Artemis + SpiderFoot) ----------

export type SurfaceCategory =
  | "Exposed Services"
  | "Subdomains & DNS"
  | "Leaked Credentials"
  | "Web Vulnerabilities"
  | "Threat Intel"
  | "Info Disclosure";

export const SURFACE_CATEGORIES: SurfaceCategory[] = [
  "Exposed Services",
  "Subdomains & DNS",
  "Leaked Credentials",
  "Web Vulnerabilities",
  "Threat Intel",
  "Info Disclosure",
];

function emptySurfaceCounts(): Record<SurfaceCategory, number> {
  return {
    "Exposed Services": 0,
    "Subdomains & DNS": 0,
    "Leaked Credentials": 0,
    "Web Vulnerabilities": 0,
    "Threat Intel": 0,
    "Info Disclosure": 0,
  };
}

// Bucket an OSINT finding into an attack-surface category from its module/event
// (the part after "Artemis: " / "SpiderFoot: ") and CVE marker.
function surfaceCategoryOf(f: Finding): SurfaceCategory {
  const raw = (f.category.split(":").pop() || "").trim().toLowerCase();
  const cve = f.cve.toLowerCase();
  const has = (...keys: string[]) =>
    keys.some((k) => raw.includes(k) || cve.includes(k));
  if (has("leaksite", "compromise", "password", "hash", "bruter", "account_external", "breach"))
    return "Leaked Credentials";
  if (has("nuclei", "sql_injection", "lfi", "wp_scanner", "wordpress", "joomla", "drupal", "api_scanner", "directory_index", "admin_panel", "vulnerability"))
    return "Web Vulnerabilities";
  if (has("malicious", "blacklist", "shodan", "darknet", "defaced"))
    return "Threat Intel";
  if (has("port")) return "Exposed Services";
  if (has("subdomain", "dns", "dangling", "internet_name", "vhost", "domain_expiration"))
    return "Subdomains & DNS";
  return "Info Disclosure";
}

export type SurfaceItem = {
  id: string;
  companyId: string;
  companyName: string;
  asset: string;
  category: SurfaceCategory;
  rawCategory: string;
  severity: Severity;
  source: "artemis" | "spiderfoot";
  title: string;
  description: string;
  lastSeen: string;
};

export type CompanySurface = {
  companyId: string;
  companyName: string;
  total: number;
  exposedAssets: number;
  byCategory: Record<SurfaceCategory, number>;
  items: SurfaceItem[];
};

export type AttackSurfaceResult = {
  summary: {
    total: number;
    companies: number;
    exposedAssets: number;
    byCategory: Record<SurfaceCategory, number>;
    bySource: { artemis: number; spiderfoot: number };
  };
  companies: CompanySurface[];
};

// External attack-surface posture from the OSINT engines (Artemis + SpiderFoot),
// grouped per client and by category — deliberately separate from the CVE
// findings, because exposure is a different question than "which CVE".
export function computeAttackSurface(filter?: {
  companyId?: string;
}): AttackSurfaceResult {
  const s = store();
  tick(s);
  const osint = Array.from(s.findings.values()).filter(
    (f) =>
      (f.connector === "artemis" || f.connector === "spiderfoot") &&
      f.status !== "Resolved" &&
      (!filter?.companyId || f.companyId === filter.companyId),
  );

  const byCompanyId = new Map<string, SurfaceItem[]>();
  const summaryCounts = emptySurfaceCounts();
  const bySource = { artemis: 0, spiderfoot: 0 };

  for (const f of osint) {
    const category = surfaceCategoryOf(f);
    const item: SurfaceItem = {
      id: f.id,
      companyId: f.companyId,
      companyName: f.companyName,
      asset: f.asset,
      category,
      rawCategory: (f.category.split(":").pop() || f.category).trim(),
      severity: f.severity,
      source: f.connector === "spiderfoot" ? "spiderfoot" : "artemis",
      title: f.title,
      description: f.description,
      lastSeen: f.lastSeen,
    };
    if (!byCompanyId.has(f.companyId)) byCompanyId.set(f.companyId, []);
    byCompanyId.get(f.companyId)!.push(item);
    summaryCounts[category] += 1;
    bySource[item.source] += 1;
  }

  const SEV_RANK: Record<Severity, number> = {
    Critical: 4,
    High: 3,
    Medium: 2,
    Low: 1,
    Info: 0,
  };
  const companies: CompanySurface[] = Array.from(byCompanyId.entries())
    .map(([companyId, items]) => {
      const byCategory = emptySurfaceCounts();
      for (const it of items) byCategory[it.category] += 1;
      items.sort(
        (a, b) =>
          SEV_RANK[b.severity] - SEV_RANK[a.severity] ||
          a.category.localeCompare(b.category),
      );
      return {
        companyId,
        companyName: items[0]?.companyName ?? companyId,
        total: items.length,
        exposedAssets: new Set(items.map((i) => i.asset)).size,
        byCategory,
        items,
      };
    })
    .sort((a, b) => b.total - a.total);

  return {
    summary: {
      total: osint.length,
      companies: companies.length,
      exposedAssets: new Set(osint.map((f) => f.asset)).size,
      byCategory: summaryCounts,
      bySource,
    },
    companies,
  };
}

// When OSINT (Artemis/SpiderFoot) surfaces an exposed service or web weakness,
// auto-queue a targeted Nessus scan of that asset — turning an external signal
// into confirmed, authenticated CVE findings. Idempotent: skips assets a Nessus
// scan already targets, so re-runs don't pile up scans.
export type OsintPivotResult = {
  scansLaunched: number;
  assetsQueued: number;
  companies: number;
  skipped: number;
};

const PIVOT_CATEGORIES = new Set<SurfaceCategory>([
  "Exposed Services",
  "Web Vulnerabilities",
]);

export async function pivotOsintToNessus(filter?: {
  companyId?: string;
}): Promise<OsintPivotResult> {
  const s = store();
  const byCompany = new Map<string, Set<string>>();
  for (const f of s.findings.values()) {
    if (f.connector !== "artemis" && f.connector !== "spiderfoot") continue;
    if (f.status === "Resolved") continue;
    if (filter?.companyId && f.companyId !== filter.companyId) continue;
    if (!PIVOT_CATEGORIES.has(surfaceCategoryOf(f))) continue;
    const asset = (f.asset || "").trim().replace(/^https?:\/\//, "").split("/")[0];
    if (!asset || asset === "unknown" || !/^[a-z0-9.:_-]+$/i.test(asset)) continue;
    if (!byCompany.has(f.companyId)) byCompany.set(f.companyId, new Set());
    byCompany.get(f.companyId)!.add(asset);
  }

  let scansLaunched = 0;
  let assetsQueued = 0;
  let skipped = 0;
  for (const [companyId, assetSet] of byCompany) {
    if (!s.companies.get(companyId)) continue;
    const alreadyTargeted = new Set<string>();
    for (const sc of s.scans.values()) {
      if (sc.companyId === companyId && sc.connector === "nessus") {
        for (const t of sc.targets) alreadyTargeted.add(t.toLowerCase());
      }
    }
    const targets = Array.from(assetSet).filter(
      (a) => !alreadyTargeted.has(a.toLowerCase()),
    );
    skipped += assetSet.size - targets.length;
    if (targets.length === 0) continue;
    const folder = ensureFolder(s, companyId, "Exposure Confirm");
    const res = await startScan({
      name: "Confirm OSINT exposures (auto-pivot)",
      connector: "nessus",
      profile: "standard",
      targets,
      companyId,
      folderId: folder.id,
      requestedBy: "auto-pivot",
    });
    if (!("error" in res)) {
      scansLaunched += 1;
      assetsQueued += targets.length;
    }
  }
  await flushNow();
  return { scansLaunched, assetsQueued, companies: byCompany.size, skipped };
}

// --- analyst priority queue (SSVC + KEV remediation SLAs) -------------------

export type PriorityItem = {
  id: string;
  companyId: string;
  companyName: string;
  cve: string;
  title: string;
  asset: string;
  severity: Severity;
  realRisk: number;
  decision: SsvcDecision;
  slaDays: number;
  dueDate: string;
  overdue: boolean;
  daysLeft: number;
  reasons: string[];
  remediation: string;
  kev: boolean;
  ransomware: boolean;
};

export type PrioritiesResult = {
  summary: {
    totalOpen: number;
    act: number;
    attend: number;
    overdue: number;
    kevOverdue: number;
    dueThisWeek: number;
  };
  items: PriorityItem[];
};

const SSVC_ORDER: Record<SsvcDecision, number> = {
  Act: 0,
  Attend: 1,
  "Track*": 2,
  Track: 3,
};

// Rank every open finding by SSVC decision, then overdue, then real-risk — the
// single "work this top-down" queue. Analyst-simple surface; SSVC rigor beneath.
export function computePriorities(filter?: {
  companyId?: string;
  limit?: number;
}): PrioritiesResult {
  const s = store();
  tick(s);
  const now = Date.now();
  const open = Array.from(s.findings.values()).filter(
    (f) =>
      (f.status === "Open" || f.status === "In Remediation") &&
      isRemediationFinding(f) && // vuln + pentest are remediation items; OSINT lives in Attack Surface
      (!filter?.companyId || f.companyId === filter.companyId),
  );

  const items: PriorityItem[] = open.map((f) => {
    const r = ssvc(f);
    const d = dueInfo(f, r.slaDays, now);
    return {
      id: f.id,
      companyId: f.companyId,
      companyName: f.companyName,
      cve: f.cve,
      title: f.title,
      asset: f.asset,
      severity: f.severity,
      realRisk: f.realRisk,
      decision: r.decision,
      slaDays: r.slaDays,
      dueDate: d.dueDate,
      overdue: d.overdue,
      daysLeft: d.daysLeft,
      reasons: r.reasons,
      remediation: f.remediation,
      kev: f.kev,
      ransomware: f.ransomware,
    };
  });

  items.sort(
    (a, b) =>
      SSVC_ORDER[a.decision] - SSVC_ORDER[b.decision] ||
      Number(b.overdue) - Number(a.overdue) ||
      b.realRisk - a.realRisk ||
      a.daysLeft - b.daysLeft,
  );

  const summary = {
    totalOpen: items.length,
    act: items.filter((i) => i.decision === "Act").length,
    attend: items.filter((i) => i.decision === "Attend").length,
    overdue: items.filter((i) => i.overdue).length,
    kevOverdue: items.filter((i) => i.kev && i.overdue).length,
    dueThisWeek: items.filter((i) => !i.overdue && i.daysLeft <= 7).length,
  };

  return { summary, items: items.slice(0, filter?.limit ?? 100) };
}

// --- remediation SLA dashboard (burndown + MTTR per client) ----------------

export type SlaClientRow = {
  companyId: string;
  companyName: string;
  open: number;
  withinSla: number;
  dueSoon: number;
  breached: number;
  slaCompliance: number; // % of open findings still within their SLA window
  mttrDays: number | null;
  resolved30: number;
  worstBreachSeverity: Severity | null;
};

export type RemediationSlaResult = {
  overall: {
    open: number;
    withinSla: number;
    dueSoon: number;
    breached: number;
    slaCompliance: number;
    mttrDays: number | null;
    resolved30: number;
  };
  burndown: { date: string; open: number; resolved: number }[];
  slaPolicy: { severity: Severity; days: number }[];
  clients: SlaClientRow[];
};

export function computeRemediationSla(): RemediationSlaResult {
  const s = store();
  tick(s);
  const now = Date.now();
  const DAY = 86_400_000;
  // Exclude demo/test companies and OSINT findings — the SLA clock is a
  // vulnerability-remediation metric; attack-surface exposures live elsewhere.
  const demo = demoCompanyIds(s);
  const all = Array.from(s.findings.values()).filter(
    (f) => !demo.has(f.companyId) && isRemediationFinding(f),
  );

  // 30-day burndown: open backlog vs resolved-per-day.
  const burndown: { date: string; open: number; resolved: number }[] = [];
  for (let d = 29; d >= 0; d--) {
    const dayEnd = now - d * DAY;
    const date = new Date(dayEnd).toISOString().slice(0, 10);
    const open = all.filter(
      (f) =>
        new Date(f.firstSeen).getTime() <= dayEnd &&
        !(f.resolvedAt && new Date(f.resolvedAt).getTime() <= dayEnd),
    ).length;
    const resolved = all.filter(
      (f) =>
        f.resolvedAt &&
        new Date(f.resolvedAt).getTime() > dayEnd - DAY &&
        new Date(f.resolvedAt).getTime() <= dayEnd,
    ).length;
    burndown.push({ date, open, resolved });
  }

  const SEV_RANK: Record<Severity, number> = {
    Critical: 4,
    High: 3,
    Medium: 2,
    Low: 1,
    Info: 0,
  };

  const byCompany = new Map<string, Finding[]>();
  for (const f of all) {
    if (!byCompany.has(f.companyId)) byCompany.set(f.companyId, []);
    byCompany.get(f.companyId)!.push(f);
  }

  let oOpen = 0, oWithin = 0, oDue = 0, oBreach = 0, oResolved30 = 0;
  const oMttr: number[] = [];
  const clients: SlaClientRow[] = [];

  for (const [companyId, list] of byCompany) {
    const company = s.companies.get(companyId);
    if (!company) continue;
    let within = 0, due = 0, breach = 0;
    let worst: Severity | null = null;
    for (const f of list.filter(isOpen)) {
      const age = (now - new Date(f.firstSeen).getTime()) / DAY;
      const sla = SLA_DAYS[f.severity];
      if (age > sla) {
        breach += 1;
        if (!worst || SEV_RANK[f.severity] > SEV_RANK[worst]) worst = f.severity;
      } else if (age > sla - 7) due += 1;
      else within += 1;
    }
    const open = within + due + breach;
    const remediated = list.filter((f) => f.status === "Resolved" && f.resolvedAt);
    const times = remediated.map(
      (f) => (new Date(f.resolvedAt!).getTime() - new Date(f.firstSeen).getTime()) / DAY,
    );
    const mttrDays = times.length
      ? Math.round(times.reduce((a, b) => a + b, 0) / times.length)
      : null;
    const resolved30 = remediated.filter(
      (f) => (now - new Date(f.resolvedAt!).getTime()) / DAY <= 30,
    ).length;
    const slaCompliance = open ? Math.round((100 * (open - breach)) / open) : 100;

    clients.push({
      companyId,
      companyName: company.name,
      open,
      withinSla: within,
      dueSoon: due,
      breached: breach,
      slaCompliance,
      mttrDays,
      resolved30,
      worstBreachSeverity: worst,
    });

    oOpen += open;
    oWithin += within;
    oDue += due;
    oBreach += breach;
    oResolved30 += resolved30;
    for (const t of times) oMttr.push(t);
  }

  clients.sort((a, b) => b.breached - a.breached || b.open - a.open);

  return {
    overall: {
      open: oOpen,
      withinSla: oWithin,
      dueSoon: oDue,
      breached: oBreach,
      slaCompliance: oOpen ? Math.round((100 * (oOpen - oBreach)) / oOpen) : 100,
      mttrDays: oMttr.length
        ? Math.round(oMttr.reduce((a, b) => a + b, 0) / oMttr.length)
        : null,
      resolved30: oResolved30,
    },
    burndown,
    slaPolicy: (Object.keys(SLA_DAYS) as Severity[]).map((severity) => ({
      severity,
      days: SLA_DAYS[severity],
    })),
    clients,
  };
}

// --- compliance (PCI DSS 4.0) ----------------------------------------------

function cvssOf(f: Finding): number {
  return f.cvssV3 || f.cvssV2 || f.cvss || 0;
}

// Evaluate PCI DSS 4.0 vulnerability-management posture per company.
export function computeCompliance(filter?: {
  companyId?: string;
  framework?: string;
}): ComplianceResult {
  const s = store();
  tick(s);
  const now = Date.now();
  const DAY = 86_400_000;

  // Exclude demo/test companies from the all-company rollup; still allow an
  // explicit single-company lookup (e.g. showing the demo customer itself).
  const demo = demoCompanyIds(s);
  const companies = Array.from(s.companies.values()).filter((c) =>
    filter?.companyId ? c.id === filter.companyId : !demo.has(c.id),
  );

  const postures: CompliancePosture[] = companies.map((company) => {
    const open = Array.from(s.findings.values()).filter(
      (f) =>
        f.companyId === company.id &&
        (f.status === "Open" || f.status === "In Remediation"),
    );
    // External ASV: internet-facing findings with CVSS >= 4.0 fail an ASV scan.
    const external = open.filter((f) => f.assetExposure === "Internet-facing");
    const asvFailing = external.filter((f) => cvssOf(f) >= 4.0);
    const asvPass = asvFailing.length === 0;

    const internalHighCrit = open.filter(
      (f) => f.severity === "Critical" || f.severity === "High",
    );
    // PCI patch window: critical/high remediated within ~1 month.
    const slaBreaches = internalHighCrit.filter(
      (f) => (now - new Date(f.firstSeen).getTime()) / DAY > 30,
    );

    const companyScans = Array.from(s.scans.values()).filter(
      (sc) => sc.companyId === company.id && sc.completedAt,
    );
    const lastScanDaysAgo = companyScans.length
      ? Math.floor(
          Math.min(
            ...companyScans.map(
              (sc) => (now - new Date(sc.completedAt!).getTime()) / DAY,
            ),
          ),
        )
      : null;
    const scanOverdue = lastScanDaysAgo === null || lastScanDaysAgo > 90;

    const signals: ComplianceSignals = {
      openTotal: open.length,
      criticalOpen: open.filter((f) => f.severity === "Critical").length,
      highCritOpen: internalHighCrit.length,
      externalFailing: asvFailing.length,
      slaBreaches30: slaBreaches.length,
      slaBreachesMed90: open.filter(
        (f) =>
          f.severity === "Medium" &&
          (now - new Date(f.firstSeen).getTime()) / DAY > 90,
      ).length,
      kevOpen: open.filter((f) => isKev(f.cve)).length,
      lastScanDaysAgo,
      scanOverdue30: lastScanDaysAgo === null || lastScanDaysAgo > 30,
      scanOverdue90: scanOverdue,
    };

    const evald = evaluateFramework(signals, filter?.framework ?? "pci");

    return {
      framework: evald.framework.name,
      companyId: company.id,
      companyName: company.name,
      overall: evald.overall,
      score: evald.score,
      asvPass,
      failingFindings: asvFailing.length,
      lastScanDaysAgo,
      requirements: evald.requirements,
      summary: {
        externalFailing: asvFailing.length,
        internalHighCrit: internalHighCrit.length,
        slaBreaches: slaBreaches.length,
        openTotal: open.length,
      },
    };
  });

  postures.sort((a, b) => a.score - b.score);
  const passing = postures.filter((p) => p.overall === "Pass").length;
  const failing = postures.filter((p) => p.overall === "Fail").length;

  return {
    framework:
      (FRAMEWORKS.find((f) => f.id === (filter?.framework ?? "pci")) ?? FRAMEWORKS[0]).name,
    aggregate: {
      companies: postures.length,
      passing,
      failing,
      avgScore: postures.length
        ? Math.round(postures.reduce((sum, p) => sum + p.score, 0) / postures.length)
        : 0,
      asvFailingCompanies: postures.filter((p) => !p.asvPass).length,
    },
    companies: postures,
  };
}

export type GrcExportResult = {
  pushed: number;
  created: number;
  updated: number;
  companies: number;
  errors: string[];
};

// Push per-company vulnerability risk into the GRC (OpenGRC) as risk records,
// for audit and compliance. One consolidated risk per company.
export async function exportToGrc(filter?: {
  companyId?: string;
}): Promise<GrcExportResult | { error: string }> {
  if (!grcConfig()) {
    return {
      error: "GRC is not configured. Set GRC_API_URL and GRC_API_TOKEN.",
    };
  }
  const compliance = computeCompliance(filter);
  const demo = demoCompanyIds(store());
  let pushed = 0;
  let created = 0;
  let updated = 0;
  const errors: string[] = [];

  for (const posture of compliance.companies) {
    // Never push demo/test companies to GRC.
    if (demo.has(posture.companyId)) continue;
    const metrics = computeMetrics({ companyId: posture.companyId });
    // Evaluate every framework for this company so the GRC record carries
    // control-level compliance evidence, not just an aggregate risk number.
    const frameworks = FRAMEWORKS.map((fw) => {
      const p = computeCompliance({
        companyId: posture.companyId,
        framework: fw.id,
      }).companies[0];
      return {
        name: fw.name,
        score: p?.score ?? 0,
        overall: p?.overall ?? "Pass",
        failing: (p?.requirements ?? [])
          .filter((r) => r.status === "Fail" || r.status === "At Risk")
          .map((r) => ({ id: r.id, title: r.title, detail: r.detail })),
      };
    });
    const top = listFindings({ companyId: posture.companyId })
      .filter((f) => f.status === "Open" || f.status === "In Remediation")
      .slice(0, 10)
      .map((f) => ({
        cve: f.cve,
        title: f.title,
        asset: f.asset,
        realRisk: f.realRisk,
      }));
    const risk = buildRisk({
      companyName: posture.companyName,
      compositeScore: metrics.composite.score,
      openTotal: posture.summary.openTotal,
      criticalOpen: metrics.severityCounts.Critical,
      kevOpen: metrics.kevOpen,
      asvFailing: posture.summary.externalFailing,
      overall: posture.overall,
      topFindings: top,
      frameworks,
    });
    try {
      const res = await grcUpsertRisk(risk);
      pushed += 1;
      if (res.created) created += 1;
      else updated += 1;
    } catch (err) {
      errors.push(
        `${posture.companyName}: ${err instanceof Error ? err.message : "failed"}`,
      );
    }
  }

  return { pushed, created, updated, companies: compliance.companies.length, errors };
}

// Maps our framework ids to the OpenGRC standard NAMES that actually have their
// controls loaded (verified via the probe). Only these get a structured push;
// the control ids our engine evaluates match these standards' control codes 1:1.
const GRC_STANDARD_BY_FRAMEWORK: Record<string, string> = {
  "nist-800-53": "NIST SP 800-53 Security Baseline (Low)",
  cmmc: "CMMC Level 2",
};

const GRC_EFFECTIVENESS: Record<string, string> = {
  Pass: "Effective",
  Info: "Effective",
  "At Risk": "Partially Effective",
  Fail: "Not Effective",
};
const GRC_IMPL_STATUS: Record<string, string> = {
  Pass: "Implemented",
  Info: "Implemented",
  "At Risk": "Partially Implemented",
  Fail: "Not Implemented",
};

export type GrcAssessment = {
  generatedAt: string;
  companies: {
    company: string;
    riskCode: string;
    controls: {
      standard: string;
      code: string;
      title: string;
      effectiveness: string;
      status: string;
      evidence: string;
    }[];
  }[];
};

// Emit the per-company, per-control compliance assessment mapped onto OpenGRC's
// control codes + Effectiveness / ImplementationStatus enums. Consumed by the
// server-side OpenGRC sync (which owns the pivot writes). No timestamps stamped
// here — the route stamps generatedAt.
export function grcAssessment(): GrcAssessment {
  const s = store();
  const demo = demoCompanyIds(s);
  const clients = Array.from(s.companies.values()).filter(
    (c) => c.kind === "client" && !demo.has(c.id),
  );
  const companies = clients.map((company) => {
    const controls: GrcAssessment["companies"][number]["controls"] = [];
    for (const [fwId, standard] of Object.entries(GRC_STANDARD_BY_FRAMEWORK)) {
      const posture = computeCompliance({
        companyId: company.id,
        framework: fwId,
      }).companies[0];
      if (!posture) continue;
      for (const r of posture.requirements) {
        controls.push({
          standard,
          code: r.id,
          title: r.title,
          effectiveness: GRC_EFFECTIVENESS[r.status] ?? "Not Assessed",
          status: GRC_IMPL_STATUS[r.status] ?? "Unknown",
          evidence: `${r.id} ${r.title} — ${r.status}: ${r.detail}`,
        });
      }
    }
    return { company: company.name, riskCode: riskCode(company.name), controls };
  });
  return { generatedAt: "", companies };
}

// --- attack paths / blast radius -------------------------------------------

const CRIT_WEIGHT: Record<string, number> = {
  "Crown Jewel": 4,
  High: 3,
  Normal: 2,
  Low: 1,
};

type AttackNode = {
  asset: string;
  companyId: string;
  companyName: string;
  exposure: string;
  criticality: string;
  worstRisk: number;
  kev: boolean;
  exploitable: boolean;
  open: number;
  subnet: string | null; // /24 when the asset resolves to an IP
  topCve: string | null;
  topTitle: string | null;
};

function subnetOf(text: string, ips: string[]): string | null {
  const candidates = [text, ...ips];
  for (const c of candidates) {
    const m = c.match(/\b(\d{1,3}\.\d{1,3}\.\d{1,3})\.\d{1,3}\b/);
    if (m) return m[1];
  }
  return null;
}

// Model how far an attacker gets after compromising an internet-facing,
// exploitable asset. Reachability is MODELED, not observed: same-/24 subnet
// (a real signal from IPs) plus perimeter->high-value-target pivots. Connect
// firewall/identity data later for true topology.
export function computeAttackPaths(filter?: {
  companyId?: string;
}): AttackPathResult {
  const s = store();
  tick(s);

  // Build one node per asset from open findings, enriched with inventory.
  const nodes = new Map<string, AttackNode>();
  const keyOf = (companyId: string, asset: string) =>
    `${companyId}|${asset.trim().toLowerCase()}`;

  for (const f of s.findings.values()) {
    if (filter?.companyId && f.companyId !== filter.companyId) continue;
    if (f.status !== "Open" && f.status !== "In Remediation") continue;
    const key = keyOf(f.companyId, f.asset);
    const node =
      nodes.get(key) ??
      ({
        asset: f.asset,
        companyId: f.companyId,
        companyName: f.companyName,
        exposure: f.assetExposure,
        criticality: f.assetCriticality,
        worstRisk: 0,
        kev: false,
        exploitable: false,
        open: 0,
        subnet: subnetOf(f.asset, []),
        topCve: null,
        topTitle: null,
      } as AttackNode);
    if (f.realRisk > node.worstRisk) {
      node.worstRisk = f.realRisk;
      node.topCve = f.cve;
      node.topTitle = f.title;
    }
    node.kev = node.kev || f.kev;
    node.exploitable = node.exploitable || f.exploitAvailable;
    node.open += 1;
    nodes.set(key, node);
  }

  // Inventory assets (incl. those with no findings) enrich context + add
  // crown-jewel targets that haven't been scanned yet.
  for (const a of s.assets.values()) {
    if (filter?.companyId && a.companyId !== filter.companyId) continue;
    const key = keyOf(a.companyId, a.identifier);
    const existing = nodes.get(key);
    if (existing) {
      existing.exposure = a.exposure;
      existing.criticality = a.criticality;
      existing.subnet = existing.subnet ?? subnetOf(a.identifier, a.ipAddresses);
    } else {
      nodes.set(key, {
        asset: a.identifier,
        companyId: a.companyId,
        companyName: a.companyName,
        exposure: a.exposure,
        criticality: a.criticality,
        worstRisk: 0,
        kev: false,
        exploitable: false,
        open: 0,
        subnet: subnetOf(a.identifier, a.ipAddresses),
        topCve: null,
        topTitle: null,
      });
    }
  }

  const all = Array.from(nodes.values());
  const byCompany = new Map<string, AttackNode[]>();
  for (const n of all) {
    const list = byCompany.get(n.companyId) ?? [];
    list.push(n);
    byCompany.set(n.companyId, list);
  }

  // --- reachability graph -------------------------------------------------
  // Edges model lateral movement and perimeter pivots WITHOUT observed
  // topology (connect firewall/identity data later for the real thing):
  //   - Lateral: hosts in the same /24 subnet can reach each other.
  //   - Perimeter breach: an internet-facing host lands on a BEACHHEAD in each
  //     internal subnet (the highest-risk non-crown host — attackers land on a
  //     foothold, not straight on the crown jewel), then move laterally to the
  //     crown from there. This yields realistic multi-hop chains.
  // Isolated assets are unreachable (segmented off).
  const MAX_HOPS = 6;
  const subnetGroups = new Map<string, AttackNode[]>();
  const internalBySubnet = new Map<string, AttackNode[]>();
  for (const n of all) {
    if (n.subnet) {
      const k = `${n.companyId}|${n.subnet}`;
      (subnetGroups.get(k) ?? subnetGroups.set(k, []).get(k)!).push(n);
      if (n.exposure === "Internal") {
        (internalBySubnet.get(k) ?? internalBySubnet.set(k, []).get(k)!).push(n);
      }
    }
  }
  // One beachhead per internal subnet: prefer a non-crown foothold, highest
  // risk; fall back to the sole host if the subnet is crown-only.
  const beachheadsByCompany = new Map<string, AttackNode[]>();
  for (const [k, list] of internalBySubnet) {
    const nonCrown = list.filter((n) => n.criticality !== "Crown Jewel");
    const pool = nonCrown.length ? nonCrown : list;
    const bh = pool.slice().sort((a, b) => b.worstRisk - a.worstRisk)[0];
    if (!bh) continue;
    const cid = k.split("|")[0];
    (beachheadsByCompany.get(cid) ?? beachheadsByCompany.set(cid, []).get(cid)!).push(bh);
  }

  function neighborsOf(node: AttackNode): { node: AttackNode; via: string }[] {
    const out: { node: AttackNode; via: string }[] = [];
    if (node.subnet) {
      for (const peer of subnetGroups.get(`${node.companyId}|${node.subnet}`) ?? []) {
        if (peer !== node && peer.exposure !== "Isolated") {
          out.push({ node: peer, via: `lateral · ${node.subnet}.0/24` });
        }
      }
    }
    if (node.exposure === "Internet-facing") {
      for (const bh of beachheadsByCompany.get(node.companyId) ?? []) {
        if (bh !== node && bh.subnet !== node.subnet) {
          out.push({ node: bh, via: "perimeter breach → internal" });
        }
      }
    }
    return out;
  }

  // BFS shortest paths (in hops) from an entry across the reachability graph.
  type Came = Map<AttackNode, { prev: AttackNode | null; via: string | null }>;
  function shortestPaths(entry: AttackNode): Came {
    const came: Came = new Map();
    const depth = new Map<AttackNode, number>();
    came.set(entry, { prev: null, via: null });
    depth.set(entry, 0);
    const queue: AttackNode[] = [entry];
    let guard = 0;
    while (queue.length && guard < 20000) {
      guard += 1;
      const cur = queue.shift()!;
      const d = depth.get(cur)!;
      if (d >= MAX_HOPS) continue;
      for (const { node, via } of neighborsOf(cur)) {
        if (came.has(node)) continue;
        came.set(node, { prev: cur, via });
        depth.set(node, d + 1);
        queue.push(node);
      }
    }
    return came;
  }

  const hopFor = (n: AttackNode, role: AttackHop["role"], via: string | null): AttackHop => ({
    asset: n.asset,
    exposure: n.exposure,
    criticality: n.criticality,
    role,
    cve: n.topCve,
    title: n.topTitle,
    realRisk: n.worstRisk,
    kev: n.kev,
    via,
    reachableOnly: n.open === 0,
  });

  // Candidate entries: internet-facing and either exploitable or high-risk.
  // Pre-rank and cap how many we BFS from, so a big estate stays fast.
  const candidates = all
    .filter(
      (n) =>
        n.exposure === "Internet-facing" &&
        (n.kev || n.exploitable || n.worstRisk >= 50),
    )
    .sort((a, b) => b.worstRisk * (b.kev ? 1.2 : 1) - a.worstRisk * (a.kev ? 1.2 : 1))
    .slice(0, 60);

  const entries: AttackEntry[] = [];
  const crownJewelsAtRisk = new Set<string>();

  for (const entry of candidates) {
    const came: Came = shortestPaths(entry);
    const reached = Array.from(came.keys()).filter((n) => n !== entry);
    const crownJewels = reached.filter((n) => n.criticality === "Crown Jewel");
    const highs = reached.filter((n) => n.criticality === "High");
    for (const cj of crownJewels) crownJewelsAtRisk.add(keyOf(cj.companyId, cj.asset));

    // Objective = the highest-value reachable asset (crown jewel first), then
    // by risk, then by the shortest chain to get there.
    const chainLen = (n: AttackNode) => {
      let len = 0;
      let cur: AttackNode | null = n;
      while (cur && came.get(cur)?.prev) {
        len += 1;
        cur = came.get(cur)!.prev;
      }
      return len;
    };
    const target =
      reached.sort(
        (a, b) =>
          CRIT_WEIGHT[b.criticality] - CRIT_WEIGHT[a.criticality] ||
          b.worstRisk - a.worstRisk ||
          chainLen(a) - chainLen(b),
      )[0] ?? null;

    // Reconstruct the full multi-hop chain entry -> ... -> target.
    const path: AttackHop[] = [];
    if (target) {
      const stack: { node: AttackNode; via: string | null }[] = [];
      let cur: AttackNode | null = target;
      while (cur) {
        const info: { prev: AttackNode | null; via: string | null } = came.get(cur)!;
        stack.push({ node: cur, via: info.via });
        cur = info.prev;
      }
      stack.reverse();
      stack.forEach((step, i) => {
        const role: AttackHop["role"] =
          i === 0 ? "entry" : i === stack.length - 1 ? "target" : "pivot";
        path.push(hopFor(step.node, role, step.via));
      });
    } else {
      path.push(hopFor(entry, "entry", null));
    }

    const hops = Math.max(0, path.length - 1);
    // Blast: value reached, weighted toward shorter (easier) chains.
    const proximity = target ? Math.max(0.4, 1 - (chainLen(target) - 1) * 0.12) : 0;
    const blastScore = Math.min(
      100,
      Math.round(
        (crownJewels.length * 22 + highs.length * 7 + reached.length * 1.2) * (0.6 + 0.4 * proximity),
      ),
    );
    const entryScore = Math.min(100, Math.round(entry.worstRisk * (entry.kev ? 1.15 : 1)));

    entries.push({
      id: keyOf(entry.companyId, entry.asset),
      asset: entry.asset,
      companyId: entry.companyId,
      companyName: entry.companyName,
      exposure: entry.exposure,
      criticality: entry.criticality,
      entryScore,
      kev: entry.kev,
      exploitable: entry.exploitable,
      reachable: reached.length,
      crownJewelsReached: crownJewels.length,
      blastScore,
      path,
      hops,
      targetAsset: target?.asset ?? null,
      targetCriticality: target?.criticality ?? null,
    });
  }

  entries.sort((a, b) => b.blastScore - a.blastScore || b.entryScore - a.entryScore);

  return {
    summary: {
      entryPoints: entries.length,
      crownJewelsAtRisk: crownJewelsAtRisk.size,
      maxBlast: entries[0]?.blastScore ?? 0,
    },
    entries: entries.slice(0, 20),
  };
}

// Recompute a finding's environmental context + real risk against the current
// inventory. Used after an inventory sync so existing findings reprice.
function rescoreFinding(s: StoreShape, f: Finding): void {
  markDirty();
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
    markDirty();
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
export type SpiderfootImportResult = {
  scansImported: number;
  findingsImported: number;
  companiesMatched: number;
  skipped: { scan: string; reason: string }[];
};

// Normalize a string to lowercase alphanumeric tokens (length >= 3) for fuzzy
// company matching.
function nameTokens(text: string): Set<string> {
  return new Set(
    text
      .toLowerCase()
      .replace(/https?:\/\//g, "")
      .split(/[^a-z0-9]+/)
      .filter((t) => t.length >= 3 && t !== "com" && t !== "www" && t !== "net"),
  );
}

// Resolve a SpiderFoot scan to an existing company by token overlap between the
// scan name/target and the company name. Returns null if nothing matches — we
// never auto-create companies from OSINT scans to avoid polluting the roster.
function matchCompanyForScan(
  s: StoreShape,
  scanName: string,
  scanTarget: string,
): string | null {
  const scanToks = nameTokens(`${scanName} ${scanTarget}`);
  if (scanToks.size === 0) return null;
  let best: { id: string; score: number } | null = null;
  for (const company of s.companies.values()) {
    const compToks = nameTokens(company.name);
    let score = 0;
    for (const t of compToks) {
      if (scanToks.has(t)) score += 1;
      else if ([...scanToks].some((x) => x.includes(t) || t.includes(x))) score += 1;
    }
    if (score > 0 && (!best || score > best.score)) best = { id: company.id, score };
  }
  return best?.id ?? null;
}

// Resolve a company by name (case-insensitive exact, then substring either way).
function resolveCompanyByName(s: StoreShape, name: string): string | null {
  const n = name.trim().toLowerCase();
  if (!n) return null;
  const exact = Array.from(s.companies.values()).find(
    (c) => c.name.toLowerCase() === n,
  );
  if (exact) return exact.id;
  const partial = Array.from(s.companies.values()).find(
    (c) => c.name.toLowerCase().includes(n) || n.includes(c.name.toLowerCase()),
  );
  return partial?.id ?? null;
}

// Explicit Artemis-tag -> company routing for tags whose label doesn't overlap
// the company name (e.g. the SONAR product scans of internal infrastructure).
const ARTEMIS_TAG_COMPANY: { pattern: RegExp; company: string }[] = [
  { pattern: /^sonar/i, company: "GMI Scans" },
];

// Pull finished SpiderFoot scans in as findings, grouped under the matching
// company. Pull-based (SpiderFoot runs scans in its own UI); no live polling.
export async function importFromSpiderfoot(): Promise<
  SpiderfootImportResult | { error: string }
> {
  if (!spiderfootConfig()) {
    return {
      error:
        "SpiderFoot is not configured. Set SPIDERFOOT_URL (and SPIDERFOOT_USER / SPIDERFOOT_PASS if it requires auth) to import.",
    };
  }
  const s = store();

  let scans: Awaited<ReturnType<typeof spiderfootListScans>>;
  try {
    scans = await spiderfootListScans();
  } catch (err) {
    return {
      error: err instanceof Error ? err.message : "Failed to reach SpiderFoot.",
    };
  }

  const skipped: { scan: string; reason: string }[] = [];
  const matchedCompanies = new Set<string>();
  let scansImported = 0;
  let findingsImported = 0;

  for (const sf of scans) {
    const label = sf.name || sf.target || sf.id;
    if (!/finish|done|complete/i.test(sf.status)) {
      skipped.push({ scan: label, reason: `status ${sf.status}` });
      continue;
    }
    // Skip scans already imported (scan record tagged with the SpiderFoot id).
    const already = Array.from(s.scans.values()).some(
      (sc) => sc.externalRef === `spiderfoot:${sf.id}`,
    );
    if (already) {
      skipped.push({ scan: label, reason: "already imported" });
      continue;
    }
    const companyId = matchCompanyForScan(s, sf.name, sf.target);
    if (!companyId) {
      skipped.push({ scan: label, reason: "no matching company" });
      continue;
    }

    let imported: Awaited<ReturnType<typeof spiderfootImportFindings>>;
    try {
      imported = await spiderfootImportFindings(sf.id);
    } catch (err) {
      skipped.push({
        scan: label,
        reason: err instanceof Error ? err.message : "results fetch failed",
      });
      continue;
    }

    const company = s.companies.get(companyId)!;
    const folder = ensureFolder(s, companyId, "SpiderFoot");
    const nowIso = new Date().toISOString();
    const scanId = nextId(s, "SCAN");
    const scan: InternalScan = {
      id: scanId,
      name: sf.name || `SpiderFoot ${sf.id}`,
      companyId: company.id,
      companyName: company.name,
      folderId: folder.id,
      folderName: folder.name,
      connector: "spiderfoot",
      profile: "imported",
      targets: sf.target ? [sf.target] : [],
      status: "Completed",
      createdAt: nowIso,
      startedAt: nowIso,
      completedAt: nowIso,
      findingsCount: 0,
      severityCounts: emptySeverityCounts(),
      hostsScanned: 0,
      requestedBy: "imported@spiderfoot",
      durationMs: 1,
      progressFrozenAt: 100,
      seed: hashSeed(scanId + sf.id),
      vendor: null,
      externalRef: `spiderfoot:${sf.id}`,
    };
    s.scans.set(scanId, scan);
    scansImported += 1;
    matchedCompanies.add(companyId);

    for (const item of imported) {
      const dedupeKey = `${scan.companyId}::${item.cve}::${item.asset}::${item.title}`;
      const existing = Array.from(s.findings.values()).find(
        (f) =>
          `${f.companyId}::${f.cve}::${f.asset}::${f.title}` === dedupeKey &&
          f.status !== "Resolved",
      );
      if (existing) {
        existing.lastSeen = nowIso;
        continue;
      }
      s.findings.set(`VLN-${(s.counter += 1)}`, {
        id: `VLN-${s.counter}`,
        scanId: scan.id,
        companyId: scan.companyId,
        companyName: scan.companyName,
        connector: "spiderfoot",
        cve: item.cve,
        title: item.title,
        severity: item.severity,
        cvss: item.cvss,
        cvssV3: item.cvss,
        cvssV2: 0,
        vpr: 0,
        epss: 0,
        asset: item.asset,
        port: "N/A",
        category: item.category,
        description: item.description,
        remediation:
          "Review the SpiderFoot event detail and remediate the exposed asset or disclosed vulnerability.",
        status: "Open",
        assignee: null,
        firstSeen: nowIso,
        lastSeen: nowIso,
        resolvedAt: null,
        exploitAvailable: false,
        ...riskFields(s, {
          cve: item.cve,
          cvss: item.cvss,
          epss: 0,
          exploitAvailable: false,
          asset: item.asset,
          companyId: scan.companyId,
        }),
      });
    }

    const all = Array.from(s.findings.values()).filter((f) => f.scanId === scan.id);
    scan.findingsCount = all.length;
    const counts = emptySeverityCounts();
    for (const f of all) counts[f.severity] += 1;
    scan.severityCounts = counts;
    scan.hostsScanned = new Set(all.map((f) => f.asset)).size || scan.targets.length;
    findingsImported += all.length;
  }

  await flushNow();
  if (s.settings.autoScanNewAssets) {
    try {
      await pivotOsintToNessus();
    } catch {
      // best-effort
    }
  }
  return {
    scansImported,
    findingsImported,
    companiesMatched: matchedCompanies.size,
    skipped,
  };
}

export type BurpImportResult = {
  findingsImported: number;
  companiesMatched: number;
  skipped: number;
};

// Core Burp inserter shared by the API pull and the XML upload. Each issue's
// host is matched to a customer; matched issues become pentest-class findings
// under a per-company "Burp" scan. Unmatched hosts are skipped (counted).
export function importBurpFindings(items: BurpFinding[]): BurpImportResult {
  const s = store();
  markDirty(); // callers (XML upload) may not flush explicitly
  const nowIso = new Date().toISOString();
  const matched = new Set<string>();
  let findingsImported = 0;
  let skipped = 0;
  const scanByCompany = new Map<string, InternalScan>();

  for (const item of items) {
    const companyId = matchCompanyForScan(s, item.asset, item.path);
    if (!companyId) {
      skipped += 1;
      continue;
    }
    let scan = scanByCompany.get(companyId);
    if (!scan) {
      const company = s.companies.get(companyId)!;
      const folder = ensureFolder(s, companyId, "Burp");
      const scanId = nextId(s, "SCAN");
      scan = {
        id: scanId,
        name: `Burp Pentest — ${company.name}`,
        companyId: company.id,
        companyName: company.name,
        folderId: folder.id,
        folderName: folder.name,
        connector: "burp",
        profile: "imported",
        targets: [item.asset],
        status: "Completed",
        createdAt: nowIso,
        startedAt: nowIso,
        completedAt: nowIso,
        findingsCount: 0,
        severityCounts: emptySeverityCounts(),
        hostsScanned: 0,
        requestedBy: "imported@burp",
        durationMs: 1,
        progressFrozenAt: 100,
        seed: hashSeed(scanId),
        vendor: null,
        externalRef: `burp:${company.id}`,
      };
      s.scans.set(scanId, scan);
      scanByCompany.set(companyId, scan);
    }
    matched.add(companyId);

    // Findings store item.port (path only lives in the description), so the
    // key must be built from port too — a path-based key never matches and
    // every re-import would duplicate all findings.
    const dedupeKey = `${scan.companyId}::${item.cve}::${item.asset}::${item.port}::${item.title}`;
    const existing = Array.from(s.findings.values()).find(
      (f) =>
        `${f.companyId}::${f.cve}::${f.asset}::${f.port}::${f.title}` === dedupeKey &&
        f.status !== "Resolved",
    );
    if (existing) {
      existing.lastSeen = nowIso;
      continue;
    }
    s.findings.set(`VLN-${(s.counter += 1)}`, {
      id: `VLN-${s.counter}`,
      scanId: scan.id,
      companyId: scan.companyId,
      companyName: scan.companyName,
      connector: "burp",
      cve: item.cve,
      title: item.title,
      severity: item.severity,
      cvss: item.cvss,
      cvssV3: item.cvss,
      cvssV2: 0,
      vpr: 0,
      epss: 0,
      asset: item.asset,
      port: item.port,
      category: item.category,
      description: `${item.description}\n\nPath: ${item.path} · Confidence: ${item.confidence}`,
      remediation: item.remediation,
      status: "Open",
      assignee: null,
      firstSeen: nowIso,
      lastSeen: nowIso,
      resolvedAt: null,
      exploitAvailable: true, // a Burp-validated issue is a demonstrated exploit
      ...riskFields(s, {
        cve: item.cve,
        cvss: item.cvss,
        epss: 0,
        exploitAvailable: true,
        asset: item.asset,
        companyId: scan.companyId,
      }),
    });
    findingsImported += 1;
  }

  for (const scan of scanByCompany.values()) {
    const all = Array.from(s.findings.values()).filter((f) => f.scanId === scan.id);
    scan.findingsCount = all.length;
    const counts = emptySeverityCounts();
    for (const f of all) counts[f.severity] += 1;
    scan.severityCounts = counts;
    scan.hostsScanned = new Set(all.map((f) => f.asset)).size;
  }

  return { findingsImported, companiesMatched: matched.size, skipped };
}

// Live pull from Burp Suite Enterprise (GraphQL). CSV/XML upload uses
// importBurpFindings(parseBurpXml(...)) directly from the upload route.
export async function importFromBurp(): Promise<BurpImportResult | { error: string }> {
  if (!burpConfig()) {
    return {
      error:
        "Burp is not configured. Set BURP_API_URL and BURP_API_KEY (Burp Suite Enterprise) to pull issues, or upload a Burp Professional XML export.",
    };
  }
  let items: BurpFinding[];
  try {
    items = await burpListIssues();
  } catch (err) {
    return { error: err instanceof Error ? err.message : "Failed to reach Burp." };
  }
  const result = importBurpFindings(items);
  await flushNow();
  return result;
}

// --- Nmap discovery ---------------------------------------------------------

export type NmapImportResult = {
  hostsProcessed: number;
  assetsUpdated: number; // inventory assets that gained ground-truth port facts
  findingsImported: number; // exposed-service findings
  companiesMatched: number;
  skipped: number; // hosts that matched no customer
};

// Ingest Nmap discovery results: attach ground-truth open ports to the matching
// inventory asset (creating a discovered asset when none exists), and emit the
// narrow set of exposed-service findings. Ports/services feed the attack-path
// model; findings are limited to genuinely risky reachable services.
export function importNmapScan(hosts: NmapHost[]): NmapImportResult {
  const s = store();
  markDirty(); // callers (XML upload) may not flush explicitly
  const nowIso = new Date().toISOString();
  const matched = new Set<string>();
  let hostsProcessed = 0;
  let assetsUpdated = 0;
  let findingsImported = 0;
  let skipped = 0;
  const scanByCompany = new Map<string, InternalScan>();

  for (const host of hosts) {
    const identifier = host.host || host.ip;
    if (!identifier) continue;
    // Match by an existing asset first (keeps customer attribution honest) —
    // but only when every inventory match agrees on one owner; asset strings
    // shared across customers are inconclusive. Then fall back to fuzzy
    // name/host matching, and scope the asset lookup to the resolved company
    // so inventory context is never borrowed cross-tenant.
    const owners = assetOwners(s, host.host, host.ip);
    const companyId =
      owners.size === 1
        ? owners.values().next().value!
        : matchCompanyForScan(s, host.host, host.ip);
    if (!companyId) {
      skipped += 1;
      continue;
    }
    const existingAsset =
      lookupAsset(s, host.host, companyId) ?? lookupAsset(s, host.ip, companyId);
    matched.add(companyId);
    hostsProcessed += 1;
    const company = s.companies.get(companyId)!;

    // Attach ground-truth port facts to the asset (upsert when absent). We do
    // NOT flip exposure here — an internal-vantage scan seeing open ports does
    // not imply Internet-facing. That upgrade belongs to an external-scope
    // runner and can be layered in when the runner reports vantage.
    const priorExisting = Boolean(existingAsset);
    const asset = upsertAsset(s, {
      identifier: existingAsset?.identifier ?? identifier,
      hostname: existingAsset?.hostname ?? (host.host !== host.ip ? host.host : ""),
      ipAddresses:
        existingAsset?.ipAddresses?.length
          ? Array.from(new Set([...existingAsset.ipAddresses, host.ip].filter(Boolean)))
          : [host.ip].filter(Boolean),
      companyId: company.id,
      companyName: company.name,
      exposure: existingAsset?.exposure ?? classifyAsset(identifier).exposure,
      criticality: existingAsset?.criticality ?? classifyAsset(identifier).criticality,
      os: host.os || existingAsset?.os || "",
      owner: existingAsset?.owner ?? "",
      tags: existingAsset?.tags ?? [],
      source: existingAsset?.source ?? "nmap",
      externalId: existingAsset?.externalId ?? "",
    });
    asset.openPorts = host.ports;
    if (priorExisting || host.ports.length) assetsUpdated += 1;

    // Emit findings only for risky exposed services.
    const services = nmapServiceFindings(host);
    if (!services.length) continue;

    let scan = scanByCompany.get(companyId);
    if (!scan) {
      const folder = ensureFolder(s, companyId, "Nmap");
      const scanId = nextId(s, "SCAN");
      scan = {
        id: scanId,
        name: `Nmap Discovery — ${company.name}`,
        companyId: company.id,
        companyName: company.name,
        folderId: folder.id,
        folderName: folder.name,
        connector: "nmap",
        profile: "discovery",
        targets: [identifier],
        status: "Completed",
        createdAt: nowIso,
        startedAt: nowIso,
        completedAt: nowIso,
        findingsCount: 0,
        severityCounts: emptySeverityCounts(),
        hostsScanned: 0,
        requestedBy: "imported@nmap",
        durationMs: 1,
        progressFrozenAt: 100,
        seed: hashSeed(scanId),
        vendor: null,
        externalRef: `nmap:${company.id}`,
      };
      s.scans.set(scanId, scan);
      scanByCompany.set(companyId, scan);
    }

    for (const svc of services) {
      const dedupeKey = `${scan.companyId}::${svc.cve}::${svc.asset}::${svc.port}`;
      const existing = Array.from(s.findings.values()).find(
        (f) =>
          `${f.companyId}::${f.cve}::${f.asset}::${f.port}` === dedupeKey &&
          f.status !== "Resolved",
      );
      if (existing) {
        existing.lastSeen = nowIso;
        continue;
      }
      s.findings.set(`VLN-${(s.counter += 1)}`, {
        id: `VLN-${s.counter}`,
        scanId: scan.id,
        companyId: scan.companyId,
        companyName: scan.companyName,
        connector: "nmap",
        cve: svc.cve,
        title: svc.title,
        severity: svc.severity,
        cvss: svc.cvss,
        cvssV3: svc.cvss,
        cvssV2: 0,
        vpr: 0,
        epss: 0,
        asset: svc.asset,
        port: svc.port,
        category: svc.category,
        description: svc.description,
        remediation: svc.remediation,
        status: "Open",
        assignee: null,
        firstSeen: nowIso,
        lastSeen: nowIso,
        resolvedAt: null,
        exploitAvailable: false,
        ...riskFields(s, {
          cve: svc.cve,
          cvss: svc.cvss,
          epss: 0,
          exploitAvailable: false,
          asset: svc.asset,
          companyId: scan.companyId,
        }),
      });
      findingsImported += 1;
    }
  }

  for (const scan of scanByCompany.values()) {
    const all = Array.from(s.findings.values()).filter((f) => f.scanId === scan.id);
    scan.findingsCount = all.length;
    const counts = emptySeverityCounts();
    for (const f of all) counts[f.severity] += 1;
    scan.severityCounts = counts;
    scan.hostsScanned = new Set(all.map((f) => f.asset)).size;
  }

  return { hostsProcessed, assetsUpdated, findingsImported, companiesMatched: matched.size, skipped };
}

// Live pull from an Nmap scan-runner. XML upload uses importNmapScan(
// parseNmapXml(...)) directly from the upload route.
export async function importFromNmap(): Promise<NmapImportResult | { error: string }> {
  if (!nmapConfig()) {
    return {
      error:
        "Nmap runner is not configured. Set NMAP_RUNNER_URL and NMAP_RUNNER_TOKEN to pull scan results, or upload an nmap -oX XML export.",
    };
  }
  let hosts: NmapHost[];
  try {
    hosts = await nmapListHosts();
  } catch (err) {
    return { error: err instanceof Error ? err.message : "Failed to reach the Nmap runner." };
  }
  const result = importNmapScan(hosts);
  await flushNow();
  return result;
}

// --- Vulners CVE enrichment --------------------------------------------------

export type VulnersImportResult = {
  cvesEnriched: number;
  findingsUpdated: number;
  exploitsFound: number;
};

// Enrich every CVE-tagged finding in the store with Vulners intelligence:
// EPSS probability, exploit availability, and CVSS backfill. Does not replace
// existing scores — only fills gaps or improves where Vulners has higher signal.
export async function importFromVulners(): Promise<VulnersImportResult | { error: string }> {
  if (!vulnersConfig()) {
    return {
      error:
        "Vulners is not configured. Set VULNERS_API_KEY (and optionally VULNERS_URL for a self-hosted instance).",
    };
  }
  const s = store();
  const cveRe = /^CVE-\d{4}-\d{4,}$/i;

  // Collect all unique CVEs from current findings.
  const allCves = new Set<string>();
  for (const f of s.findings.values()) {
    const cves = f.cves?.length ? f.cves : [f.cve];
    for (const c of cves) {
      if (cveRe.test(c)) allCves.add(c.toUpperCase());
    }
  }

  if (!allCves.size) {
    return { cvesEnriched: 0, findingsUpdated: 0, exploitsFound: 0 };
  }

  let enriched: Map<string, VulnersCveData>;
  try {
    enriched = await vulnersEnrichCves([...allCves]);
  } catch (err) {
    return { error: err instanceof Error ? err.message : "Vulners enrichment failed." };
  }

  let findingsUpdated = 0;
  let exploitsFound = 0;

  for (const f of s.findings.values()) {
    const cves = f.cves?.length ? f.cves : [f.cve];
    let best: VulnersCveData | undefined;
    let bestExploit = false;

    for (const c of cves) {
      const d = enriched.get(c.toUpperCase());
      if (!d) continue;
      if (!best || d.cvss > best.cvss) best = d;
      if (d.exploitAvailable) bestExploit = true;
    }

    if (!best) continue;

    let changed = false;
    if (best.epss > 0 && (!f.epss || best.epss > f.epss)) {
      f.epss = best.epss;
      changed = true;
    }
    if (best.cvss > 0 && (!f.cvss || f.cvss <= 0)) {
      f.cvss = best.cvss;
      if (!f.cvssV3) f.cvssV3 = best.cvss;
      changed = true;
    }
    if (bestExploit && !f.exploitAvailable) {
      f.exploitAvailable = true;
      changed = true;
    }
    if (best.description && !f.description) {
      f.description = best.description;
      changed = true;
    }
    if (changed) {
      rescoreFinding(s, f);
      findingsUpdated += 1;
    }
    if (bestExploit) exploitsFound += 1;
  }

  await flushNow();
  return { cvesEnriched: enriched.size, findingsUpdated, exploitsFound };
}

// --- Vulners Bridge (nmap active scanner) ------------------------------------

export type VulnersBridgeImportResult = {
  hostsScanned: number;
  findingsImported: number;
  skipped: number;
};

// Scan each known asset IP via the Vulners bridge (nmap --script vulners -sV).
// Findings are attributed to the same company as the asset.
export async function importFromVulnersBridge(): Promise<
  VulnersBridgeImportResult | { error: string }
> {
  if (!vulnersBridgeConfig()) {
    return {
      error:
        "Vulners bridge is not configured. Set VULNERS_BRIDGE_URL and VULNERS_BRIDGE_PASS.",
    };
  }
  const s = store();
  const nowIso = new Date().toISOString();
  let hostsScanned = 0;
  let findingsImported = 0;
  let skipped = 0;
  const scanByCompany = new Map<string, InternalScan>();

  // Collect unique IPs from asset inventory — scan each once.
  const targets = new Map<string, { companyId: string; companyName: string; asset: InternalAsset }>();
  for (const asset of s.assets.values()) {
    for (const ip of asset.ipAddresses ?? []) {
      if (!ip || targets.has(ip)) continue;
      targets.set(ip, {
        companyId: asset.companyId,
        companyName: asset.companyName,
        asset,
      });
    }
  }

  for (const [ip, { companyId, companyName, asset }] of Array.from(targets.entries())) {
    let results: VulnersBridgeFinding[];
    try {
      results = await vulnersBridgeScanHost(ip);
    } catch {
      skipped += 1;
      continue;
    }
    if (!results.length) { hostsScanned += 1; continue; }
    hostsScanned += 1;

    let scan = scanByCompany.get(companyId);
    if (!scan) {
      const folder = ensureFolder(s, companyId, "Vulners Bridge");
      const scanId = nextId(s, "SCAN");
      scan = {
        id: scanId,
        name: `Vulners Bridge — ${companyName}`,
        companyId,
        companyName,
        folderId: folder.id,
        folderName: folder.name,
        connector: "vulners",
        profile: "standard",
        targets: [ip],
        status: "Completed",
        createdAt: nowIso,
        startedAt: nowIso,
        completedAt: nowIso,
        findingsCount: 0,
        severityCounts: emptySeverityCounts(),
        hostsScanned: 0,
        requestedBy: "imported@vulners-bridge",
        durationMs: 1,
        progressFrozenAt: 100,
        seed: hashSeed(scanId),
        vendor: null,
        externalRef: `vulners-bridge:${companyId}`,
      };
      s.scans.set(scanId, scan);
      scanByCompany.set(companyId, scan);
    }

    for (const v of results) {
      // Company-scoped, and only non-Resolved findings match — a re-detected
      // CVE that was Resolved is a regression and must surface as a new Open
      // finding (same behavior as the other importers).
      const existing = Array.from(s.findings.values()).find(
        (f) =>
          f.companyId === companyId &&
          f.cve === v.cve &&
          (f.asset === ip || f.asset === asset.hostname) &&
          f.status !== "Resolved",
      );
      if (existing) {
        if (v.exploitAvailable && !existing.exploitAvailable) {
          existing.exploitAvailable = true;
          rescoreFinding(s, existing);
        }
        existing.lastSeen = nowIso;
        continue;
      }
      const severity = v.cvss >= 9 ? "Critical" : v.cvss >= 7 ? "High" : v.cvss >= 4 ? "Medium" : v.cvss > 0 ? "Low" : "Info";
      const fid = nextId(s, "FIND");
      const f: Finding = {
        id: fid,
        scanId: scan.id,
        companyId,
        companyName,
        connector: "vulners",
        cve: v.cve,
        title: `${v.cve} — ${v.component}`,
        severity: severity as Finding["severity"],
        cvss: v.cvss,
        cvssV2: 0,
        cvssV3: v.cvss,
        vpr: 0,
        epss: 0,
        asset: asset.hostname || ip,
        port: v.component.match(/Port (\d+)/)?.[1] ?? "",
        category: "Network Service",
        description: `${v.cve} detected on ${v.component} at ${ip}`,
        remediation: `Patch or mitigate ${v.component} — see ${v.cve} for details.`,
        status: "Open",
        assignee: null,
        firstSeen: nowIso,
        lastSeen: nowIso,
        resolvedAt: null,
        exploitAvailable: v.exploitAvailable,
        kev: false,
        ransomware: false,
        assetExposure: asset.exposure ?? "Internal",
        assetCriticality: asset.criticality ?? "Normal",
        assetSource: "nmap",
        realRisk: 0,
        riskPriority: "Info",
      };
      rescoreFinding(s, f);
      s.findings.set(fid, f);
      scan.findingsCount += 1;
      scan.severityCounts[f.severity] = (scan.severityCounts[f.severity] ?? 0) + 1;
      scan.hostsScanned += 1;
      findingsImported += 1;
    }
  }

  await flushNow();
  return { hostsScanned, findingsImported, skipped };
}

export type ArtemisImportResult = {
  findingsImported: number;
  tagsProcessed: number;
  companiesMatched: number;
  skipped: { tag: string; reason: string }[];
};

// Shared hosting / cloud domains that aren't a customer's own attack surface —
// deriving OSINT scan targets from these would scan the provider, not the
// client, so they're excluded.
const SHARED_HOST_SUFFIXES = [
  "amazonaws.com",
  "cloudfront.net",
  "elasticbeanstalk.com",
  "azurewebsites.net",
  "azure.com",
  "windows.net",
  "cloudapp.net",
  "googleusercontent.com",
  "appspot.com",
  "run.app",
  "herokuapp.com",
  "herokudns.com",
  "sucuri.net",
  "akamaiedge.net",
  "akamai.net",
  "fastly.net",
  "cloudflare.net",
  "cloudflare.com",
  "digitaloceanspaces.com",
  "netlify.app",
  "vercel.app",
  "github.io",
  "wpengine.com",
];

// Multi-label public suffixes we must keep two labels of (foo.co.uk not co.uk).
const MULTI_LABEL_TLDS = new Set([
  "co.uk", "org.uk", "gov.uk", "ac.uk", "com.au", "net.au", "org.au",
  "co.nz", "co.za", "com.br", "com.mx", "co.in", "co.jp", "com.sg",
]);

const IP_RE = /^\d{1,3}(\.\d{1,3}){3}$/;

// Reduce a hostname to its registrable (eTLD+1) domain, or null if it's an IP
// or a shared-hosting domain we shouldn't scan as the customer's surface.
export function registrableDomain(host: string): string | null {
  const h = host.trim().toLowerCase().replace(/^\*\./, "").replace(/\.$/, "");
  if (!h || IP_RE.test(h) || !h.includes(".")) return null;
  if (SHARED_HOST_SUFFIXES.some((suf) => h === suf || h.endsWith(`.${suf}`))) {
    return null;
  }
  const labels = h.split(".");
  const last2 = labels.slice(-2).join(".");
  const domain =
    labels.length >= 3 && MULTI_LABEL_TLDS.has(last2)
      ? labels.slice(-3).join(".")
      : last2;
  if (SHARED_HOST_SUFFIXES.some((suf) => domain === suf || domain.endsWith(`.${suf}`))) {
    return null;
  }
  return domain;
}

// Derive the set of root domains to run OSINT scans against for a company,
// from its findings' assets and any inventory assets.
export function osintTargetsForCompany(s: StoreShape, companyId: string): string[] {
  const domains = new Set<string>();
  for (const f of s.findings.values()) {
    if (f.companyId !== companyId) continue;
    const d = registrableDomain(f.asset);
    if (d) domains.add(d);
  }
  for (const a of s.assets.values()) {
    if (a.companyId !== companyId) continue;
    const d = registrableDomain(a.hostname || a.identifier || "");
    if (d) domains.add(d);
  }
  return Array.from(domains).sort();
}

export type SyncAllEntry = {
  connector: string;
  configured: boolean;
  ok: boolean;
  result?: unknown;
  error?: string;
};

// One-shot: pull results from every *configured* connector, so an analyst can
// bring the whole console up to date with a single click. Unconfigured
// connectors are reported (configured:false) rather than errored.
export async function syncAllConnectors(): Promise<SyncAllEntry[]> {
  const jobs: {
    connector: string;
    ready: boolean;
    run: () => Promise<any>;
  }[] = [
    { connector: "Nessus", ready: Boolean(nessusConfig()), run: importFromNessus },
    // CrowdStrike: fire background jobs (avoids DO 120s gateway timeout).
    // Results appear on the next manual sync or page refresh.
    {
      connector: "CrowdStrike Devices",
      ready: Boolean(falconConfig()),
      run: async () => {
        const r = startCsDevicesSync();
        if (!r.started) return { error: r.error ?? "Could not start sync." };
        return { message: "Sync started in background." };
      },
    },
    {
      connector: "CrowdStrike Spotlight",
      ready: Boolean(falconConfig()),
      run: async () => {
        const r = startCsSpotlightSync();
        if (!r.started) return { error: r.error ?? "Could not start sync." };
        return { message: "Sync started in background." };
      },
    },
    { connector: "Defender", ready: Boolean(defenderConfig()), run: importFromDefender },
    { connector: "Tidal", ready: Boolean(tidalConfig()), run: importFromTidal },
    { connector: "Intune", ready: Boolean(intuneConfig()), run: importFromIntune },
    { connector: "SpiderFoot", ready: Boolean(spiderfootConfig()), run: importFromSpiderfoot },
    { connector: "Artemis", ready: Boolean(artemisConfig()), run: importFromArtemis },
    { connector: "Burp", ready: Boolean(burpConfig()), run: importFromBurp },
    { connector: "Nmap", ready: Boolean(nmapConfig()), run: importFromNmap },
    { connector: "Vulners Enrichment", ready: Boolean(vulnersConfig()), run: importFromVulners },
    { connector: "Vulners Bridge", ready: Boolean(vulnersBridgeConfig()), run: importFromVulnersBridge },
  ];

  const out: SyncAllEntry[] = [];
  for (const job of jobs) {
    if (!job.ready) {
      out.push({ connector: job.connector, configured: false, ok: false });
      continue;
    }
    try {
      const r = await job.run();
      if (r && typeof r === "object" && "error" in r) {
        out.push({ connector: job.connector, configured: true, ok: false, error: (r as any).error });
      } else {
        out.push({ connector: job.connector, configured: true, ok: true, result: r });
      }
    } catch (err) {
      out.push({
        connector: job.connector,
        configured: true,
        ok: false,
        error: err instanceof Error ? err.message : "sync failed",
      });
    }
  }
  return out;
}

export type OsintPreview = {
  companies: number;
  domainsTotal: number;
  perCompany: { company: string; domains: string[] }[];
};

// Show exactly which customers and root domains a quarterly OSINT sweep would
// target — without launching anything.
export function previewOsintTargets(): OsintPreview {
  const s = store();
  const perCompany: { company: string; domains: string[] }[] = [];
  let domainsTotal = 0;
  for (const company of s.companies.values()) {
    if (company.kind !== "client") continue;
    const domains = osintTargetsForCompany(s, company.id);
    if (domains.length === 0) continue;
    perCompany.push({ company: company.name, domains });
    domainsTotal += domains.length;
  }
  perCompany.sort((a, b) => a.company.localeCompare(b.company));
  return { companies: perCompany.length, domainsTotal, perCompany };
}

export type OsintLaunchResult = {
  companies: number;
  domainsTotal: number;
  artemis: { configured: boolean; launched: number; failed: number };
  spiderfoot: { configured: boolean; launched: number; failed: number };
  perCompany: { company: string; domains: string[] }[];
  errors: string[];
};

// Launch supplemental OSINT / attack-surface scans (Artemis + SpiderFoot only —
// not Nessus) for every client company, against that company's derived root
// domains. Tagged/named by company so the results route back on import.
export async function launchOsintScans(): Promise<OsintLaunchResult> {
  const s = store();
  const artemisReady = Boolean(artemisConfig());
  const sfReady = Boolean(spiderfootConfig());
  const sfUsecase = process.env.SPIDERFOOT_USECASE || "Footprint";

  const result: OsintLaunchResult = {
    companies: 0,
    domainsTotal: 0,
    artemis: { configured: artemisReady, launched: 0, failed: 0 },
    spiderfoot: { configured: sfReady, launched: 0, failed: 0 },
    perCompany: [],
    errors: [],
  };
  if (!artemisReady && !sfReady) {
    result.errors.push(
      "Neither Artemis nor SpiderFoot is configured — set their env vars first.",
    );
    return result;
  }

  const clients = Array.from(s.companies.values()).filter(
    (c) => c.kind === "client",
  );
  for (const company of clients) {
    const domains = osintTargetsForCompany(s, company.id);
    if (domains.length === 0) continue;
    result.companies += 1;
    result.domainsTotal += domains.length;
    result.perCompany.push({ company: company.name, domains });

    // Artemis: one batch add for all of the company's domains, tagged by name.
    if (artemisReady) {
      try {
        await artemisAddTargets(domains, company.name);
        result.artemis.launched += 1;
      } catch (err) {
        result.artemis.failed += 1;
        result.errors.push(
          `Artemis (${company.name}): ${err instanceof Error ? err.message : "add failed"}`,
        );
      }
    }

    // SpiderFoot: one scan per domain, named by company so import maps back.
    if (sfReady) {
      for (const domain of domains) {
        try {
          await spiderfootStartScan(`${company.name} — ${domain}`, domain, sfUsecase);
          result.spiderfoot.launched += 1;
        } catch (err) {
          result.spiderfoot.failed += 1;
          result.errors.push(
            `SpiderFoot (${company.name}/${domain}): ${err instanceof Error ? err.message : "start failed"}`,
          );
        }
      }
    }
  }
  await flushNow();
  return result;
}

// Pull Artemis "interesting" task results in as findings, grouped by tag ->
// company. Reuses one scan record per tag (idempotent via externalRef) so
// re-importing refreshes rather than duplicates.
export async function importFromArtemis(): Promise<
  ArtemisImportResult | { error: string }
> {
  if (!artemisConfig()) {
    return {
      error:
        "Artemis is not configured. Set ARTEMIS_API_URL and ARTEMIS_API_TOKEN to import.",
    };
  }
  const s = store();

  let mapped: ArtemisFinding[];
  try {
    mapped = await artemisImportFindings();
  } catch (err) {
    return {
      error: err instanceof Error ? err.message : "Failed to reach Artemis.",
    };
  }

  // Group findings by Artemis tag (their per-client label).
  const byTag = new Map<string, ArtemisFinding[]>();
  for (const f of mapped) {
    const tag = f.tag || "untagged";
    if (!byTag.has(tag)) byTag.set(tag, []);
    byTag.get(tag)!.push(f);
  }

  const skipped: { tag: string; reason: string }[] = [];
  const matchedCompanies = new Set<string>();
  let findingsImported = 0;
  let tagsProcessed = 0;
  const nowIso = new Date().toISOString();

  for (const [tag, items] of byTag) {
    // Resolution order: explicit tag->company alias, then token overlap on the
    // tag, then on the first asset.
    const alias = ARTEMIS_TAG_COMPANY.find((a) => a.pattern.test(tag));
    const companyId =
      (alias ? resolveCompanyByName(s, alias.company) : null) ??
      matchCompanyForScan(s, tag, "") ??
      matchCompanyForScan(s, "", items[0]?.asset ?? "");
    if (!companyId) {
      skipped.push({ tag, reason: "no matching company" });
      continue;
    }
    const company = s.companies.get(companyId)!;
    const folder = ensureFolder(s, companyId, "Artemis");
    const externalRef = `artemis:${tag}`;

    let scan = Array.from(s.scans.values()).find((sc) => sc.externalRef === externalRef);
    if (!scan) {
      const scanId = nextId(s, "SCAN");
      scan = {
        id: scanId,
        name: `Artemis — ${tag}`,
        companyId: company.id,
        companyName: company.name,
        folderId: folder.id,
        folderName: folder.name,
        connector: "artemis",
        profile: "imported",
        targets: [],
        status: "Completed",
        createdAt: nowIso,
        startedAt: nowIso,
        completedAt: nowIso,
        findingsCount: 0,
        severityCounts: emptySeverityCounts(),
        hostsScanned: 0,
        requestedBy: "imported@artemis",
        durationMs: 1,
        progressFrozenAt: 100,
        seed: hashSeed(scanId + tag),
        vendor: null,
        externalRef,
      };
      s.scans.set(scanId, scan);
    } else {
      scan.completedAt = nowIso;
    }
    tagsProcessed += 1;
    matchedCompanies.add(companyId);

    for (const item of items) {
      const dedupeKey = `${scan.companyId}::${item.cve}::${item.asset}::${item.title}`;
      const existing = Array.from(s.findings.values()).find(
        (f) =>
          `${f.companyId}::${f.cve}::${f.asset}::${f.title}` === dedupeKey &&
          f.status !== "Resolved",
      );
      if (existing) {
        existing.lastSeen = nowIso;
        continue;
      }
      s.findings.set(`VLN-${(s.counter += 1)}`, {
        id: `VLN-${s.counter}`,
        scanId: scan.id,
        companyId: scan.companyId,
        companyName: scan.companyName,
        connector: "artemis",
        cve: item.cve,
        title: item.title,
        severity: item.severity,
        cvss: item.cvss,
        cvssV3: item.cvss,
        cvssV2: 0,
        vpr: 0,
        epss: 0,
        asset: item.asset,
        port: "N/A",
        category: item.category,
        description: item.description,
        remediation:
          "Review the Artemis task result for this target and remediate the reported exposure.",
        status: "Open",
        assignee: null,
        firstSeen: nowIso,
        lastSeen: nowIso,
        resolvedAt: null,
        exploitAvailable: false,
        ...riskFields(s, {
          cve: item.cve,
          cvss: item.cvss,
          epss: 0,
          exploitAvailable: false,
          asset: item.asset,
          companyId: scan.companyId,
        }),
      });
    }

    const all = Array.from(s.findings.values()).filter((f) => f.scanId === scan.id);
    scan.findingsCount = all.length;
    const counts = emptySeverityCounts();
    for (const f of all) counts[f.severity] += 1;
    scan.severityCounts = counts;
    scan.hostsScanned = new Set(all.map((f) => f.asset)).size || 0;
    findingsImported += all.length;
  }

  await flushNow();
  if (s.settings.autoScanNewAssets) {
    try {
      await pivotOsintToNessus();
    } catch {
      // best-effort: never fail the import because the pivot scan failed
    }
  }
  return {
    findingsImported,
    tagsProcessed,
    companiesMatched: matchedCompanies.size,
    skipped,
  };
}

// Core inventory loader shared by the CSV import and the (legacy) API sync.
// Maps each asset's customer to a company (match by name, create if missing),
// upserts the asset, then reprices every finding so real risk reflects the
// authoritative environment. Assets come from a Tidal CSV export or the API.
export async function importTidalInventory(
  assets: TidalAsset[],
): Promise<TidalImportResult> {
  const s = store();

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

  await flushNow();
  return { companiesCreated, assetsUpserted, findingsRescored, autoScan };
}

// Live sync: sign in to Tidal with email + password and pull the inventory
// straight from the portal API. CSV upload remains as an offline fallback.
export async function importFromTidal(
  onProgress?: (p: TidalProgress) => void,
): Promise<TidalImportResult | { error: string }> {
  if (!tidalConfig()) {
    return {
      error:
        "Tidal is not configured. Set TIDAL_EMAIL and TIDAL_PASSWORD to sign in and pull the live inventory (or upload a CSV export).",
    };
  }
  let assets;
  try {
    assets = await tidalListAssets(onProgress);
  } catch (err) {
    return {
      error: err instanceof Error ? err.message : "Failed to reach the Tidal API.",
    };
  }
  return importTidalInventory(assets);
}

// --- Background Tidal sync with pollable progress ---------------------------
// The live sync spans ~49 client companies and can pull thousands of devices,
// so it runs as a background job. The UI starts it (POST) and polls its status
// (GET). Progress lives in module scope — one sync at a time.
export type TidalSyncStatus = {
  running: boolean;
  phase: string;
  companiesTotal: number;
  companiesDone: number;
  currentCompany: string;
  assetsFound: number;
  startedAt: number;
  finishedAt: number | null;
  result: TidalImportResult | null;
  error: string | null;
};

let tidalSync: TidalSyncStatus = {
  running: false,
  phase: "idle",
  companiesTotal: 0,
  companiesDone: 0,
  currentCompany: "",
  assetsFound: 0,
  startedAt: 0,
  finishedAt: null,
  result: null,
  error: null,
};

export function getTidalSyncStatus(): TidalSyncStatus {
  return tidalSync;
}

// Kick off the background sync. Returns immediately; poll getTidalSyncStatus().
export function startTidalSync(): { started: boolean; error?: string } {
  if (!tidalConfig()) {
    return {
      started: false,
      error:
        "Tidal is not configured. Set TIDAL_EMAIL and TIDAL_PASSWORD to sign in and pull the live inventory (or upload a CSV export).",
    };
  }
  if (tidalSync.running) return { started: false, error: "A Tidal sync is already running." };

  tidalSync = {
    running: true,
    phase: "Starting",
    companiesTotal: 0,
    companiesDone: 0,
    currentCompany: "",
    assetsFound: 0,
    startedAt: Date.now(),
    finishedAt: null,
    result: null,
    error: null,
  };

  // Fire-and-forget: the DO app is a persistent Node server, so the async
  // continues running after the POST response returns.
  void (async () => {
    try {
      const result = await importFromTidal((p) => {
        tidalSync = { ...tidalSync, ...p };
      });
      if ("error" in result) {
        tidalSync = { ...tidalSync, running: false, phase: "Error", error: result.error, finishedAt: Date.now() };
      } else {
        tidalSync = {
          ...tidalSync,
          running: false,
          phase: "Done",
          currentCompany: "",
          result,
          finishedAt: Date.now(),
        };
      }
    } catch (err) {
      tidalSync = {
        ...tidalSync,
        running: false,
        phase: "Error",
        error: err instanceof Error ? err.message : "Tidal sync failed.",
        finishedAt: Date.now(),
      };
    }
  })();

  return { started: true };
}

// --- CrowdStrike background sync state --------------------------------------

export type CsSyncStatus = {
  running: boolean;
  phase: string;
  startedAt: number;
  finishedAt: number | null;
  result: unknown;
  error: string | null;
};

const csIdleState = (): CsSyncStatus => ({
  running: false,
  phase: "idle",
  startedAt: 0,
  finishedAt: null,
  result: null,
  error: null,
});

let csDevicesSync: CsSyncStatus = csIdleState();
let csSpotlightSync: CsSyncStatus = csIdleState();

export function getCsDevicesSyncStatus(): CsSyncStatus { return csDevicesSync; }
export function getCsSpotlightSyncStatus(): CsSyncStatus { return csSpotlightSync; }

export function startCsDevicesSync(): { started: boolean; error?: string } {
  if (!falconConfig()) return { started: false, error: "CrowdStrike is not configured." };
  if (csDevicesSync.running) return { started: false, error: "Devices sync already running." };
  csDevicesSync = { running: true, phase: "Syncing", startedAt: Date.now(), finishedAt: null, result: null, error: null };
  void (async () => {
    try {
      const r = await importFromCrowdstrike();
      if ("error" in r) {
        csDevicesSync = { ...csDevicesSync, running: false, phase: "Error", error: r.error, finishedAt: Date.now() };
      } else {
        csDevicesSync = { ...csDevicesSync, running: false, phase: "Done", result: r, finishedAt: Date.now() };
      }
    } catch (err) {
      csDevicesSync = { ...csDevicesSync, running: false, phase: "Error", error: err instanceof Error ? err.message : "Sync failed.", finishedAt: Date.now() };
    }
  })();
  return { started: true };
}

export function startCsSpotlightSync(): { started: boolean; error?: string } {
  if (!falconConfig()) return { started: false, error: "CrowdStrike is not configured." };
  if (csSpotlightSync.running) return { started: false, error: "Spotlight sync already running." };
  csSpotlightSync = { running: true, phase: "Syncing", startedAt: Date.now(), finishedAt: null, result: null, error: null };
  void (async () => {
    try {
      const r = await importFromCrowdstrikeSpotlight();
      if ("error" in r) {
        csSpotlightSync = { ...csSpotlightSync, running: false, phase: "Error", error: r.error, finishedAt: Date.now() };
      } else {
        csSpotlightSync = { ...csSpotlightSync, running: false, phase: "Done", result: r, finishedAt: Date.now() };
      }
    } catch (err) {
      csSpotlightSync = { ...csSpotlightSync, running: false, phase: "Error", error: err instanceof Error ? err.message : "Sync failed.", finishedAt: Date.now() };
    }
  })();
  return { started: true };
}

export type IntuneImportResult = {
  assetsUpserted: number;
  findingsRescored: number;
  company: string;
  autoScan?: AutoScanResult;
};

// Sync Intune managed devices as inventory assets. Devices belong to the
// tenant — our own organization — so they attach to the internal company
// (GMI), created if it doesn't exist yet. Honest linkage: Intune endpoints are
// never attributed to an external client.
export async function importFromIntune(): Promise<
  IntuneImportResult | { error: string }
> {
  if (!intuneConfig()) {
    return {
      error:
        "Intune is not configured. Set INTUNE_TENANT_ID, INTUNE_CLIENT_ID, and INTUNE_CLIENT_SECRET to sync managed devices.",
    };
  }
  const s = store();
  try {
    const devices = await intuneListAssets();
    return await importEndpoints(s, devices, "intune");
  } catch (err) {
    return {
      error: err instanceof Error ? err.message : "Failed to reach Microsoft Graph.",
    };
  }
}

export type EndpointImportResult = {
  assetsUpserted: number;
  findingsRescored: number;
  company: string;
  autoScan?: AutoScanResult;
};

// Shared endpoint-inventory upsert for Intune / CrowdStrike device sources.
// By default devices attach to the internal org. Set customerName to pin
// them to a specific client company instead (e.g. FALCON_CUSTOMER env var),
// which is required for MSSP deployments where one Falcon tenant serves a client.
async function importEndpoints(
  s: StoreShape,
  devices: {
    externalId: string;
    hostname: string;
    ipAddresses: string[];
    os: string;
    owner: string;
    tags: string[];
    criticality: InternalAsset["criticality"];
    exposure: InternalAsset["exposure"];
  }[],
  source: AssetSource,
  customerName?: string,
): Promise<EndpointImportResult> {
  let internal: InternalCompany | undefined;
  if (customerName) {
    // Pin to a named client company; create it if first encounter.
    internal = Array.from(s.companies.values()).find(
      (c) => c.name.toLowerCase() === customerName.toLowerCase(),
    );
    if (!internal) {
      const created = createCompany({ name: customerName });
      if ("error" in created) throw new Error(created.error);
      internal = s.companies.get(created.id)!;
    }
  } else {
    internal = Array.from(s.companies.values()).find((c) => c.kind === "internal");
    if (!internal) {
      const created = createCompany({ name: "GMI", kind: "internal" });
      if ("error" in created) throw new Error(created.error);
      internal = s.companies.get(created.id)!;
    }
  }

  let assetsUpserted = 0;
  for (const d of devices) {
    const identifier = d.hostname || d.externalId;
    if (!identifier) continue;
    upsertAsset(s, {
      identifier,
      hostname: d.hostname,
      ipAddresses: d.ipAddresses,
      companyId: internal.id,
      companyName: internal.name,
      exposure: d.exposure,
      criticality: d.criticality,
      os: d.os,
      owner: d.owner,
      tags: d.tags,
      source,
      externalId: d.externalId,
    });
    assetsUpserted += 1;
  }

  let findingsRescored = 0;
  for (const f of s.findings.values()) {
    const before = f.realRisk;
    rescoreFinding(s, f);
    if (f.realRisk !== before || f.assetSource === source) findingsRescored += 1;
  }

  let autoScan: AutoScanResult | undefined;
  if (s.settings.autoScanNewAssets) autoScan = await autoScanGaps();

  await flushNow();
  return { assetsUpserted, findingsRescored, company: internal.name, autoScan };
}

// Sync CrowdStrike Falcon host inventory (the scan/coverage perspective).
// Set FALCON_CUSTOMER to pin devices to a specific client company; omit to
// attach to the internal GMI org (default for own-estate deployments).
export async function importFromCrowdstrike(): Promise<
  EndpointImportResult | { error: string }
> {
  if (!falconConfig()) {
    return {
      error:
        "CrowdStrike is not configured. Set FALCON_CLIENT_ID, FALCON_CLIENT_SECRET, and FALCON_CLOUD to sync host inventory.",
    };
  }
  const s = store();
  const customer = process.env.FALCON_CUSTOMER?.trim() || undefined;
  try {
    const devices = await falconListAssets();
    return await importEndpoints(s, devices, "crowdstrike", customer);
  } catch (err) {
    return {
      error: err instanceof Error ? err.message : "Failed to reach the CrowdStrike API.",
    };
  }
}

export type SpotlightImportResult = {
  findingsImported: number;
  hostsAffected: number;
  skipped: number;
};

// Import CrowdStrike Spotlight vulnerabilities as vuln-class findings.
// Each finding is matched to a company via host lookup (prefers CrowdStrike
// device assets already in inventory). Requires spotlight-vulnerabilities:read.
export async function importFromCrowdstrikeSpotlight(): Promise<
  SpotlightImportResult | { error: string }
> {
  if (!falconConfig()) {
    return {
      error:
        "CrowdStrike is not configured. Set FALCON_CLIENT_ID, FALCON_CLIENT_SECRET, and FALCON_CLOUD.",
    };
  }
  const s = store();
  let items;
  try {
    items = await spotlightListFindings();
  } catch (err) {
    return { error: err instanceof Error ? err.message : "Failed to reach the CrowdStrike Spotlight API." };
  }

  const nowIso = new Date().toISOString();
  let findingsImported = 0;
  let skipped = 0;
  const hosts = new Set<string>();
  const scanByCompany = new Map<string, InternalScan>();
  const falconCustomer = process.env.FALCON_CUSTOMER?.trim() || "";

  // Build a dedupe index once — O(n) — instead of scanning all findings per
  // item. Keys are company-scoped so customers sharing asset strings never
  // swallow each other's findings.
  const existingFindingByKey = new Map<string, Finding>();
  for (const f of s.findings.values()) {
    if (f.connector === "crowdstrike" && f.status !== "Resolved") {
      existingFindingByKey.set(`${f.companyId}::${f.cve}::${f.asset}`, f);
    }
  }

  // Reuse existing spotlight scan per company (upsert by externalRef).
  const existingScanByCompany = new Map<string, InternalScan>();
  for (const scan of s.scans.values()) {
    if (scan.externalRef?.startsWith("spotlight:")) {
      existingScanByCompany.set(scan.companyId, scan);
    }
  }

  for (const item of items) {
    const assetKey = item.hostname || item.localIp;
    if (!assetKey) { skipped += 1; continue; }

    // Match to a company via existing asset, then company-name fuzzy match.
    // Customer segmentation: FALCON_CUSTOMER pins all Spotlight findings to a
    // named client company. Without it, findings match via Tidal asset lookup
    // then hostname tokens, then fall back to the internal org — only when no
    // FALCON_CUSTOMER is set (own-estate deployment). Inventory attribution
    // only counts when every matching asset agrees on a single owner —
    // hostnames/IPs shared across customers are inconclusive.
    const owners = assetOwners(s, item.hostname, item.localIp);
    let companyId: string | null | undefined =
      owners.size === 1 ? owners.values().next().value : undefined;
    if (!companyId && falconCustomer) {
      // Pin to the named customer company; create it if first encounter.
      let c = Array.from(s.companies.values()).find(
        (co) => co.name.toLowerCase() === falconCustomer.toLowerCase(),
      );
      if (!c) {
        const cr = createCompany({ name: falconCustomer });
        if (!("error" in cr)) c = s.companies.get(cr.id);
      }
      companyId = c?.id;
    }
    if (!companyId) companyId = matchCompanyForScan(s, item.hostname, item.localIp);
    if (!companyId && !falconCustomer) {
      // Own-estate fallback only when no FALCON_CUSTOMER is set.
      companyId = Array.from(s.companies.values()).find((c) => c.kind === "internal")?.id;
    }
    if (!companyId) { skipped += 1; continue; }
    hosts.add(assetKey);

    // Reuse an existing scan for this company rather than creating a new one each sync.
    let scan = scanByCompany.get(companyId) ?? existingScanByCompany.get(companyId);
    if (!scan) {
      const company = s.companies.get(companyId)!;
      const folder = ensureFolder(s, companyId, "Spotlight");
      const scanId = nextId(s, "SCAN");
      scan = {
        id: scanId,
        name: `CrowdStrike Spotlight — ${company.name}`,
        companyId: company.id,
        companyName: company.name,
        folderId: folder.id,
        folderName: folder.name,
        connector: "crowdstrike",
        profile: "agent-sync",
        targets: [assetKey],
        status: "Completed",
        createdAt: nowIso,
        startedAt: nowIso,
        completedAt: nowIso,
        findingsCount: 0,
        severityCounts: emptySeverityCounts(),
        hostsScanned: 0,
        requestedBy: "imported@crowdstrike-spotlight",
        durationMs: 1,
        progressFrozenAt: 100,
        seed: hashSeed(scanId),
        vendor: null,
        externalRef: `spotlight:${companyId}`,
      };
      s.scans.set(scanId, scan);
    }
    scan.completedAt = nowIso;
    scanByCompany.set(companyId, scan);

    const dedupeKey = `${companyId}::${item.cve}::${assetKey}`;
    const existingFinding = existingFindingByKey.get(dedupeKey);
    if (existingFinding) { existingFinding.lastSeen = nowIso; continue; }

    s.findings.set(`VLN-${(s.counter += 1)}`, {
      id: `VLN-${s.counter}`,
      scanId: scan.id,
      companyId: scan.companyId,
      companyName: scan.companyName,
      connector: "crowdstrike",
      cve: item.cve,
      title: item.title,
      severity: item.severity,
      cvss: item.cvss,
      cvssV3: item.cvss,
      cvssV2: 0,
      vpr: 0,
      epss: 0,
      asset: item.hostname || item.localIp,
      port: "N/A",
      category: "Endpoint",
      description: `${item.description}${item.exprRating ? `\n\nExPRT Rating: ${item.exprRating}` : ""}`,
      remediation: item.remediation,
      status: "Open",
      assignee: null,
      firstSeen: nowIso,
      lastSeen: nowIso,
      resolvedAt: null,
      exploitAvailable: item.exploitAvailable,
      ...riskFields(s, {
        cve: item.cve,
        cvss: item.cvss,
        epss: 0,
        exploitAvailable: item.exploitAvailable,
        asset: item.hostname || item.localIp,
        companyId: scan.companyId,
      }),
    });
    findingsImported += 1;
  }

  for (const scan of scanByCompany.values()) {
    const all = Array.from(s.findings.values()).filter((f) => f.scanId === scan.id);
    scan.findingsCount = all.length;
    const counts = emptySeverityCounts();
    for (const f of all) counts[f.severity] += 1;
    scan.severityCounts = counts;
    scan.hostsScanned = new Set(all.map((f) => f.asset)).size;
  }

  await flushNow();
  return { findingsImported, hostsAffected: hosts.size, skipped };
}

export type DefenderImportResult = {
  findingsImported: number;
  hostsAffected: number;
  company: string;
};

// Import Microsoft Defender device vulnerabilities as findings (the vuln
// perspective for a Defender estate). Attaches to the DEFENDER_CUSTOMER
// company when set, else the internal org. Findings land under a "Defender"
// folder on a synthetic completed scan.
export async function importFromDefender(): Promise<
  DefenderImportResult | { error: string }
> {
  if (!defenderConfig()) {
    return {
      error:
        "Defender is not configured. Set DEFENDER_TENANT_ID, DEFENDER_CLIENT_ID, and DEFENDER_CLIENT_SECRET.",
    };
  }
  const s = store();
  let items;
  try {
    items = await defenderListFindings();
  } catch (err) {
    return {
      error: err instanceof Error ? err.message : "Failed to reach the Defender API.",
    };
  }

  // Resolve the owning company.
  const customer = (process.env.DEFENDER_CUSTOMER ?? "").trim();
  let company: InternalCompany | undefined;
  if (customer) {
    company =
      Array.from(s.companies.values()).find(
        (c) => c.name.toLowerCase() === customer.toLowerCase(),
      ) ?? undefined;
    if (!company) {
      const created = createCompany({ name: customer });
      if ("error" in created) return { error: created.error };
      company = s.companies.get(created.id)!;
    }
  } else {
    company = Array.from(s.companies.values()).find((c) => c.kind === "internal");
    if (!company) {
      const created = createCompany({ name: "GMI", kind: "internal" });
      if ("error" in created) return { error: created.error };
      company = s.companies.get(created.id)!;
    }
  }

  const folder = ensureFolder(s, company.id, "Defender");
  const nowIso = new Date().toISOString();
  const scanId = nextId(s, "SCAN");
  const scan: InternalScan = {
    id: scanId,
    name: "Defender Vulnerability Sync",
    companyId: company.id,
    companyName: company.name,
    folderId: folder.id,
    folderName: folder.name,
    connector: "defender",
    profile: "agent-sync",
    targets: [],
    status: "Completed",
    createdAt: nowIso,
    startedAt: nowIso,
    completedAt: nowIso,
    findingsCount: 0,
    severityCounts: emptySeverityCounts(),
    hostsScanned: 0,
    requestedBy: "defender@import",
    durationMs: 1,
    progressFrozenAt: 100,
    seed: hashSeed(scanId),
    vendor: null,
  };
  s.scans.set(scanId, scan);

  let findingsImported = 0;
  for (const item of items) {
    const dedupeKey = `${item.cve}::${item.asset}`;
    const existing = Array.from(s.findings.values()).find(
      (f) =>
        `${f.cve}::${f.asset}` === dedupeKey &&
        f.companyId === company!.id &&
        f.status !== "Resolved",
    );
    if (existing) {
      existing.lastSeen = nowIso;
      continue;
    }
    const id = nextId(s, "VLN");
    s.findings.set(id, {
      id,
      scanId,
      companyId: company.id,
      companyName: company.name,
      connector: "defender",
      cve: item.cve,
      title: item.title,
      severity: item.severity,
      cvss: item.cvss,
      cvssV3: item.cvss,
      cvssV2: 0,
      vpr: 0,
      epss: 0,
      asset: item.asset,
      port: "N/A",
      category: item.category,
      description: item.description,
      remediation: item.remediation,
      status: "Open",
      assignee: null,
      firstSeen: nowIso,
      lastSeen: nowIso,
      resolvedAt: null,
      exploitAvailable: false,
      ...riskFields(s, {
        cve: item.cve,
        cvss: item.cvss,
        epss: 0,
        exploitAvailable: false,
        asset: item.asset,
        companyId: company.id,
      }),
    });
    findingsImported += 1;
  }

  const all = Array.from(s.findings.values()).filter((f) => f.scanId === scanId);
  scan.findingsCount = all.length;
  const counts = emptySeverityCounts();
  for (const f of all) counts[f.severity] += 1;
  scan.severityCounts = counts;
  scan.hostsScanned = new Set(all.map((f) => f.asset)).size;

  await flushNow();
  return {
    findingsImported,
    hostsAffected: scan.hostsScanned,
    company: company.name,
  };
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

  await flushNow();
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

// Runs Vulners Bridge scans per target asynchronously after startScan() returns.
// Updates the scan record in-place and flushes to the DB when done.
async function runVulnersBridgeScanAsync(
  scanId: string,
  targets: string[],
  companyId: string,
): Promise<void> {
  const s = store();
  const scan = s.scans.get(scanId);
  if (!scan || !scan.bridgeScan) return;

  const nowIso = new Date().toISOString();
  const company = s.companies.get(companyId);
  const companyName = company?.name ?? scan.companyName;

  try {
    for (const target of targets) {
      let results: VulnersBridgeFinding[];
      try {
        results = await vulnersBridgeScanHost(target);
      } catch {
        continue; // skip unreachable targets; don't abort the whole scan
      }
      for (const v of results) {
        const existing = Array.from(s.findings.values()).find(
          (f) =>
            f.companyId === companyId &&
            f.cve === v.cve &&
            f.asset === target &&
            f.status !== "Resolved",
        );
        if (existing) {
          if (v.exploitAvailable && !existing.exploitAvailable) {
            existing.exploitAvailable = true;
            rescoreFinding(s, existing);
          }
          existing.lastSeen = nowIso;
          continue;
        }
        const severity: Finding["severity"] =
          v.cvss >= 9 ? "Critical" : v.cvss >= 7 ? "High" : v.cvss >= 4 ? "Medium" : v.cvss > 0 ? "Low" : "Info";
        const fid = nextId(s, "FIND");
        const f: Finding = {
          id: fid,
          scanId,
          companyId,
          companyName,
          connector: "vulners",
          cve: v.cve,
          title: `${v.cve} — ${v.component}`,
          severity,
          cvss: v.cvss,
          cvssV2: 0,
          cvssV3: v.cvss,
          vpr: 0,
          epss: 0,
          asset: target,
          port: v.component.match(/Port (\d+)/)?.[1] ?? "",
          category: "Network Service",
          description: `${v.cve} detected on ${v.component} at ${target}.`,
          remediation: `Patch or mitigate ${v.component} — see ${v.cve} for details.`,
          status: "Open",
          assignee: null,
          firstSeen: nowIso,
          lastSeen: nowIso,
          resolvedAt: null,
          exploitAvailable: v.exploitAvailable,
          kev: false,
          ransomware: false,
          assetExposure: "Internet-facing",
          assetCriticality: "Normal",
          assetSource: "nmap",
          realRisk: 0,
          riskPriority: "Info",
        };
        rescoreFinding(s, f);
        s.findings.set(fid, f);
      }
    }
  } catch (err) {
    const current = s.scans.get(scanId);
    if (current) {
      current.status = "Failed";
      current.error = err instanceof Error ? err.message : "Bridge scan failed.";
      current.completedAt = new Date().toISOString();
      current.progressFrozenAt = 0;
      if (current.bridgeScan) current.bridgeScan.done = true;
    }
    void flushNow();
    return;
  }

  const current = s.scans.get(scanId);
  if (!current || !current.bridgeScan) return;
  const all = Array.from(s.findings.values()).filter((f) => f.scanId === scanId);
  current.findingsCount = all.length;
  const counts = emptySeverityCounts();
  for (const f of all) counts[f.severity] = (counts[f.severity] ?? 0) + 1;
  current.severityCounts = counts;
  current.hostsScanned = new Set(all.map((f) => f.asset)).size || targets.length;
  current.status = "Completed";
  current.completedAt = new Date().toISOString();
  current.progressFrozenAt = 100;
  current.bridgeScan.done = true;
  void flushNow();
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
  const isBridgeScan = input.connector === "vulners" && Boolean(vulnersBridgeConfig());

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

  if (!vendor && !isBridgeScan && !demoScansEnabled()) {
    return {
      error: `${input.connector} is not connected to a live scanner. Configure its credentials to run real scans — demo scans are disabled in production.`,
    };
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
    progressFrozenAt: vendor ? 0 : isBridgeScan ? 30 : null,
    seed: seedVal,
    vendor,
    bridgeScan: isBridgeScan ? { done: false } : undefined,
  };
  s.scans.set(id, scan);

  if (isBridgeScan) {
    void runVulnersBridgeScanAsync(id, input.targets, company.id);
  }

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
      markDirty();
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
      markDirty();
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
      markDirty();
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
  markDirty();
  return toPublic(scan, now);
}

// Finding classes are the different LENSES on an org's security, each telling a
// different part of the story and each first-class:
//   vuln    — CVE-based vulnerability scans (Nessus/Defender/CrowdStrike/Vulners)
//   osint   — external attack-surface recon (SpiderFoot/Artemis)
//   pentest — manual/authenticated app testing (Burp Suite — near-term)
// Extend by mapping a new connector here; the rest of the app keys off the class.
export type FindingClass = "vuln" | "osint" | "pentest";
const CONNECTOR_CLASS: Record<string, FindingClass> = {
  nessus: "vuln",
  defender: "vuln",
  crowdstrike: "vuln",
  vulners: "vuln",
  spiderfoot: "osint",
  artemis: "osint",
  burp: "pentest",
};
export function findingClass(f: Finding): FindingClass {
  return CONNECTOR_CLASS[f.connector] ?? "vuln";
}
export function isOsintFinding(f: Finding): boolean {
  return findingClass(f) === "osint";
}
// Remediation-worthy findings you patch/fix (vuln + pentest) — as opposed to
// attack-surface exposures you shrink. Drives the SSVC queue and SLA clock.
export function isRemediationFinding(f: Finding): boolean {
  return findingClass(f) !== "osint";
}

export function listFindings(filter?: {
  scanId?: string;
  companyId?: string;
  kind?: FindingClass | "all";
}): Finding[] {
  const s = store();
  tick(s);
  let all = Array.from(s.findings.values());
  if (filter?.scanId) all = all.filter((f) => f.scanId === filter.scanId);
  if (filter?.companyId) all = all.filter((f) => f.companyId === filter.companyId);
  const kind = filter?.kind ?? "all";
  if (kind !== "all") all = all.filter((f) => findingClass(f) === kind);
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
  markDirty();
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
  // For a specific company, honor the filter; for the all-company rollup,
  // exclude demo/test companies so they don't inflate production metrics.
  // Vuln posture engine: CVE-based scan findings only. OSINT/attack-surface is
  // a separate story (Attack Surface page), never blended into these metrics.
  const demo = demoCompanyIds(s);
  const all = Array.from(s.findings.values()).filter(
    (f) =>
      isRemediationFinding(f) &&
      (filter?.companyId ? f.companyId === filter.companyId : !demo.has(f.companyId)),
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

  // Scan coverage for the composite: scoped to a company, or summed globally.
  const globalCoverage = filter?.companyId
    ? companyCoverage(s, filter.companyId)
    : Array.from(s.companies.keys()).reduce(
        (acc, cid) => {
          const c = companyCoverage(s, cid);
          return { known: acc.known + c.known, scanned: acc.scanned + c.scanned };
        },
        { known: 0, scanned: 0 },
      );

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
    composite: computeComposite(open, globalCoverage),
    riskPriorityCounts,
    topRisks,
  };
}

// --- demo seed -------------------------------------------------------------

function seed(s: StoreShape): void {
  if (s.seeded) return;
  s.seeded = true;
  // Demo/stub data only when explicitly requested. In production the console
  // is populated from the real Nessus import instead.
  if (process.env.SEED_DEMO_DATA !== "true") return;
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
      name: "GMI",
      industry: "Managed Security — Our Organization",
      contactName: "Chuck Helstein",
      contactEmail: "chuck@gmi.com",
      folders: ["Corporate", "External", "Servers", "Endpoints"],
    },
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
    { company: "GMI", identifier: "dc01.gmi.local", ips: ["10.0.0.10"], exposure: "Internal", criticality: "Crown Jewel", os: "Windows Server 2022", owner: "GMI IT" },
    { company: "GMI", identifier: "fw-edge-01.gmi.local", ips: ["10.0.0.1"], exposure: "Internet-facing", criticality: "Crown Jewel", os: "FortiOS 7.4", owner: "GMI NetSec" },
    { company: "GMI", identifier: "jump-01.gmi.local", ips: ["10.0.0.50"], exposure: "Internal", criticality: "High", os: "Ubuntu 22.04", owner: "GMI SecOps" },
    { company: "GMI", identifier: "ci-build-01.gmi.local", ips: ["10.0.0.60"], exposure: "Internal", criticality: "High", os: "Ubuntu 22.04", owner: "GMI Eng" },
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
      name: "GMI Corporate Credentialed Scan",
      company: "GMI",
      folder: "Servers",
      connector: "nessus",
      profile: "credentialed",
      targets: ["10.0.0.0/24"],
      daysAgo: 4,
    },
    {
      name: "GMI Perimeter Scan",
      company: "GMI",
      folder: "External",
      connector: "nessus",
      profile: "standard",
      targets: ["gmi.com"],
      daysAgo: 2,
    },
    {
      name: "GMI Endpoint Telemetry Sync",
      company: "GMI",
      folder: "Endpoints",
      connector: "crowdstrike",
      profile: "agent-sync",
      targets: ["ws-eng-207.gmi.local", "ws-ops-052.gmi.local"],
      daysAgo: 1,
    },
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
