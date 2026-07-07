export type Severity = "Critical" | "High" | "Medium" | "Low" | "Info";

export type CvssVersion = "v2" | "v3";

export type ScanStatus =
  | "Queued"
  | "Running"
  | "Paused"
  | "Completed"
  | "Stopped"
  | "Failed";

export type FindingStatus =
  | "Open"
  | "In Remediation"
  | "Risk Accepted"
  | "False Positive"
  | "Resolved";

export type Company = {
  id: string;
  name: string;
  // "internal" = our own organization (GMI scans its own assets);
  // "client" = an external customer we scan on their behalf.
  kind: "internal" | "client";
  industry: string;
  contactName: string;
  contactEmail: string;
  createdAt: string;
  // derived rollups
  folderCount: number;
  scanCount: number;
  activeScans: number;
  openFindings: number; // open vulnerability-scan findings (CVE-based)
  exposureFindings: number; // open OSINT / attack-surface exposures
  criticalOpen: number;
  exposureScore: number;
  // Asset-inventory coverage. inventoryAssets is how many inventory assets
  // this customer has (0 = not in Tidal / no inventory). inventoryCoverage is
  // the % of open findings whose environment context comes from the inventory
  // rather than being inferred from the hostname (-1 when there are none).
  inventoryAssets: number;
  inventoryCoverage: number;
  // Composite security-posture score (0-100, higher = worse) and its band.
  compositeScore: number;
  compositeBand: "Low" | "Guarded" | "Elevated" | "High" | "Critical";
  // True for demo/test companies — shown in the console but excluded from
  // production reporting and GRC push.
  isDemo: boolean;
};

export type CompositeScore = {
  score: number;
  band: "Low" | "Guarded" | "Elevated" | "High" | "Critical";
  components: {
    // each 0-100, higher = worse, with the weight it contributes
    exposure: number;
    kevPressure: number;
    slaBreach: number;
    coverageGap: number;
  };
};

export type Folder = {
  id: string;
  companyId: string;
  name: string;
  createdAt: string;
  scanCount: number;
};

export type AssetExposure = "Internet-facing" | "Internal" | "Isolated";
export type AssetCriticality = "Crown Jewel" | "High" | "Normal" | "Low";
export type AssetSource =
  | "tidal"
  | "intune"
  | "crowdstrike"
  | "manual"
  | "inferred";

// An asset in the inventory (sourced from Tidal.io, or entered manually).
// This is the authoritative environmental context for real-risk scoring.
export type InventoryAsset = {
  id: string;
  identifier: string; // primary hostname/ip that findings reference
  hostname: string;
  ipAddresses: string[];
  companyId: string;
  companyName: string;
  exposure: AssetExposure;
  criticality: AssetCriticality;
  os: string;
  owner: string;
  tags: string[];
  source: AssetSource;
  externalId: string; // Tidal asset id, when sourced from Tidal
  lastSynced: string;
  openFindings: number; // derived
};

export type ConnectorId =
  | "nessus"
  | "vulners"
  | "crowdstrike"
  | "defender"
  | "qualys"
  | "spiderfoot"
  | "artemis";

export type ConnectorStatus =
  | "Connected"
  | "Demo Mode"
  | "Not Configured"
  | "CSV Upload"
  | "Planned"
  | "Error";

export type Connector = {
  id: ConnectorId;
  name: string;
  vendor: string;
  kind: string;
  description: string;
  status: ConnectorStatus;
  capabilities: string[];
  envVars: string[];
  configured: boolean;
  docsUrl: string;
};

export type ScanProfile = {
  id: string;
  label: string;
  description: string;
};

export type Scan = {
  id: string;
  name: string;
  companyId: string;
  companyName: string;
  folderId: string;
  folderName: string;
  connector: ConnectorId;
  profile: string;
  targets: string[];
  status: ScanStatus;
  progress: number;
  createdAt: string;
  startedAt: string | null;
  completedAt: string | null;
  findingsCount: number;
  severityCounts: Record<Severity, number>;
  hostsScanned: number;
  requestedBy: string;
  error?: string;
};

export type Finding = {
  id: string;
  scanId: string;
  companyId: string;
  companyName: string;
  connector: ConnectorId;
  cve: string;
  title: string;
  severity: Severity;
  cvss: number; // primary score (CVSS v3 when available, else v2)
  cvssV2: number; // 0 when the source has no v2 score
  cvssV3: number; // 0 when the source has no v3 score
  vpr: number; // Tenable Vulnerability Priority Rating (0-10), 0 when absent
  epss: number;
  asset: string;
  port: string;
  category: string;
  description: string;
  remediation: string;
  status: FindingStatus;
  assignee: string | null;
  firstSeen: string;
  lastSeen: string;
  resolvedAt: string | null;
  exploitAvailable: boolean;
  // Threat intel
  // Every CVE the source maps to (a scanner plugin often covers several). The
  // primary `cve` above is KEV-preferred; enrichment re-checks the full set.
  cves?: string[];
  kev: boolean; // CISA Known Exploited Vulnerability (exploited in the wild)
  ransomware: boolean; // KEV flagged as used in ransomware campaigns

  // Environmental context (from the affected asset)
  assetExposure: "Internet-facing" | "Internal" | "Isolated";
  assetCriticality: "Crown Jewel" | "High" | "Normal" | "Low";
  // Where the environmental context came from: the asset inventory (Tidal /
  // manual) or hostname-inferred heuristics.
  assetSource: AssetSource;
  // Composite real-risk score (0-100) and its priority band
  realRisk: number;
  riskPriority: "Critical" | "High" | "Medium" | "Low" | "Info";
};

export type ComplianceStatus = "Pass" | "Fail" | "At Risk" | "Info";

export type ComplianceRequirement = {
  id: string; // e.g. "11.3.2"
  title: string;
  status: ComplianceStatus;
  detail: string;
  failing: number;
};

export type CompliancePosture = {
  framework: string; // "PCI DSS 4.0"
  companyId: string;
  companyName: string;
  overall: ComplianceStatus;
  score: number; // 0-100 compliance score
  asvPass: boolean;
  failingFindings: number; // CVSS >= 4.0 on internet-facing assets
  lastScanDaysAgo: number | null;
  requirements: ComplianceRequirement[];
  summary: {
    externalFailing: number;
    internalHighCrit: number;
    slaBreaches: number;
    openTotal: number;
  };
};

export type ComplianceResult = {
  framework: string;
  aggregate: {
    companies: number;
    passing: number;
    failing: number;
    avgScore: number;
    asvFailingCompanies: number;
  };
  companies: CompliancePosture[];
};

export type AttackHop = {
  asset: string;
  exposure: string;
  criticality: string;
  role: "entry" | "pivot" | "target";
  cve: string | null;
  title: string | null;
  realRisk: number;
  kev: boolean;
  // How the attacker reaches THIS hop from the previous one (null on the entry).
  via: string | null;
  // Reachable on the network but with no known open finding to exploit — the
  // hop is a movement step, not a confirmed compromise.
  reachableOnly: boolean;
};

export type AttackEntry = {
  id: string;
  asset: string;
  companyId: string;
  companyName: string;
  exposure: string;
  criticality: string;
  entryScore: number; // ease of initial compromise, 0-100
  kev: boolean;
  exploitable: boolean;
  reachable: number;
  crownJewelsReached: number;
  blastScore: number; // 0-100
  path: AttackHop[];
  hops: number; // number of moves in the chain (path length - 1)
  targetAsset: string | null;
  targetCriticality: string | null;
};

export type AttackPathResult = {
  summary: {
    entryPoints: number;
    crownJewelsAtRisk: number;
    maxBlast: number;
  };
  entries: AttackEntry[];
};

export type QuantifyMetrics = {
  totalOpen: number;
  severityCounts: Record<Severity, number>;
  avgCvss: number;
  exposureScore: number;
  exploitableOpen: number;
  slaBuckets: { label: string; count: number; breach: boolean }[];
  assetRisk: { asset: string; score: number; open: number; worst: Severity }[];
  connectorCounts: { connector: ConnectorId; open: number }[];
  statusCounts: Record<FindingStatus, number>;
  trend: { date: string; open: number; resolved: number }[];
  meanTimeToRemediateDays: number | null;
  companyBreakdown: {
    companyId: string;
    companyName: string;
    open: number;
    critical: number;
    exposureScore: number;
  }[];
  kevOpen: number;
  composite: CompositeScore;
  riskPriorityCounts: Record<
    "Critical" | "High" | "Medium" | "Low" | "Info",
    number
  >;
  topRisks: {
    id: string;
    cve: string;
    title: string;
    asset: string;
    companyName: string;
    realRisk: number;
    riskPriority: "Critical" | "High" | "Medium" | "Low" | "Info";
    kev: boolean;
    exposure: string;
  }[];
};
