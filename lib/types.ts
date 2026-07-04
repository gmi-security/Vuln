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
  openFindings: number;
  criticalOpen: number;
  exposureScore: number;
  // Asset-inventory coverage. inventoryAssets is how many inventory assets
  // this customer has (0 = not in Tidal / no inventory). inventoryCoverage is
  // the % of open findings whose environment context comes from the inventory
  // rather than being inferred from the hostname (-1 when there are none).
  inventoryAssets: number;
  inventoryCoverage: number;
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
export type AssetSource = "tidal" | "manual" | "inferred";

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

export type ConnectorId = "nessus" | "vulners" | "crowdstrike" | "qualys";

export type ConnectorStatus = "Connected" | "Demo Mode" | "Planned" | "Error";

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
  kev: boolean; // CISA Known Exploited Vulnerability (exploited in the wild)
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
