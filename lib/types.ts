export type Severity = "Critical" | "High" | "Medium" | "Low" | "Info";

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
};

export type Folder = {
  id: string;
  companyId: string;
  name: string;
  createdAt: string;
  scanCount: number;
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
  cvss: number;
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
};
