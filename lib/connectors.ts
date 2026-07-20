import type { Connector, ConnectorId, ScanProfile } from "@/lib/types";

// Scanner connector registry. Each connector runs in Demo Mode until its
// environment variables are set, at which point the adapter in this file is
// the single integration point for wiring the real vendor API.

type ConnectorDef = Omit<Connector, "status" | "configured"> & {
  planned?: boolean;
  // Set when a connector supports two independent, alternative auth modes
  // (e.g. Vulners' cloud API key vs its bridge URL+key) — configured is true
  // if EITHER full set is present, not requiring both. envVars stays the
  // union of both sets for display (each shown with its own set/unset pill).
  envVarsAlt?: string[];
  // Demo simulation profile: how long a simulated scan runs and how noisy it is.
  demo: {
    minDurationMs: number;
    maxDurationMs: number;
    minFindings: number;
    maxFindings: number;
    categories?: string[];
  };
};

const CONNECTOR_DEFS: Record<ConnectorId, ConnectorDef> = {
  nessus: {
    id: "nessus",
    name: "Nessus",
    vendor: "Tenable",
    kind: "Network Vulnerability Scanner",
    description:
      "Authenticated and unauthenticated network scanning via the Nessus REST API. Launch scans by policy, track scan status, and import plugin results as findings.",
    capabilities: ["Launch scans", "Scan status", "Import findings", "Scan policies"],
    envVars: ["NESSUS_URL", "NESSUS_ACCESS_KEY", "NESSUS_SECRET_KEY"],
    docsUrl: "https://developer.tenable.com/reference/navigate",
    demo: { minDurationMs: 90_000, maxDurationMs: 180_000, minFindings: 18, maxFindings: 34 },
  },
  vulners: {
    id: "vulners",
    name: "Vulners",
    vendor: "Vulners",
    kind: "Vulnerability Intelligence & Audit",
    description:
      "Package-level audit and CVE enrichment via the Vulners cloud API, plus an active nmap --script vulners scan against a live target through the Vulners Bridge. Enriches findings with exploit and EPSS intelligence.",
    capabilities: ["Package audit", "CVE enrichment", "Exploit intel", "EPSS scores", "Active bridge scan"],
    // Two independent auth modes — either is enough to be "configured".
    envVars: ["VULNERS_API_KEY"],
    envVarsAlt: ["VULNERS_BRIDGE_URL", "VULNERS_BRIDGE_API_KEY"],
    docsUrl: "https://vulners.com/docs",
    demo: {
      minDurationMs: 30_000,
      maxDurationMs: 75_000,
      minFindings: 10,
      maxFindings: 22,
      categories: ["Application Library", "Operating System", "Web Server", "Cryptography", "CI/CD"],
    },
  },
  crowdstrike: {
    id: "crowdstrike",
    name: "CrowdStrike Spotlight",
    vendor: "CrowdStrike",
    kind: "Endpoint Vulnerability Management",
    description:
      "Agent-based vulnerability visibility from Falcon Spotlight. Pulls open vulnerabilities per host from the Falcon API — no active scanning required, results reflect live sensor telemetry.",
    capabilities: ["Sensor telemetry sync", "Host vulnerabilities", "ExPRT ratings", "Remediation info"],
    envVars: ["FALCON_CLIENT_ID", "FALCON_CLIENT_SECRET", "FALCON_CLOUD"],
    docsUrl: "https://falcon.crowdstrike.com/documentation/page/spotlight-apis",
    demo: {
      minDurationMs: 20_000,
      maxDurationMs: 45_000,
      minFindings: 12,
      maxFindings: 26,
      categories: ["Endpoint", "Operating System", "Application Library"],
    },
  },
  defender: {
    id: "defender",
    name: "Microsoft Defender Vulnerability Management",
    vendor: "Microsoft",
    kind: "Endpoint Vulnerability Management",
    description:
      "Agent-based vulnerability data from Microsoft Defender for Endpoint / Defender Vulnerability Management. Pulls CVE findings per device from the Microsoft Security API — no active scanning, reflects live Defender telemetry.",
    capabilities: ["Device vulnerabilities", "CVSS & severity", "Security recommendations", "No active scan"],
    envVars: ["DEFENDER_TENANT_ID", "DEFENDER_CLIENT_ID", "DEFENDER_CLIENT_SECRET"],
    docsUrl: "https://learn.microsoft.com/en-us/defender-endpoint/api/exposed-apis-list",
    demo: {
      minDurationMs: 20_000,
      maxDurationMs: 45_000,
      minFindings: 12,
      maxFindings: 26,
      categories: ["Endpoint", "Operating System", "Application Library"],
    },
  },
  qualys: {
    id: "qualys",
    name: "Qualys VMDR",
    vendor: "Qualys",
    kind: "Cloud Vulnerability Management",
    description:
      "Planned integration. Qualys VMDR scan orchestration and detection import via the Qualys API — on the roadmap once licensing lands.",
    capabilities: ["Launch scans", "Detection import", "Asset tags"],
    envVars: ["QUALYS_API_URL", "QUALYS_USERNAME", "QUALYS_PASSWORD"],
    docsUrl: "https://docs.qualys.com/en/vm/api/",
    planned: true,
    demo: { minDurationMs: 60_000, maxDurationMs: 120_000, minFindings: 15, maxFindings: 30 },
  },
  spiderfoot: {
    id: "spiderfoot",
    name: "SpiderFoot",
    vendor: "SpiderFoot",
    kind: "OSINT & Attack Surface Recon",
    description:
      "Automated OSINT and attack-surface reconnaissance across 200+ modules. Kicks off scans against a target's domains and IPs, then correlates exposed hosts, open ports, leaked credentials, and threat-intel associations into findings.",
    capabilities: ["OSINT collection", "Attack surface mapping", "Exposure discovery", "Threat intel correlation"],
    envVars: ["SPIDERFOOT_URL"],
    docsUrl: "https://www.spiderfoot.net/documentation/",
    demo: {
      minDurationMs: 60_000,
      maxDurationMs: 150_000,
      minFindings: 8,
      maxFindings: 20,
      categories: ["Attack Surface", "OSINT", "Exposed Service", "Threat Intel"],
    },
  },
  artemis: {
    id: "artemis",
    name: "Artemis",
    vendor: "CERT Polska",
    kind: "Attack Surface Vulnerability Scanner",
    description:
      "Modular attack-surface scanner from CERT.pl. Enumerates subdomains and services for a target, then runs checks for misconfigurations, exposed admin panels, weak credentials, and known CVEs across many hosts, importing per-target results as findings.",
    capabilities: ["Subdomain enumeration", "Misconfiguration checks", "Known-CVE detection", "Bulk host scanning"],
    envVars: ["ARTEMIS_API_URL", "ARTEMIS_API_TOKEN"],
    docsUrl: "https://artemis-scanner.readthedocs.io/",
    demo: {
      minDurationMs: 120_000,
      maxDurationMs: 300_000,
      minFindings: 10,
      maxFindings: 28,
      categories: ["Attack Surface", "Web Server", "Misconfiguration", "Exposed Service"],
    },
  },
  burp: {
    id: "burp",
    name: "Burp Suite",
    vendor: "PortSwigger",
    kind: "Web App Pentest & DAST",
    description:
      "Human-validated web-application testing from Burp Suite. Pulls scan issues from Burp Suite Enterprise (GraphQL API) or imports a Burp Professional XML export — web vulnerabilities confirmed by a tester, the strongest remediation signal.",
    capabilities: ["Validated web vulns", "DAST issues", "XML import", "Per-host issues"],
    envVars: ["BURP_API_URL", "BURP_API_KEY"],
    docsUrl: "https://portswigger.net/burp/documentation/enterprise/api-documentation",
    demo: {
      minDurationMs: 90_000,
      maxDurationMs: 240_000,
      minFindings: 6,
      maxFindings: 20,
      categories: ["Web Vulnerability", "Injection", "Authentication", "Misconfiguration"],
    },
  },
  nmap: {
    id: "nmap",
    name: "Nmap",
    vendor: "Nmap Project",
    kind: "Network Discovery & Service Enumeration",
    description:
      "Open-source network discovery. Enumerates open ports and running services per host and attaches that ground truth to the asset inventory — sharpening attack-path reachability — while raising findings only for genuinely risky exposed services (RDP, SMB, Telnet, databases). Pulls from a scan-runner or imports an nmap -oX XML export.",
    capabilities: ["Port discovery", "Service enumeration", "Exposed-service findings", "XML import"],
    envVars: ["NMAP_RUNNER_URL", "NMAP_RUNNER_TOKEN"],
    docsUrl: "https://nmap.org/book/output-formats-xml-output.html",
    demo: {
      minDurationMs: 30_000,
      maxDurationMs: 90_000,
      minFindings: 4,
      maxFindings: 14,
      categories: ["Exposed Service", "Open Port", "Service Enumeration"],
    },
  },
  zap: {
    id: "zap",
    name: "OWASP ZAP",
    vendor: "OWASP",
    kind: "Dynamic Application Security Testing (DAST)",
    description:
      "Live web-app scanning via the OWASP ZAP API. Crawls a target URL with the spider, then runs ZAP's active scan against everything it found — surfacing OWASP Top 10-class issues (injection, XSS, misconfiguration) confirmed against the running application, not just its source.",
    capabilities: ["Crawl & spider", "Active vulnerability scan", "OWASP Top 10 coverage", "Per-target findings"],
    envVars: ["ZAP_URL", "ZAP_API_KEY"],
    docsUrl: "https://www.zaproxy.org/docs/api/",
    demo: {
      minDurationMs: 60_000,
      maxDurationMs: 180_000,
      minFindings: 6,
      maxFindings: 18,
      categories: ["Web Vulnerability", "Injection", "Authentication", "Misconfiguration"],
    },
  },
};

export const SCAN_PROFILES: ScanProfile[] = [
  {
    id: "discovery",
    label: "Discovery",
    description: "Host and service discovery only — fast, low impact.",
  },
  {
    id: "standard",
    label: "Standard Vulnerability Scan",
    description: "Full unauthenticated vulnerability assessment of exposed services.",
  },
  {
    id: "credentialed",
    label: "Credentialed Deep Scan",
    description: "Authenticated scan with local checks, patch audit, and configuration review.",
  },
  {
    id: "pci",
    label: "PCI External",
    description: "External scan aligned to PCI DSS quarterly scanning requirements.",
  },
  {
    id: "agent-sync",
    label: "Agent Telemetry Sync",
    description: "Pull latest vulnerability state from deployed agents (no active probing).",
  },
];

function envSetComplete(vars: string[]): boolean {
  return vars.every((v) => Boolean(process.env[v]));
}

// Configured if the primary set is complete, OR (when present) the
// alternative set is — the two are independent auth modes, not a combined
// requirement.
function isConfigured(def: ConnectorDef): boolean {
  return envSetComplete(def.envVars) || Boolean(def.envVarsAlt && envSetComplete(def.envVarsAlt));
}

export function getConnectors(): Connector[] {
  return (Object.values(CONNECTOR_DEFS) as ConnectorDef[]).map((def) => {
    const configured = isConfigured(def);
    return {
      id: def.id,
      name: def.name,
      vendor: def.vendor,
      kind: def.kind,
      description: def.description,
      capabilities: def.capabilities,
      envVars: [...def.envVars, ...(def.envVarsAlt ?? [])],
      docsUrl: def.docsUrl,
      configured,
      status: def.planned
        ? "Planned"
        : configured
          ? "Connected"
          : process.env.DEMO_SCANS === "true"
            ? "Demo Mode"
            : "Not Configured",
    };
  });
}

export function getConnector(id: ConnectorId): Connector | undefined {
  return getConnectors().find((c) => c.id === id);
}

export function getDemoProfile(id: ConnectorId) {
  return CONNECTOR_DEFS[id].demo;
}

export function isPlanned(id: ConnectorId): boolean {
  return Boolean(CONNECTOR_DEFS[id].planned);
}

// ---------------------------------------------------------------------------
// Real API integration points.
//
//   nessus:      IMPLEMENTED in lib/nessus.ts — X-ApiKeys auth, template
//                lookup, create + launch, status polling, findings import.
//   vulners:     POST https://vulners.com/api/v3/audit/audit with package
//                inventory per host; map returned CVE list to findings.
//   crowdstrike: OAuth2 token from https://api.{FALCON_CLOUD}/oauth2/token,
//                then GET /spotlight/queries/vulnerabilities/v2 + entities
//                lookup; map to findings.
//   qualys:      planned — VM scan launch via /api/2.0/fo/scan/.
//   spiderfoot:  POST {SPIDERFOOT_URL}/startscan (scanname, scantarget,
//                typelist/modulelist), poll /scanstatus, pull results via
//                /scaneventresults?id=…; map correlations to findings.
//   artemis:     POST {ARTEMIS_API_URL}/api/add (targets) with Bearer
//                {ARTEMIS_API_TOKEN}, poll /api/analyses, then
//                /api/task-results/… ; map reports to findings.
//
// Connectors without a real adapter run in demo mode: the in-process scan
// engine (lib/store.ts) simulates progress and materializes findings.
// ---------------------------------------------------------------------------
