/** Shared vocabulary for customer source review and existing platform reporting.
 * A capability describes an implemented path, never proof that credentials work.
 */
export type ConnectorDomain = "endpoint-findings" | "web-findings" | "exposures" | "inventory" | "enrichment" | "saved-queries" | "appsec" | "ticket-delivery" | "orchestration";
export type ConnectorCapability = "vulnerability-import" | "inventory" | "scan" | "enrichment" | "saved-query" | "appsec" | "ticket-delivery" | "orchestration";
type Contract = { name: string; domains: readonly ConnectorDomain[]; capabilities: readonly ConnectorCapability[];
  storage: string; identity: string; lifecycle: string; planned?: boolean };
export const connectorDataContracts = {
  defender: { name: "Microsoft Defender", domains: ["endpoint-findings","inventory"], capabilities: ["vulnerability-import","inventory"], storage: "Completed Defender SQL generations and published platform findings", identity: "Customer, tenant, device, CVE and software version", lifecycle: "Completed import; preserve workflow and existing device-heartbeat closure rules" },
  crowdstrike: { name: "CrowdStrike", domains: ["endpoint-findings","inventory","saved-queries"], capabilities: ["vulnerability-import","inventory","saved-query"], storage: "Spotlight SQL generations, platform inventory and customer query cache", identity: "Customer, CID, AID and source finding ID", lifecycle: "Complete cursor import; suppression and closure remain source-specific" },
  elastic: { name: "Elasticsearch", domains: ["saved-queries"], capabilities: ["saved-query"], storage: "Customer-owned query definitions, cached results and history", identity: "Customer, saved query ID and dataset scope", lifecycle: "Replace result only after successful query; never sum mirrors into platform findings" },
  nessus: { name: "Nessus", domains: ["endpoint-findings"], capabilities: ["scan"], storage: "Published platform scans and findings", identity: "Customer, scan, host, plugin and port", lifecycle: "Keep scan coverage including hosts with no findings and existing reconciliation" },
  vulners: { name: "Vulners", domains: ["endpoint-findings","enrichment"], capabilities: ["scan","enrichment"], storage: "Published platform findings and enrichment provenance", identity: "Customer, bridge job or package finding; CVE for enrichment", lifecycle: "Bridge findings are observations; enrichment alone is not a second finding source" },
  spiderfoot: { name: "SpiderFoot", domains: ["exposures"], capabilities: ["scan"], storage: "Published platform scans and exposure findings", identity: "Customer, approved target, scan and event", lifecycle: "Exposure observations remain separate from patchable findings" },
  artemis: { name: "Artemis", domains: ["exposures"], capabilities: ["scan"], storage: "Published platform scans and attack-surface findings", identity: "Customer, target, analysis and task result", lifecycle: "Preserve CVE and non-CVE observations and existing exposure classification" },
  nmap: { name: "Nmap", domains: ["endpoint-findings","inventory"], capabilities: ["scan","inventory"], storage: "Published platform scans, inventory ports and risky-service findings", identity: "Customer, host, port and protocol", lifecycle: "Open services are inventory; only existing risky-service rules create findings" },
  burp: { name: "Burp Suite", domains: ["web-findings"], capabilities: ["scan"], storage: "Published platform web-test findings", identity: "Customer, site, URL and issue", lifecycle: "Preserve Enterprise and XML issue evidence; no invented CVE" },
  zap: { name: "OWASP ZAP", domains: ["web-findings"], capabilities: ["scan"], storage: "Published platform web-test scans and findings", identity: "Customer, target URL, scan and alert", lifecycle: "Keep crawl/scan progress and non-CVE alerts" },
  tidal: { name: "Tidal", domains: ["inventory"], capabilities: ["inventory"], storage: "Published platform asset inventory", identity: "Customer and external asset ID", lifecycle: "Keep API/CSV ownership and asset criticality; inventory is not assessment coverage" },
  intune: { name: "Microsoft Intune", domains: ["inventory"], capabilities: ["inventory"], storage: "Published platform asset inventory", identity: "Customer, tenant and managed device ID", lifecycle: "Device context only; missing assessments stay unknown" },
  automate: { name: "ConnectWise Automate", domains: ["inventory"], capabilities: ["inventory"], storage: "Published platform asset inventory", identity: "Customer, Automate client and computer ID", lifecycle: "Inventory/context update without creating scanner findings" },
  misp: { name: "MISP", domains: ["enrichment"], capabilities: ["enrichment"], storage: "Saved CVE enrichment joined to customer findings", identity: "CVE and attributed source evidence", lifecycle: "Preserve retained signals; sightings require semantic verification before exploitation claims" },
  opencti: { name: "OpenCTI", domains: ["enrichment"], capabilities: ["enrichment"], storage: "Saved CVE enrichment joined to customer findings", identity: "CVE, STIX object and qualified relationship", lifecycle: "Unrelated relationships are not exploitation; missing/failed lookups are not clean results" },
  intelowl: { name: "IntelOwl", domains: ["enrichment"], capabilities: ["enrichment"], storage: "Saved CVE enrichment joined to customer findings", identity: "CVE, job and analyzer evidence", lifecycle: "Analyzer support and completed evidence required; preserve failures as unavailable" },
  appsec: { name: "AppSec / Trivy", domains: ["appsec"], capabilities: ["appsec"], storage: "Existing AppSec Elasticsearch scan/finding streams", identity: "Repository, scan, tool, location and native issue ID", lifecycle: "Repository findings, secrets and licenses stay separate from endpoint device/CVE counts" },
  connectwise: { name: "ConnectWise PSA", domains: ["ticket-delivery"], capabilities: ["ticket-delivery"], storage: "Existing patch ticket requests, routing, references and audit", identity: "Customer, request, external ticket and coverage", lifecycle: "Preserve uncertain-create reconciliation and manual-only boundaries" },
  n8n: { name: "n8n", domains: ["orchestration"], capabilities: ["orchestration"], storage: "Existing named ingestion contracts and job history", identity: "Workflow, customer and idempotency key", lifecycle: "Orchestration is not an additional findings source; preserve one job owner" },
  qualys: { name: "Qualys", domains: ["endpoint-findings"], capabilities: [], storage: "No implemented production adapter", identity: "Not available", lifecycle: "Preserve planned status; never simulate migration acceptance", planned: true },
} as const satisfies Record<string, Contract>;
export type ConnectorProvider = keyof typeof connectorDataContracts;
export function connectorDataContract(provider: string): Contract | null {
  return Object.hasOwn(connectorDataContracts, provider) ? connectorDataContracts[provider as ConnectorProvider] : null;
}
export function connectorFindingClass(provider: string): "vuln" | "osint" | "pentest" {
  const domains = connectorDataContract(provider)?.domains;
  if (domains?.includes("exposures")) return "osint";
  if (domains?.includes("web-findings")) return "pentest";
  return "vuln"; // Preserve the legacy reporting classification for stored records.
}
