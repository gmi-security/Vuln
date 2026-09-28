import { createHash } from "node:crypto";
import { dashboardCsv } from "./dashboard-csv";
import type { Finding } from "./types";
import type { PatchGroup } from "./patch-request";
import { reportingFindingClass } from "./reporting-metrics";

const clean = (value: string) => value.trim().replace(/\s+/g, " ");
const csvText = (value: string) => value.slice(0, 2000);

// Unstructured scanner text cannot prove that one patch covers several CVEs.
// Group within one CVE and exact action; a reviewer can still consolidate
// assets and corroborating connectors without merging unrelated fixes.
export function buildStoredFindingGroups(company: { id: string; name: string }, findings: Finding[], excluded: Set<string> = new Set()): PatchGroup[] {
  const groups = new Map<string, Finding[]>();
  for (const finding of findings) {
    if (finding.companyId !== company.id || !["Open", "In Remediation"].includes(finding.status)) continue;
    if (reportingFindingClass(finding.connector) === "osint" || !/^CVE-\d{4}-\d{4,19}$/i.test(finding.cve)) continue;
    if (excluded.has(JSON.stringify([company.id, finding.asset, finding.cve]))) continue;
    const action = clean(finding.remediation || "");
    const key = `cve:${finding.cve}:${action.toLowerCase()}`;
    const rows = groups.get(key) ?? [];
    rows.push(finding); groups.set(key, rows);
  }
  return [...groups].flatMap(([key, findingsForAction]) => {
    const ordered = findingsForAction.sort((a, b) => a.id.localeCompare(b.id));
    const parts: PatchGroup[] = [];
    for (let offset = 0; offset < ordered.length; offset += 1000) {
    const rows = ordered.slice(offset, offset + 1000);
    const first = rows[0];
    const action = clean(first.remediation || "") || "Investigate the finding and confirm a safe remediation before scheduling work.";
    const cves = [...new Set(rows.map(row => row.cve))].sort();
    const hostScope = [...new Set(rows.map(row => JSON.stringify([company.id, row.asset])))].sort();
    const connectors = [...new Set(rows.flatMap(row => row.seenBy?.length ? row.seenBy : [row.connector]))].sort();
    const remediationId = createHash("sha256").update(`${company.id}\0${key}`).digest("hex").slice(0, 32);
    const label = (cves.length === 1 ? cves[0] : `${cves[0]}+${cves.length - 1}more`).replace(/[^A-Za-z0-9+-]/g, "-").slice(0, 80);
    const baseTitle = cves.length === 1 ? `${cves[0]} remediation` : `Remediation for ${cves.length} CVEs`;
    const title = ordered.length > 1000 ? `${baseTitle} · batch ${Math.floor(offset / 1000) + 1}` : baseTitle;
    const csv = dashboardCsv({ columns: ["cve", "asset", "severity", "risk_score", "connectors", "finding_id", "remediation"].map(name => ({ name, type: "keyword" })),
      rows: rows.map(row => [csvText(row.cve), csvText(row.asset), row.severity, row.realRisk,
        csvText((row.seenBy?.length ? row.seenBy : [row.connector]).join("; ")), csvText(row.id), csvText(row.remediation)]), truncated: false });
    const ticketBody = ["REMEDIATION REQUEST", "", `Customer: ${company.name} (${company.id})`, `Sources: ${connectors.join(", ")}`,
      `CVEs: ${cves.join(", ")}`, `Affected assets: ${hostScope.length}`, `Open findings: ${rows.length}`, "", "PROPOSED ACTION",
      action, "", "REVIEW BEFORE SENDING", "Confirm asset ownership, the exact fix, change window, and whether another ticket already covers this work.",
      `Affected findings are listed in ${label}-patch-request.csv.`].join("\n");
    parts.push({ source: "stored-findings", appCompanyId: company.id, companyName: company.name, connectors,
      remediationId, tenantId: company.id, title, action, reference: "", vendorUrl: "", link: "", published: "",
      cves, deviceCount: hostScope.length, findingCount: rows.length, hostScope,
      deviceCves: rows.map(row => ({ cid: company.id, hostId: row.asset, cve: row.cve })),
      reviewRows: rows.map(row => ({ asset: row.asset, cve: row.cve, severity: row.severity, risk: row.realRisk,
        connectors: row.seenBy?.length ? row.seenBy : [row.connector], findingId: row.id })),
      csv, label, ticketTitle: `${company.name}: ${title}`.slice(0, 100), ticketBody });
    }
    return parts;
  }).sort((a, b) => b.deviceCount - a.deviceCount || b.findingCount - a.findingCount || a.title.localeCompare(b.title));
}
