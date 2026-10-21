import { createHash } from "node:crypto";
import { dashboardCsv } from "./dashboard-csv";
import type { Finding } from "./types";
import type { PatchGroup } from "./patch-request";
import { reportingFindingClass } from "./reporting-metrics";
import { worstSeverityOf } from "./vuln-sla";
import { requiresConsolidationManualReview } from "./customer-consolidation-hold";
import type { DefenderRecord } from "./defender-client";
import type { TicketedPairs } from "./patch-coverage";

export type DefenderPatchUpdate = Pick<DefenderRecord, "softwareVendor" | "softwareName" | "softwareVersion" | "remediation" | "remediationId">;

const clean = (value: string) => value.trim().replace(/\s+/g, " ");
const csvText = (value: string) => value.slice(0, 2000);

// Unstructured scanner text cannot prove that one patch covers several CVEs.
// Group within one CVE and exact action; a reviewer can still consolidate
// assets and corroborating connectors without merging unrelated fixes.
export function buildStoredFindingGroups(company: { id: string; name: string }, findings: Finding[], excluded: Set<string> = new Set(), defenderUpdates = new Map<string, DefenderPatchUpdate[]>()): PatchGroup[] {
  const groups = new Map<string, { finding: Finding; updates: DefenderPatchUpdate[] }[]>();
  for (const finding of findings) {
    if (finding.companyId !== company.id || !["Open", "In Remediation"].includes(finding.status)) continue;
    if (reportingFindingClass(finding.connector) === "osint" || !/^CVE-\d{4}-\d{4,19}$/i.test(finding.cve)) continue;
    if (excluded.has(JSON.stringify([company.id, finding.asset, finding.cve]))) continue;
    const updates = defenderUpdates.get(finding.id);
    const actions = new Map<string, DefenderPatchUpdate[]>();
    // Only structured, complete Defender evidence proves that installed builds share a fix.
    if (finding.connector === "defender" && finding.defender?.active && !finding.defender.otherRemediation &&
        !finding.seenBy?.some(source => source !== "defender") && updates?.length &&
        updates.every(row => [row.softwareVendor, row.softwareName, row.remediation, row.remediationId].every(value => typeof value === "string" && value.trim()))) {
      for (const update of updates) {
        const key = `defender:${JSON.stringify([finding.cve, update.softwareVendor, update.softwareName, update.remediationId, update.remediation].map(value => clean(value).toLowerCase()))}`;
        const members = actions.get(key) ?? [];
        members.push(update); actions.set(key, members);
      }
    } else actions.set(`cve:${finding.cve}:${clean(finding.remediation || "").toLowerCase()}`, []);
    for (const [key, updates] of actions) {
      const actionId = createHash("sha256").update(`${company.id}\0${key}`).digest("hex").slice(0, 32);
      if (updates.length && typeof (excluded as TicketedPairs).hasAction === "function" && (excluded as TicketedPairs).hasAction(company.id, finding.asset, finding.cve, actionId)) continue;
      const rows = groups.get(key) ?? [];
      rows.push({ finding, updates }); groups.set(key, rows);
    }
  }
  return [...groups].flatMap(([key, findingsForAction]) => {
    const ordered = findingsForAction.sort((a, b) => a.finding.id.localeCompare(b.finding.id));
    const parts: PatchGroup[] = [];
    for (let offset = 0; offset < ordered.length; offset += 1000) {
    const entries = ordered.slice(offset, offset + 1000);
    const rows = entries.map(row => row.finding);
    const first = rows[0];
    const update = entries[0].updates[0];
    const product = update ? clean(update.softwareName).replace(/_/g, " ").replace(/\b\w/g, letter => letter.toUpperCase()) : "";
    const reference = update ? (update.softwareVendor.toLowerCase() === "microsoft" && /^(?:KB)?\d+$/i.test(update.remediationId)
      ? `KB${update.remediationId.replace(/^KB/i, "")}` : update.remediationId) : "";
    const action = update ? `Install ${reference} for ${product}: ${clean(update.remediation)}`
      : clean(first.remediation || "") || "Investigate the finding and confirm a safe remediation before scheduling work.";
    const cves = [...new Set(rows.map(row => row.cve))].sort();
    const hostScope = [...new Set(rows.map(row => JSON.stringify([company.id, row.asset])))].sort();
    const connectors = [...new Set(rows.flatMap(row => row.seenBy?.length ? row.seenBy : [row.connector]))].sort();
    const remediationId = createHash("sha256").update(`${company.id}\0${key}`).digest("hex").slice(0, 32);
    const label = (cves.length === 1 ? cves[0] : `${cves[0]}+${cves.length - 1}more`).replace(/[^A-Za-z0-9+-]/g, "-").slice(0, 80);
    const baseTitle = update ? `${product} — Install ${reference}` : cves.length === 1 ? `${cves[0]} remediation` : `Remediation for ${cves.length} CVEs`;
    const title = ordered.length > 1000 ? `${baseTitle} · batch ${Math.floor(offset / 1000) + 1}` : baseTitle;
    const csv = dashboardCsv({ columns: ["cve", "asset", "hostname", "severity", "cvss", "risk_score", "connectors", "finding_id", "remediation",
      ...(update ? ["software_vendor", "software_product", "installed_versions", "recommended_update", "update_id"] : [])].map(name => ({ name, type: "keyword" })),
      rows: entries.map(({ finding: row, updates }) => [csvText(row.cve), csvText(row.asset), csvText(row.defender?.hostname || row.asset), row.severity, row.cvss, row.realRisk,
        csvText((row.seenBy?.length ? row.seenBy : [row.connector]).join("; ")), csvText(row.id), csvText(update ? action : row.remediation),
        ...(update ? [update.softwareVendor, update.softwareName, [...new Set(updates.map(item => item.softwareVersion))].sort().join("; "), update.remediation, reference] : [])]), truncated: false });
    const ticketBody = ["REMEDIATION REQUEST", "", `Customer: ${company.name} (${company.id})`, `Sources: ${connectors.join(", ")}`,
      `CVEs: ${cves.join(", ")}`, `Affected assets: ${hostScope.length}`, `Open findings: ${rows.length}`, "", "PROPOSED ACTION",
      action, "", "REVIEW BEFORE SENDING", "Confirm asset ownership, the exact fix, change window, and whether another ticket already covers this work.",
      `Affected findings are listed in ${label}-patch-request.csv.`].join("\n");
    parts.push({ source: "stored-findings", appCompanyId: company.id, companyName: company.name, connectors,
      ...(requiresConsolidationManualReview(company.id) ? { manualOnly: true } : {}),
      remediationId, tenantId: company.id, title, action, reference, vendorUrl: "", link: "", published: "",
      cves, deviceCount: hostScope.length, findingCount: rows.length, hostScope,
      deviceCves: rows.map(row => ({ cid: company.id, hostId: row.asset, cve: row.cve })),
      ...(update ? { deviceCveCoverage: { cves, hosts: hostScope.map(value => {
        const [cid, hostId] = JSON.parse(value) as [string, string];
        return { cid, hostId, bits: "AQ==" };
      }) } } : {}),
      reviewRows: rows.map(row => ({ asset: row.asset, hostname:row.defender?.hostname || row.asset, cve: row.cve, severity: row.severity, risk: row.realRisk,
        connectors: row.seenBy?.length ? row.seenBy : [row.connector], findingId: row.id })),
      worstSeverity: worstSeverityOf(rows),
      maxRisk: Math.max(0, ...rows.map(row => row.realRisk)),
      csv, label, ticketTitle: `${company.name}: ${title}`.slice(0, 100), ticketBody });
    }
    return parts;
  }).sort((a, b) => b.deviceCount - a.deviceCount || b.findingCount - a.findingCount || a.title.localeCompare(b.title));
}
