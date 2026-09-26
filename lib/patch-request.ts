import { DashboardError, type QueryResult } from "./elastic-dashboard";
import { normalizeVulnerability, type Vulnerability } from "./crowdstrike-dashboard";
import { dashboardCsv } from "./dashboard-csv";

export type PatchRequest = {
  cve: string; collectedAt: string; region: string; hostCount: number; findingCount: number;
  csvRows: number; title: string; body: string; csv: string; warnings: string[];
  tenantIds: string[]; hostScope: string[];
};
export type Remediation = {
  id: string; title: string; action: string; link: string; vendorUrl: string;
  reference: string; recommendationType: string; published: string;
};
type PatchApp = { vendor: string; product: string; version: string; ids: string[]; recommended: string; minimum: string };
export type PatchFinding = Vulnerability & {
  ip: string; os: string; hostCriticality: string; exposure: string; suppressed: boolean | null;
  description: string; vector: string; exploitability: number | null; impact: number | null;
  published: string; references: string[]; apps: PatchApp[]; remediations: Remediation[];
};
type Json = Record<string, any>;
const text = (value: unknown): string => typeof value === "string" ? value.replace(/[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/g, "") : "";
const list = (value: unknown): string[] => Array.isArray(value) ? [...new Set(value.map(text).filter(Boolean))] : [];
const num = (value: unknown): number | null => typeof value === "number" && Number.isFinite(value) ? value : null;
const shown = (value: unknown): string => value === null || value === undefined || value === "" ? "Not supplied" : String(value);

export function parsePatchInput(value: unknown): { source: "crowdstrike"; cve: string; tenantId?: string } {
  const cve = (value as { cve?: unknown } | null)?.cve;
  if (typeof cve !== "string" || !/^CVE-\d{4}-\d{4,19}$/i.test(cve)) throw new DashboardError("Choose a valid CVE identifier.");
  const tenantId = (value as { tenantId?: unknown }).tenantId;
  if (tenantId !== undefined && (typeof tenantId !== "string" || !/^[a-f0-9]{32}$/i.test(tenantId))) throw new DashboardError("Choose a valid CrowdStrike tenant.");
  return { source: "crowdstrike", cve: cve.toUpperCase(), ...(typeof tenantId === "string" ? { tenantId: tenantId.toLowerCase() } : {}) };
}

export function parseConsolidationInput(value: unknown): { source: "crowdstrike"; cves: string[]; tenantId?: string } {
  const cves = (value as { cves?: unknown } | null)?.cves;
  if (!Array.isArray(cves) || cves.length < 2 || cves.length > 12) throw new DashboardError("Choose 2 to 12 CVEs to consolidate.");
  const normalized = cves.map((c) => (typeof c === "string" ? c.toUpperCase() : ""));
  if (normalized.some((c) => !/^CVE-\d{4}-\d{4,19}$/.test(c))) throw new DashboardError("Choose valid CVE identifiers.");
  const unique = [...new Set(normalized)];
  if (unique.length !== normalized.length) throw new DashboardError("Remove duplicate CVEs before consolidating.");
  const tenantId = (value as { tenantId?: unknown } | null)?.tenantId;
  if (tenantId !== undefined && (typeof tenantId !== "string" || !/^[a-f0-9]{32}$/i.test(tenantId))) throw new DashboardError("Choose a valid CrowdStrike tenant.");
  return { source: "crowdstrike", cves: unique, ...(typeof tenantId === "string" ? { tenantId: tenantId.toLowerCase() } : {}) };
}

export function parseVerifyInput(value: unknown): { source: "crowdstrike"; ticketKind: "cve" | "group"; ticketId: string } {
  const body = value as { ticketKind?: unknown; ticketId?: unknown } | null;
  const ticketKind = body?.ticketKind;
  if (ticketKind !== "cve" && ticketKind !== "group") throw new DashboardError("Choose a valid ticket type to verify.");
  const ticketId = body?.ticketId;
  if (typeof ticketId !== "string" || !/^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/i.test(ticketId)) throw new DashboardError("Choose a valid ticket to verify.");
  return { source: "crowdstrike", ticketKind, ticketId };
}

export type PatchGroup = {
  remediationId: string; tenantId: string; title: string; action: string; reference: string;
  vendorUrl: string; link: string; published: string;
  cves: string[]; deviceCount: number; findingCount: number; hostScope: string[]; csv: string;
  deviceCves: { cid: string; hostId: string; cve: string }[];
  label: string; ticketTitle: string; ticketBody: string;
};
export type PatchConsolidation = {
  cves: string[]; region: string; collectedAt: string; totalDevices: number; totalFindings: number;
  tenantIds: string[]; title: string; body: string; csv: string; groups: PatchGroup[]; unmapped: { cve: string; deviceCount: number }[];
  alreadyTicketedFindings: number;
};

export function normalizeRemediation(raw: Json): Remediation {
  if (!raw || typeof raw !== "object" || !text(raw.id)) throw new DashboardError("CrowdStrike returned an invalid remediation. No patch request was prepared.");
  return { id: text(raw.id), title: text(raw.title), action: text(raw.action), link: text(raw.link), vendorUrl: text(raw.vendor_url),
    reference: text(raw.reference), recommendationType: text(raw.recommendation_type), published: text(raw.patch_publication_date) };
}

// The application's explicit recommendation takes precedence over entity tags.
// Without it, accept only explicitly recommended entities mapped to this app.
export function recommendedRemediationIds(app: PatchApp | undefined, remediations: Remediation[]): string[] {
  if (app?.recommended) return [app.recommended];
  return [...new Set(remediations.filter(r => r.recommendationType.toLowerCase() === "recommended" && (!app || app.ids.includes(r.id))).map(r => r.id))];
}

export function patchRecommendationIds(row: PatchFinding): string[] {
  return [...new Set(row.apps.length ? row.apps.flatMap(app => recommendedRemediationIds(app, row.remediations)) : recommendedRemediationIds(undefined, row.remediations))];
}

export function normalizePatchFinding(raw: Json, cve: string): PatchFinding {
  const row = normalizeVulnerability(raw);
  if (row.cve.toUpperCase() !== cve || !["open", "reopen"].includes(row.status)) throw new DashboardError("CrowdStrike returned a finding outside the requested CVE/open scope. Retry the request.");
  if (!row.hostId || !row.cid) throw new DashboardError("A finding is missing its tenant or host ID. A complete affected-host list cannot be prepared.");
  if (raw.apps !== undefined && !Array.isArray(raw.apps)) throw new DashboardError("CrowdStrike returned invalid application details.");
  if (raw.remediation?.entities !== undefined && !Array.isArray(raw.remediation.entities)) throw new DashboardError("CrowdStrike returned invalid remediation details.");
  const host = raw.host_info ?? {}, info = raw.cve ?? {};
  return { ...row, cve, ip: text(host.local_ip), os: text(host.os_version), hostCriticality: text(host.asset_criticality), exposure: text(host.internet_exposure),
    suppressed: typeof raw.suppression_info?.is_suppressed === "boolean" ? raw.suppression_info.is_suppressed : null,
    description: text(info.description || info.original_description), vector: text(info.vector), exploitability: num(info.exploitability_score), impact: num(info.impact_score),
    published: text(info.published_date), references: [...new Set([...list(info.references), ...list(info.vendor_advisory)])],
    apps: (raw.apps ?? []).map((app: Json) => ({ vendor: text(app.vendor_normalized), product: text(app.product_name_normalized), version: text(app.product_name_version),
      ids: [...new Set([...list(app.remediation?.ids), text(app.remediation_info?.recommended_id), text(app.remediation_info?.minimum_id)].filter(Boolean))],
      recommended: text(app.remediation_info?.recommended_id), minimum: text(app.remediation_info?.minimum_id) })),
    remediations: (raw.remediation?.entities ?? []).map(normalizeRemediation) };
}

export function buildPatchRequest(cve: string, records: PatchFinding[], region: string, startedAt: string, collectedAt: string): PatchRequest {
  if (!records.length) throw new DashboardError("CrowdStrike currently reports no open/reopened findings for this CVE. No patch request was prepared.");
  const hosts = new Map<string, PatchFinding>(), remedies = new Map<string, Remediation>();
  const warnings = new Set<string>(), csvRows: QueryResult["rows"] = [];
  const names = ["cve", "tenant_id", "host_id", "hostname", "local_ip", "operating_system", "host_criticality", "internet_exposure", "finding_id", "status", "suppressed",
    "severity", "cvss_base_score", "cvss_vector", "exprt_rating", "exploit_status", "exploitability_score", "impact_score", "cisa_kev", "gmi_priority", "gmi_risk_score",
    "application_vendor", "application_product", "application_version", "remediation_id", "remediation_mapping", "recommended_remediation_id",
    "remediation_title", "remediation_action", "remediation_reference", "remediation_url", "vendor_url", "recommendation_type", "patch_published_at", "finding_updated_at", "collected_at"];
  const ordered = [...records].sort((a, b) => a.cid.localeCompare(b.cid) || a.hostname.localeCompare(b.hostname) || a.hostId.localeCompare(b.hostId) || a.id.localeCompare(b.id));
  for (const row of ordered) {
    const hostKey = JSON.stringify([row.cid, row.hostId]), previousHost = hosts.get(hostKey);
    if (!previousHost || Date.parse(row.updated) > Date.parse(previousHost.updated)) hosts.set(hostKey, row);
    const localRemedies = new Map(row.remediations.map((r) => [r.id, r]));
    for (const id of patchRecommendationIds(row)) {
      const remediation = localRemedies.get(id);
      if (!remediation) continue;
      const key = JSON.stringify([row.cid, remediation.id]);
      const old = remedies.get(key);
      if (old && JSON.stringify(old) !== JSON.stringify(remediation)) throw new DashboardError("Remediation details changed during collection. Retry to prepare a consistent request.");
      remedies.set(key, remediation);
    }
    if (!row.hostname) warnings.add("Some hostnames were not supplied. Use the tenant and host IDs in the CSV to identify those devices.");
    if (row.suppressed === true) warnings.add("Suppressed findings are included and marked in the CSV. Review suppression decisions before scheduling their patches.");
    if (row.suppressed === null) warnings.add("Suppression status was not supplied for some findings; review those entries in Falcon.");
    const apps: PatchApp[] = row.apps.length ? row.apps : [{ vendor: "", product: "", version: "", ids: row.remediations.map((r) => r.id), recommended: "", minimum: "" }];
    for (const app of apps) {
      const recommendations = recommendedRemediationIds(row.apps.length ? app : undefined, row.remediations);
      const ids = recommendations.length ? recommendations : [""];
      for (const id of ids) {
        const remediation = localRemedies.get(id);
        if (!id || !remediation?.action) warnings.add("CrowdStrike did not supply an actionable recommended remediation for some application entries. These are marked in the CSV; review them in Falcon before patching.");
        const mapping = !id ? "No recommended remediation supplied" : row.apps.length ? "Recommended application remediation" : "Recommended finding-level remediation (application not supplied)";
        csvRows.push([row.cve, row.cid, row.hostId, row.hostname || null, row.ip || null, row.os || null, row.hostCriticality || null, row.exposure || null, row.id, row.status, row.suppressed,
          row.severity, row.cvss, row.vector || null, row.exprt, row.exploit, row.exploitability, row.impact, row.kev, row.priority, row.risk,
          app.vendor || null, app.product || null, app.version || null, id || null, mapping, id || null,
          remediation?.title || null, remediation?.action || null, remediation?.reference || null, remediation?.link || null, remediation?.vendorUrl || null,
          id ? "recommended" : null, remediation?.published || null, row.updated || null, collectedAt]);
      }
    }
  }
  const values = (get: (r: PatchFinding) => unknown) => [...new Set(ordered.map(get).map(shown))].join(", ");
  const max = (get: (r: PatchFinding) => number | null) => ordered.reduce<number | null>((highest, row) => { const value = get(row); return value === null ? highest : highest === null ? value : Math.max(highest, value); }, null);
  const severities = values((r) => r.severity);
  const title = `Patch request: ${cve} | ${severities} | ${hosts.size} affected hosts`;
  const remediationText = [...remedies].map(([key, r]) => {
    const [cid] = JSON.parse(key);
    return [`- ${r.id} — ${shown(r.title)} (tenant ${cid})`, `  Action: ${shown(r.action)}`, `  Type: Recommended; reference: ${shown(r.reference)}`,
      `  Source: ${shown(r.link)}; vendor: ${shown(r.vendorUrl)}`, `  Patch published: ${shown(r.published)}`].join("\n");
  });
  const descriptions = [...new Set(ordered.map((r) => r.description).filter(Boolean))];
  const references = [...new Set(ordered.flatMap((r) => r.references))];
  const body = ["PATCH REQUEST — MANUAL CONNECTWISE ENTRY", "", `CVE: ${cve}`, `Source: CrowdStrike Spotlight (${region.toUpperCase()})`,
    `Collection started: ${startedAt}`, `Collection completed: ${collectedAt}`, `Scope: All open/reopened findings for this CVE visible to the connected CrowdStrike API client, including suppressed findings. Dashboard filters and top-N limits are not applied.`,
    `Affected hosts: ${hosts.size} (unique tenant + host ID)`, `Open/reopened findings: ${ordered.length}`, `CSV rows: ${csvRows.length} (finding/application/remediation mappings; a host may appear more than once)`,
    "", "CRITICALITY AND SCORES", `CVE severity: ${severities}`, `CVSS base score(s): ${values((r) => r.cvss)}`, `CVSS vector(s): ${values((r) => r.vector)}`,
    `CrowdStrike ExPRT rating(s): ${values((r) => r.exprt)}`, `Exploit status code(s): ${values((r) => r.exploit)}`, `Exploitability score(s): ${values((r) => r.exploitability)}`, `Impact score(s): ${values((r) => r.impact)}`,
    `CISA KEV: ${values((r) => r.kev)}`, `GMI custom priority: ${values((r) => r.priority)}`, `Maximum GMI custom risk score: ${shown(max((r) => r.risk))} / 100 (GMI policy, not a CrowdStrike score)`,
    "", "DESCRIPTION", descriptions.join("\n\n") || "Not supplied by CrowdStrike.", "", "PATCH TEAM ACTIONS",
    "1. Review each host/application entry in the attached CSV and confirm ownership and the maintenance window.",
    "2. Apply the recommended CrowdStrike remediation mapped to each application in the CSV. The ticket lists all applicable recommendations; minimum-only alternatives are excluded.",
    "3. Review suppressed findings and entries with missing remediation before scheduling work.",
    "4. After patching and any required restart, verify the findings are closed in Falcon and record the outcome in this ticket.",
    "", "RECOMMENDED REMEDIATIONS FROM CROWDSTRIKE", remediationText.join("\n\n") || "No recommended remediation was supplied. Manual investigation is required.",
    "", "AFFECTED ASSETS", `See the attached ${cve}-patch-request.csv for the complete asset list and per-application recommended remediations.`, "", "SOURCE REFERENCES", references.join("\n") || "Not supplied.",
    "", "COLLECTION NOTES", "All matching pages were collected. This is a paginated observation, not an atomic CrowdStrike snapshot. Counts can differ from the cached dashboard.",
    ...warnings, `Attach ${cve}-patch-request.csv. No ticket has been sent to ConnectWise.`].join("\n");
  const csv = dashboardCsv({ columns: names.map((name) => ({ name, type: "keyword" })), rows: csvRows, truncated: false });
  const packet: PatchRequest = { cve, collectedAt, region, hostCount: hosts.size, findingCount: records.length, csvRows: csvRows.length, title, body, csv, warnings: [...warnings],
    tenantIds: [...new Set(ordered.map(row => row.cid))].sort(), hostScope: [...hosts.keys()].sort() };
  if (new TextEncoder().encode(JSON.stringify(packet)).length > 32 * 1024 * 1024) throw new DashboardError("This patch request exceeds the 32 MiB export limit. No partial export was prepared.");
  return packet;
}

// Groups open findings across several CVEs by the single CrowdStrike remediation
// that resolves them, so one patch/deployment covering several CVEs and many
// devices is not mistaken for several unrelated fixes. Ranked by devices
// reached per remediation action (highest impact for one maintenance action
// first), then by how many of the requested CVEs that same action clears.
export function buildPatchConsolidation(cves: string[], records: PatchFinding[], region: string, startedAt: string, collectedAt: string, alreadyTicketed: Set<string> = new Set()): PatchConsolidation {
  if (!records.length) throw new DashboardError("CrowdStrike currently reports no open/reopened findings for these CVEs. No consolidation was prepared.");
  type GroupRow = { cid: string; hostId: string; hostname: string; ip: string; os: string; hostCriticality: string; exposure: string; cve: string };
  type GroupAcc = { tenantId: string; remediation: Remediation; cves: Set<string>; devices: Set<string>; findings: Set<string>; rows: Map<string, GroupRow> };
  const groups = new Map<string, GroupAcc>();
  const devicesByCve = new Map<string, Set<string>>();
  const mappedCves = new Set<string>();
  let alreadyTicketedFindings = 0;
  const ordered = [...records].sort((a, b) => a.cve.localeCompare(b.cve) || a.cid.localeCompare(b.cid) || a.hostname.localeCompare(b.hostname) || a.id.localeCompare(b.id));
  for (const row of ordered) {
    const deviceKey = JSON.stringify([row.cid, row.hostId]);
    const cveDevices = devicesByCve.get(row.cve) ?? new Set<string>();
    cveDevices.add(deviceKey); devicesByCve.set(row.cve, cveDevices);
    const localRemedies = new Map(row.remediations.map((r) => [r.id, r]));
    for (const id of patchRecommendationIds(row)) {
      const remediation = localRemedies.get(id);
      if (!remediation?.action) continue;
      mappedCves.add(row.cve);
      const rowKey = JSON.stringify([row.cid, row.hostId, row.cve]);
      if (alreadyTicketed.has(rowKey)) { alreadyTicketedFindings++; continue; }
      const key = JSON.stringify([row.cid, remediation.id]);
      const existing = groups.get(key);
      if (existing) {
        if (JSON.stringify(existing.remediation) !== JSON.stringify(remediation)) throw new DashboardError("Remediation details changed during collection. Retry to prepare a consistent consolidation.");
        existing.cves.add(row.cve); existing.devices.add(deviceKey); existing.findings.add(JSON.stringify([row.cid, row.id]));
        existing.rows.set(rowKey, { cid: row.cid, hostId: row.hostId, hostname: row.hostname, ip: row.ip, os: row.os, hostCriticality: row.hostCriticality, exposure: row.exposure, cve: row.cve });
      } else {
        groups.set(key, { tenantId: row.cid, remediation, cves: new Set([row.cve]), devices: new Set([deviceKey]), findings: new Set([JSON.stringify([row.cid, row.id])]),
          rows: new Map([[rowKey, { cid: row.cid, hostId: row.hostId, hostname: row.hostname, ip: row.ip, os: row.os, hostCriticality: row.hostCriticality, exposure: row.exposure, cve: row.cve }]]) });
      }
    }
  }
  const groupCsvNames = ["cve", "tenant_id", "host_id", "hostname", "local_ip", "operating_system", "host_criticality", "internet_exposure"];
  const groupList: PatchGroup[] = [...groups.values()].map((g) => {
    const groupRows = [...g.rows.values()].sort((a, b) => a.cve.localeCompare(b.cve) || a.hostname.localeCompare(b.hostname) || a.hostId.localeCompare(b.hostId));
    const csv = dashboardCsv({ columns: groupCsvNames.map((name) => ({ name, type: "keyword" })),
      rows: groupRows.map((r) => [r.cve, r.cid, r.hostId, r.hostname || null, r.ip || null, r.os || null, r.hostCriticality || null, r.exposure || null]), truncated: false });
    const sortedCves = [...g.cves].sort(), deviceCount = g.devices.size, findingCount = g.findings.size;
    const label = (sortedCves.length === 1 ? sortedCves[0] : `${sortedCves[0]}+${sortedCves.length - 1}more`).slice(0, 80);
    const ticketTitle = `Patch ${sortedCves.length === 1 ? sortedCves[0] : `${sortedCves.length} CVEs`} | ${deviceCount.toLocaleString()} affected devices`.slice(0, 100);
    const ticketBody = ["PATCH REQUEST — MANUAL CONNECTWISE ENTRY", "",
      `CVEs resolved by this patch: ${sortedCves.join(", ")}`, `CrowdStrike tenant: ${g.tenantId}`, `Source: CrowdStrike Spotlight (${region.toUpperCase()})`,
      `Collection started: ${startedAt}`, `Collection completed: ${collectedAt}`,
      `Affected devices: ${deviceCount.toLocaleString()}`, `Open findings closed: ${findingCount.toLocaleString()}`,
      "", "RECOMMENDED REMEDIATION", shown(g.remediation.title), `Action: ${shown(g.remediation.action)}`,
      `Type: Recommended; reference: ${shown(g.remediation.reference)}`, `Source: ${shown(g.remediation.link)}; vendor: ${shown(g.remediation.vendorUrl)}`, `Patch published: ${shown(g.remediation.published)}`,
      "", "PATCH TEAM ACTIONS", "1. Review each device in the attached CSV and confirm ownership and the maintenance window.",
      "2. Apply the recommended remediation above. It resolves every CVE listed above on the same device.",
      "3. After patching and any required restart, verify the findings are closed in Falcon and record the outcome in this ticket.",
      "", "AFFECTED ASSETS", `See the attached ${label}-patch-request.csv for the complete device list (one row per device/CVE pair).`,
      "", "COLLECTION NOTES", "All matching pages were collected per CVE. This is a paginated observation, not an atomic CrowdStrike snapshot.",
      `Attach ${label}-patch-request.csv. No ticket has been sent to ConnectWise.`].join("\n");
    return { remediationId: g.remediation.id, tenantId: g.tenantId, title: g.remediation.title, action: g.remediation.action,
      reference: g.remediation.reference, vendorUrl: g.remediation.vendorUrl, link: g.remediation.link, published: g.remediation.published,
      cves: sortedCves, deviceCount, findingCount, hostScope: [...g.devices].sort(),
      deviceCves: groupRows.map((r) => ({ cid: r.cid, hostId: r.hostId, cve: r.cve })), csv, label, ticketTitle, ticketBody };
  }).sort((a, b) => b.deviceCount - a.deviceCount || b.cves.length - a.cves.length || a.remediationId.localeCompare(b.remediationId));
  const unmapped = cves.filter((c) => !mappedCves.has(c)).map((c) => ({ cve: c, deviceCount: devicesByCve.get(c)?.size ?? 0 }));
  const totalDevices = new Set(ordered.map((r) => JSON.stringify([r.cid, r.hostId]))).size;
  const totalFindings = ordered.length;
  const tenantIds = [...new Set(ordered.map((r) => r.cid))].sort();
  const title = `Patch consolidation: ${cves.length} CVEs → ${groupList.length} patch action${groupList.length === 1 ? "" : "s"} · ${totalDevices.toLocaleString()} devices`;
  const rank = groupList.map((g, index) => {
    const share = totalDevices > 0 ? Math.round((g.deviceCount / totalDevices) * 1000) / 10 : 0;
    return [`${index + 1}. ${shown(g.title)} (remediation ${g.remediationId}, tenant ${g.tenantId})`,
      `   Resolves: ${g.cves.join(", ")}`,
      `   Devices reached: ${g.deviceCount.toLocaleString()} (${share}% of all devices affected by the requested CVEs) · Findings closed: ${g.findingCount.toLocaleString()}`,
      `   Action: ${shown(g.action)}`,
      `   Reference: ${shown(g.reference)} · Vendor: ${shown(g.vendorUrl)} · Source: ${shown(g.link)} · Published: ${shown(g.published)}`].join("\n");
  });
  const body = ["PATCH CONSOLIDATION REPORT — MOST DEVICES CLEARED PER PATCH ACTION", "",
    `CVEs requested: ${cves.join(", ")}`, `Source: CrowdStrike Spotlight (${region.toUpperCase()})`,
    `Collection started: ${startedAt}`, `Collection completed: ${collectedAt}`,
    "Scope: All open/reopened findings for these CVEs visible to the connected CrowdStrike API client, including suppressed findings.",
    `Unique devices affected across all requested CVEs: ${totalDevices.toLocaleString()}`, `Open/reopened findings: ${totalFindings.toLocaleString()}`,
    `Distinct patch actions needed to cover the mapped CVEs: ${groupList.length}`,
    `CrowdStrike tenants (CIDs) represented: ${tenantIds.length} — ${tenantIds.join(", ")}`,
    ...(alreadyTicketedFindings ? [`${alreadyTicketedFindings.toLocaleString()} finding(s) already covered by an active ConnectWise ticket were excluded from the plan below — see the ticket tracker for their status.`] : []),
    ...(tenantIds.length > 1 ? ["This report spans more than one tenant. Each ranked action below is scoped to a single tenant (shown in its heading); do not combine devices across tenants into one ticket or maintenance window."] : []),
    "", "HOW TO READ THIS", "Each entry below is one CrowdStrike-recommended remediation (one patch/update/config change), scoped to one tenant, and excludes any device/CVE pair already covered by an active ticket. Ranked by how many devices a single action clears, then by how many of the requested CVEs it also resolves — the fastest way to shrink this list is to work top to bottom.",
    "", "RANKED PATCH ACTIONS", rank.join("\n\n") || "CrowdStrike did not supply an actionable recommended remediation for any requested CVE. Manual investigation is required.",
    ...(unmapped.length ? ["", "CVEs WITHOUT A MAPPED REMEDIATION", "CrowdStrike did not supply an actionable recommended remediation for these CVEs (or no open findings were found). Review them individually in Falcon.",
      ...unmapped.map((u) => `- ${u.cve} (${u.deviceCount.toLocaleString()} affected device${u.deviceCount === 1 ? "" : "s"})`)] : []),
    "", "COLLECTION NOTES", "All matching pages were collected per CVE. This is a paginated observation, not an atomic CrowdStrike snapshot. A device or finding can appear in more than one patch action when it needs more than one fix.",
    "No ticket has been sent to ConnectWise and no patching has been started."].join("\n");
  const names = ["rank", "remediation_id", "tenant_id", "cves_resolved", "device_count", "finding_count", "share_of_devices_pct", "title", "action", "reference", "vendor_url", "source_url", "patch_published_at"];
  const csvRows: QueryResult["rows"] = groupList.map((g, index) => [index + 1, g.remediationId, g.tenantId, g.cves.join("; "), g.deviceCount, g.findingCount,
    totalDevices > 0 ? Math.round((g.deviceCount / totalDevices) * 1000) / 10 : 0, g.title || null, g.action || null, g.reference || null, g.vendorUrl || null, g.link || null, g.published || null]);
  const csv = dashboardCsv({ columns: names.map((name) => ({ name, type: ["rank", "device_count", "finding_count"].includes(name) ? "long" : name === "share_of_devices_pct" ? "double" : "keyword" })), rows: csvRows, truncated: false });
  const consolidation: PatchConsolidation = { cves, region, collectedAt, totalDevices, totalFindings, tenantIds, title, body, csv, groups: groupList, unmapped, alreadyTicketedFindings };
  if (new TextEncoder().encode(JSON.stringify(consolidation)).length > 32 * 1024 * 1024) throw new DashboardError("This consolidation exceeds the 32 MiB export limit. No partial export was prepared.");
  return consolidation;
}
