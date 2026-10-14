import { DashboardError } from "./elastic-dashboard";
import { normalizeVulnerability, type Vulnerability } from "./crowdstrike-dashboard";

export type Remediation = {
  id: string; title: string; action: string; link: string; vendorUrl: string;
  reference: string; recommendationType: string; published: string;
};
export type PatchApp = { vendor: string; product: string; version: string; ids: string[]; recommended: string; minimum: string };
export type PatchFinding = Vulnerability & {
  ip: string; os: string; hostCriticality: string; exposure: string; suppressed: boolean | null;
  description: string; vector: string; exploitability: number | null; impact: number | null;
  published: string; references: string[]; apps: PatchApp[]; remediations: Remediation[];
};
type Json = Record<string, any>;
const text = (value: unknown): string => typeof value === "string" ? value.replace(/[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/g, "") : "";
const list = (value: unknown): string[] => Array.isArray(value) ? [...new Set(value.map(text).filter(Boolean))] : [];
const num = (value: unknown): number | null => typeof value === "number" && Number.isFinite(value) ? value : null;

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

