import type { SlaSettings } from "./types";

export type ReportingKevCatalog = {
  version: 1;
  cves: string[];
  ransomware: string[];
  refreshedAt: string | null;
};
export function validateReportingCatalog(value: unknown): asserts value is ReportingKevCatalog {
  const c = value as ReportingKevCatalog | null;
  const valid = (rows: unknown): rows is string[] => Array.isArray(rows) && rows.length <= 100_000 &&
    rows.every((id, i) => typeof id === "string" && /^CVE-\d{4}-\d{4,19}$/.test(id) && (i === 0 || rows[i - 1] < id));
  if (!c || c.version !== 1 || !valid(c.cves) || !valid(c.ransomware) ||
      (c.refreshedAt !== null && !Number.isFinite(Date.parse(c.refreshedAt))))
    throw new Error("Saved reporting KEV catalog is missing or invalid");
  const ids = new Set(c.cves);
  if (c.ransomware.some(id => !ids.has(id))) throw new Error("Saved ransomware catalog is inconsistent");
}
export function validateReportingSla(value: unknown): asserts value is SlaSettings {
  const s = value as SlaSettings | null;
  if (!s || !(["Critical", "High", "Medium", "Low"] as const).every(k => Number.isFinite(s[k]) && s[k] >= 0 && s[k] <= 3650))
    throw new Error("Saved reporting SLA policy is missing or invalid");
}
