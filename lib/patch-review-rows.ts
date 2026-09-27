import type { PatchGroup } from "./patch-request";

// Saved packets predating reviewRows still carry the complete affected-assets CSV.
export function patchReviewRows(group: PatchGroup): NonNullable<PatchGroup["reviewRows"]> {
  if (group.reviewRows) return group.reviewRows;
  const records: string[][] = [];
  let row: string[] = [], cell = "", quoted = false;
  for (let index = 0; index < group.csv.length; index++) {
    const char = group.csv[index];
    if (char === '"') {
      if (quoted && group.csv[index + 1] === '"') { cell += '"'; index++; }
      else quoted = !quoted;
    } else if (!quoted && char === ",") { row.push(cell); cell = ""; }
    else if (!quoted && (char === "\n" || char === "\r")) {
      if (char === "\r" && group.csv[index + 1] === "\n") index++;
      row.push(cell); records.push(row); row = []; cell = "";
    } else cell += char;
  }
  if (cell || row.length) { row.push(cell); records.push(row); }
  const headers = records.shift()?.map(value => value.replace(/^\uFEFF/, "")) ?? [];
  const field = (values: string[], name: string) => values[headers.indexOf(name)] || "";
  if (!headers.includes("cve")) return group.deviceCves.map(item => ({ asset: item.hostId, cve: item.cve }));
  return records.filter(values => values.some(Boolean)).map(values => {
    const risk = Number(field(values, "risk_score"));
    return {
      asset: field(values, "asset") || field(values, "hostname") || field(values, "host_id"),
      cve: field(values, "cve"), severity: field(values, "severity"),
      risk: field(values, "risk_score") && Number.isFinite(risk) ? risk : undefined,
      connectors: field(values, "connectors") ? field(values, "connectors").split("; ") : group.source === "stored-findings" ? group.connectors : ["CrowdStrike"],
      findingId: field(values, "finding_id"), hostname: field(values, "hostname"), ip: field(values, "local_ip"),
      os: field(values, "operating_system"), criticality: field(values, "host_criticality"), exposure: field(values, "internet_exposure"),
    };
  });
}
