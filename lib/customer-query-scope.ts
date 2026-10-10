import { DashboardError } from "./elastic-dashboard";
// User filters must remain entirely inside the server's CID conjunction. This
// lexical check rejects unbalanced grouping/quotes and unsupported escapes; it
// does not replace the vendor's syntax validation or interpret business filters.
export function customerFql(query: string, cid: string): string {
  if (!/^[a-f0-9]{32}$/i.test(cid)) throw new DashboardError("Invalid reviewed CrowdStrike CID.");
  const stack: string[] = []; let quoted = false;
  for (let i = 0; i < query.length; i++) {
    const c = query[i];
    if (quoted) {
      if (c === "\\") { if (!query[i+1] || !["'", "\\"].includes(query[++i])) throw new DashboardError("Unsupported FQL string escape."); }
      else if (c === "'") quoted = false;
      continue;
    }
    if (c === "'") { quoted = true; continue; }
    if (c === "(" || c === "[") stack.push(c);
    else if (c === ")" || c === "]") {
      if (stack.pop() !== (c === ")" ? "(" : "[")) throw new DashboardError("Unbalanced FQL filter.");
    } else if (!/[a-zA-Z0-9_.:+,!<>=~* -]/.test(c)) throw new DashboardError("Unsupported character in FQL filter.");
  }
  if (quoted || stack.length) throw new DashboardError("Unbalanced FQL filter.");
  return `cid:'${cid.toLowerCase()}'+(${query})`;
}
export function assertQueryCid(raw: unknown, cid?: string) {
  if (!cid) return;
  const returned = (raw as { cid?: unknown } | null)?.cid;
  if (typeof returned !== "string" || returned.toLowerCase() !== cid.toLowerCase())
    throw new DashboardError("CrowdStrike returned a missing or different customer CID. Results were withheld.");
}

export type QueryScopeProof = { companyId: string; cid: string; bindingKey: string; connectionRevision: number };
export function assertPatchCid(hostScope: string[], tenantIds: string[], cid: string) {
  if (tenantIds.some(id => id !== cid)) throw new DashboardError("Patch report contains a different customer CID.", 409);
  for (const key of hostScope) {
    let identity: unknown;
    try { identity = JSON.parse(key); } catch { throw new DashboardError("Invalid patch device identity.", 409); }
    if (!Array.isArray(identity) || identity.length !== 2 || identity[0] !== cid || typeof identity[1] !== "string" || !identity[1])
      throw new DashboardError("Patch report contains an invalid or different customer device.", 409);
  }
}
