import type { Finding } from "./types";
import type { PatchGroup } from "./patch-request";
import { DashboardError } from "./elastic-dashboard";

export function assessDefenderPatch(packet: PatchGroup, findings: Finding[], currentRun: string,
  importedAt: string, ticketCreatedAt: string, now = Date.now()) {
  if (packet.source !== "stored-findings" || packet.connectors?.length !== 1 || packet.connectors[0] !== "defender" || !packet.appCompanyId || !packet.reviewRows?.length)
    throw new DashboardError("This request needs verification in all of its source scanners.",409);
  if (!Number.isFinite(Date.parse(importedAt)) || Date.parse(importedAt) <= Date.parse(ticketCreatedAt) || now-Date.parse(importedAt)>86_400_000)
    throw new DashboardError("Run a new Defender sync after ticket creation before verifying this fix. The import must be less than 24 hours old.",409);
  const byId = new Map(findings.map(f=>[f.id,f]));
  const stillOpen = new Set<string>();
  for (const row of packet.reviewRows) {
    const f = row.findingId ? byId.get(row.findingId) : undefined;
    if (!f || f.companyId !== packet.appCompanyId || f.asset !== row.asset || f.cve !== row.cve || !f.defender || f.defender.runId !== currentRun)
      throw new DashboardError("Defender has not provided fresh evidence for every scoped device. Sync active devices and retry; missing devices are not treated as patched.",409);
    if (f.defender.active || f.status !== "Resolved") stillOpen.add(f.asset);
  }
  return { checkedAt:importedAt,state:stillOpen.size ? "still_open" : "verified",stillOpenCount:stillOpen.size };
}
