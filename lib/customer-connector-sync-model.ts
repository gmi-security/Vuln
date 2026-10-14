export type SyncState = "idle" | "queued" | "running" | "succeeded" | "failed" | "interrupted" | "unavailable";
export type CustomerSyncRow = {
  id: string; label: string; scope: "customer" | "shared"; state: SyncState;
  lastSuccessAt: string | null; lastAttemptAt: string | null; detail: string;
  action: "sync" | "refresh" | "shared" | null; canSync: boolean;
};
export type CustomerSyncStatus = { companyId: string; checkedAt: string; schedulerPaused: boolean; rows: CustomerSyncRow[] };
export type ImportSyncRecord = {
  status?: string; last_success_at?: string | Date | null; started_at?: string | Date | null;
  lease_until?: string | Date | null; fetched?: number; hydrated_count?: number;
};
export type QuerySyncRecord = {
  id: string; title: string; source: string; companyId?: string | null;
  refreshed_at?: string | Date | null; attempted_at?: string | Date | null;
  refresh_lease_until?: string | Date | null; refresh_requested?: boolean; last_error?: string | null;
};
const names: Record<string,string> = { defender:"Microsoft Defender", crowdstrike:"CrowdStrike", elastic:"Elasticsearch",
  nessus:"Nessus", spiderfoot:"SpiderFoot", artemis:"Artemis", zap:"OWASP ZAP", tidal:"Tidal", automate:"ConnectWise Automate",
  intune:"Microsoft Intune", misp:"MISP", opencti:"OpenCTI", intelowl:"IntelOwl", connectwise:"ConnectWise PSA", appsec:"AppSec", n8n:"n8n", vulners:"Vulners", burp:"Burp", nmap:"Nmap", qualys:"Qualys" };
const time = (value: string | Date | null | undefined) => value && Number.isFinite(new Date(value).getTime()) ? new Date(value).toISOString() : null;
export function requireSyncAction(status: Pick<CustomerSyncStatus,"rows">, id: string): CustomerSyncRow {
  const row = status.rows.find(row=>row.id === id);
  if (!row || !row.canSync || !["sync","refresh"].includes(row.action ?? ""))
    throw new Error(row?.detail || "This sync action is not available for the selected customer.");
  return row;
}
export function customerSyncRows(input: {
  companyId: string; providers: string[]; now: number; defender?: ImportSyncRecord | null;
  spotlight?: ImportSyncRecord | null; spotlightAvailable?: boolean; spotlightActive?: boolean;
  spotlightBusy?: boolean; queries: QuerySyncRecord[];
}): CustomerSyncRow[] {
  const rows: CustomerSyncRow[] = [];
  const providers = new Set(input.providers);
  if (providers.has("defender") || input.defender) {
    const run = input.defender;
    const state: SyncState = !run ? "unavailable" : run.status === "running"
      ? (new Date(run.lease_until ?? 0).getTime() > input.now ? "running" : "interrupted")
      : run.status === "queued" ? "queued" : run.status === "failed" ? "failed" : run.status === "succeeded" ? "succeeded" : "idle";
    rows.push({id:"defender",label:"Microsoft Defender · vulnerabilities and devices",scope:"customer",state,
      lastSuccessAt:time(run?.last_success_at),lastAttemptAt:time(run?.started_at),action:"sync",
      canSync:!!run && state !== "running",
      detail:state === "running" ? `${Number(run?.fetched ?? 0).toLocaleString()} source rows processed.` : state === "queued" ? "Waiting for the Defender worker. Resume sync wakes this queued job without creating a duplicate."
        : state === "interrupted" ? "Worker lease expired. Resume sync safely replaces the abandoned job; previous completed data is retained."
        : state === "failed" ? "Latest import failed. Previous completed data is retained; see Defender connection details."
        : !run ? "No saved customer connection is available." : "Imports vulnerabilities and device inventory for this customer."});
  }
  if (providers.has("crowdstrike") || input.spotlightAvailable) {
    const run = input.spotlight;
    const state: SyncState = input.spotlightActive ? "running" : run?.status === "running" ? "interrupted"
      : run?.status === "failed" ? "failed" : run?.status === "completed" ? "succeeded" : "idle";
    rows.push({id:"crowdstrike-spotlight",label:"CrowdStrike · Spotlight vulnerabilities",scope:"customer",state,
      lastSuccessAt:time(run?.last_success_at),lastAttemptAt:time(run?.started_at),action:"sync",
      canSync:!!input.spotlightAvailable && !input.spotlightBusy,
      detail:!input.spotlightAvailable ? "A current, unambiguous customer import mapping is required. Historical data or a saved query alone cannot start an import."
        : input.spotlightActive ? `${Number(run?.hydrated_count ?? 0).toLocaleString()} source rows stored.`
        : input.spotlightBusy ? "The shared Spotlight worker is busy. Try again after it finishes."
        : state === "interrupted" ? "Import was interrupted. Sync now resumes the existing checkpoint."
        : state === "failed" ? "Latest import failed. Previous completed data is retained; Sync now retries the import."
        : "Imports this customer's Spotlight findings; device inventory uses the shared tools."});
  }
  for (const query of input.queries) {
    const running = new Date(query.refresh_lease_until ?? 0).getTime() > input.now;
    const cooldown = new Date(query.attempted_at ?? 0).getTime() > input.now - 30_000;
    const state: SyncState = running ? "running" : query.refresh_requested ? "queued" : query.last_error ? "failed" : query.refreshed_at ? "succeeded" : "idle";
    rows.push({id:`query:${query.id}`,label:`${names[query.source] ?? query.source} · ${query.title}`,scope:"customer",state,
      lastSuccessAt:time(query.refreshed_at),lastAttemptAt:time(query.attempted_at),action:"refresh",canSync:!running && !cooldown,
      detail:running ? "Refreshing saved query results." : query.refresh_requested ? "Refresh requested; waiting for the query worker. Resume refresh wakes the existing request."
        : cooldown ? "A refresh was just attempted. Please wait 30 seconds before retrying."
        : query.last_error ? "Latest query failed. Previous results are retained; the dashboard tile has the error details."
        : "Refreshes this saved tile, not a full vulnerability import."});
  }
  for (const provider of providers) {
    if (["defender","elastic"].includes(provider)) continue;
    rows.push({id:`shared:${provider}`,label:provider === "crowdstrike" ? "CrowdStrike · device inventory" : names[provider] ?? provider,
      scope:"shared",state:"unavailable",lastSuccessAt:null,lastAttemptAt:null,canSync:false,action:"shared",
      detail:"No customer-specific sync timestamp is recorded here. Shared tools show the available import, scan or enrichment actions and may affect multiple customers."});
  }
  if (providers.has("elastic") && !input.queries.some(q=>q.source === "elastic")) rows.push({id:"elastic",label:"Elasticsearch",scope:"customer",
    state:"unavailable",lastSuccessAt:null,lastAttemptAt:null,action:null,canSync:false,detail:"No saved Elasticsearch queries are assigned to this customer."});
  return rows;
}
