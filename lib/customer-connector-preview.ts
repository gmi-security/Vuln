import { createHash } from "node:crypto";
import { getConnectors } from "./connectors";
import { normalizeCompanyName, findNearDuplicateCompanyName } from "./company-name";
import { reportingTileCompanyId, customerReportingTileIds } from "./reporting-direct-sources";
import { connectorDataContract, type ConnectorCapability } from "./connector-data-contracts";

// Migration evidence only. Nothing here grants access or chooses a source for a page.
// Keep references to existing credentials; never copy/decrypt them into this model.
export type RegistryCompany = { id: string; name: string; isDemo?: boolean };
export type ConnectorMetadata = {
  companies: RegistryCompany[];
  defender: { companyId: string; tenantId: string; revision: number }[];
  spotlight: { companyId: string; runId: string; status: string | null }[];
  connections: { source: string; revision: number }[];
  delivery?: { revision: number }[];
  tiles: { id: string; source: string; companyId?: string | null; revision: number }[];
};
type Evidence = "saved-binding" | "environment-match" | "shared-configuration" | "saved-tile" | "completed-import";
type Capability = ConnectorCapability;
export type ConnectorCandidate = {
  id: string;
  provider: string;
  connectionRef: string | null;
  companyId: string | null;
  evidence: Evidence;
  capabilities: Capability[];
  // A tenant is a vendor tenant, not the app company ID used by Spotlight's tenant_key.
  tenantId: string | null;
  scope: "tenant" | "unverified" | "historical-only";
  revision: number | null;
  tileId: string | null;
  runId: string | null;
  configured: boolean;
  review: string[];
  state: "pending-review";
  enabled: false;
  authority: "unassigned";
};

const digest = (value: unknown) => createHash("sha256").update(JSON.stringify(value)).digest("hex");
const text = (value: string | undefined) => value?.trim() ?? "";
// Non-secret connection identity changes invalidate reviews. Key rotation itself
// is not claimed as a detected revision; credential values never enter evidence.
const environmentRevision = (provider: string, env: Partial<NodeJS.ProcessEnv>, keys: string[]) =>
  parseInt(digest([provider, keys.map(key => [key, text(env[key])])]).slice(0, 12), 16) + 1;

export function buildConnectorPreview(metadata: ConnectorMetadata, env: Partial<NodeJS.ProcessEnv> = {}) {
  const companies = metadata.companies.filter(c => !c.isDemo);
  if (new Set(metadata.companies.map(c => c.id)).size !== metadata.companies.length)
    throw new Error("Duplicate company IDs in source metadata; review cannot continue.");
  const known = new Set(companies.map(c => c.id));
  const candidates: ConnectorCandidate[] = [];
  function add(input: Omit<ConnectorCandidate, "id" | "state" | "enabled" | "authority">) {
    const review = [...input.review];
    if (input.companyId && !known.has(input.companyId)) review.push("unknown-or-demo-customer");
    // Current generation changes are evidence updates, not a new registry entry
    // for every daily import. Historical pointers have one identity per customer.
    const id = digest([input.provider, input.connectionRef, input.evidence, input.tileId,
      input.evidence === "completed-import" ? input.companyId : input.runId]);
    if (candidates.some(c => c.id === id)) throw new Error("Duplicate connector evidence; review cannot continue.");
    candidates.push({ ...input, review, id, state: "pending-review", enabled: false, authority: "unassigned" });
  }
  const base = (provider: string, connectionRef: string | null, capabilities: Capability[]) => ({
    provider, connectionRef, capabilities, companyId: null, tenantId: null, scope: "unverified" as const,
    revision: null, tileId: null, runId: null, configured: false, review: [] as string[],
  });
  function match(label: string, mode: "defender" | "falcon") {
    if (!label) return { companyId: null, review: ["customer-not-specified"] };
    if (mode === "defender" && known.has(label)) return { companyId: label, review: ["environment-id-needs-review"] };
    const matches = companies.filter(c => mode === "falcon"
      ? normalizeCompanyName(c.name) === normalizeCompanyName(label)
      : c.name.trim().toLowerCase() === label.toLowerCase());
    if (matches.length !== 1) return { companyId: null, review: [matches.length ? "ambiguous-customer-name" : "customer-name-not-found"] };
    if (mode === "falcon" && findNearDuplicateCompanyName(label, companies, matches[0].id))
      return { companyId: null, review: ["near-duplicate-customer-name"] };
    return { companyId: matches[0].id, review: ["name-match-needs-review"] };
  }

  for (const saved of metadata.defender) add({
    ...base("defender", `application:defender_connections:${saved.companyId}`, ["vulnerability-import", "inventory"]),
    evidence: "saved-binding", companyId: saved.companyId, tenantId: saved.tenantId,
    scope: "tenant", revision: saved.revision, configured: true, review: ["verify-tenant-and-authority"],
  });

  // Include incomplete and unreachable numbered configurations as review evidence.
  // Do not pretend the legacy loader consumes entries after the first Falcon gap.
  const falconIndices = new Set<number>([1]);
  const defenderPrefixes = new Set<string>(["DEFENDER"]);
  for (const key of Object.keys(env)) {
    const f = /^FALCON_(?:CLIENT_ID|CLIENT_SECRET|CLOUD|CUSTOMER)_(\d+)$/.exec(key);
    if (f && Number(f[1]) >= 2) falconIndices.add(Number(f[1]));
    const d = /^(DEFENDER_\d+)_(?:TENANT_ID|CLIENT_ID|CLIENT_SECRET|CUSTOMER)$/.exec(key);
    if (d) defenderPrefixes.add(d[1]);
  }
  let previousIndex = 1, blocked = false;
  for (const index of [...falconIndices].sort((a, b) => a - b)) {
    const suffix = index === 1 ? "" : `_${index}`;
    const key = (name: string) => `FALCON_${name}${suffix}`;
    const present = ["CLIENT_ID", "CLIENT_SECRET", "CUSTOMER", "CLOUD"].some(n => text(env[key(n)]));
    const configured = !!text(env[key("CLIENT_ID")]) && !!text(env[key("CLIENT_SECRET")]);
    if (index >= 2 && (index > previousIndex + 1 || !configured)) blocked = true;
    previousIndex = index;
    if (!present) continue;
    const owner = match(text(env[key("CUSTOMER")]), "falcon");
    add({ ...base("crowdstrike", `environment:FALCON${suffix}`, ["vulnerability-import", "inventory"]),
      ...owner, evidence: "environment-match", configured, revision: environmentRevision("crowdstrike", env, [key("CLIENT_ID"),key("CLOUD"),key("CUSTOMER")]),
      review: [...owner.review, "vendor-tenant-not-verified", ...(!configured ? ["incomplete-credentials"] : []),
        ...(blocked ? ["legacy-loader-stops-before-this-entry"] : []),
        ...(text(env[key("CLOUD")]) && !["us-1", "us1", "us-2", "us2", "eu-1", "eu1", "us-gov-1"].includes(text(env[key("CLOUD")]).toLowerCase()) ? ["unrecognized-cloud"] : [])],
    });
  }
  for (const prefix of [...defenderPrefixes].sort()) {
    const key = (name: string) => `${prefix}_${name}`;
    if (!["TENANT_ID", "CLIENT_ID", "CLIENT_SECRET", "CUSTOMER"].some(n => text(env[key(n)]))) continue;
    const configured = ["TENANT_ID", "CLIENT_ID", "CLIENT_SECRET", "CUSTOMER"].every(n => text(env[key(n)]));
    const owner = match(text(env[key("CUSTOMER")]), "defender");
    const tenantId = text(env[key("TENANT_ID")]) || null;
    const saved = metadata.defender.find(s => s.companyId === owner.companyId);
    add({ ...base("defender", `environment:${prefix}`, ["vulnerability-import", "inventory"]),
      ...owner, tenantId, evidence: "environment-match", configured, revision: environmentRevision("defender",env,[key("TENANT_ID"),key("CLIENT_ID"),key("CUSTOMER")]),
      review: [...owner.review, ...(!configured ? ["incomplete-credentials"] : []),
        ...(prefix !== "DEFENDER" && !text(env[key("TENANT_ID")]) ? ["legacy-loader-ignores-without-tenant"] : []),
        ...(saved ? [saved.tenantId === tenantId ? "also-present-in-saved-connection" : "saved-environment-tenant-conflict"] : [])],
    });
  }

  for (const connector of getConnectors(env)) {
    if (["defender", "crowdstrike"].includes(connector.id)) continue;
    const present = connector.envVars.some(k => text(env[k]));
    if (!present) continue;
    add({ ...base(connector.id, `environment:scanner:${connector.id}`, [...(connectorDataContract(connector.id)?.capabilities ?? [])]),
      evidence: "shared-configuration", configured: connector.configured,
      revision: environmentRevision(connector.id,env,[...connector.envVars.filter(key=>/URL$/.test(key)), ...(connector.id === "nessus" ? ["NESSUS_TLS_INSECURE"] : [])]),
      review: ["customer-target-scope-not-assigned", ...(connector.status === "Planned" ? ["adapter-planned"] : []),
        ...(!connector.configured ? ["incomplete-credentials"] : []),
        ...(connector.id === "spiderfoot" ? ["scan-to-customer-mapping-needs-review"] : [])],
    });
  }
  const shared: [string, Capability, string[][]][] = [
    ["tidal", "inventory", [["TIDAL_EMAIL", "TIDAL_PASSWORD"], ["TIDAL_USERNAME", "TIDAL_PASSWORD"]]],
    ["intune", "inventory", [["INTUNE_TENANT_ID", "INTUNE_CLIENT_ID", "INTUNE_CLIENT_SECRET"]]],
    ["automate", "inventory", [["AUTOMATE_BASE_URL", "AUTOMATE_API_CLIENT_ID", "AUTOMATE_USERNAME", "AUTOMATE_PASSWORD"]]],
    ["misp", "enrichment", [["MISP_URL", "MISP_API_KEY"]]],
    ["opencti", "enrichment", [["OPENCTI_URL", "OPENCTI_API_KEY"]]],
    ["intelowl", "enrichment", [["INTELOWL_URL", "INTELOWL_API_KEY"]]],
  ];
  for (const [provider, capability, alternatives] of shared) {
    if (!alternatives.flat().some(k => text(env[k]))) continue;
    const configured = alternatives.some(keys => keys.every(k => text(env[k])));
    add({ ...base(provider, `environment:${provider}`, [capability]), evidence: "shared-configuration", configured,
      tenantId: provider === "intune" ? text(env.INTUNE_TENANT_ID) || null : null,
      revision: environmentRevision(provider,env,Object.keys(env).filter(key=>key.startsWith(provider.toUpperCase()+"_")&&/(?:URL|ORIGIN|TENANT_ID|CLIENT_ID|EMAIL|USERNAME)$/.test(key)).sort()),
      review: ["shared-connection-not-a-customer-binding", ...(!configured ? ["incomplete-credentials"] : [])] });
  }

  // These integrations keep their own storage/consumers. Listing them does not
  // promote repository issues, tickets or orchestration into endpoint findings.
  for (const [provider, keys] of [["appsec",["APPSEC_ELASTIC_URL","APPSEC_ELASTIC_API_KEY"]],
    ["n8n",["N8N_WEBHOOK_URL","N8N_MCP_URL"]]] as const) {
    if (!keys.some(key=>text(env[key]))) continue;
    add({ ...base(provider, `environment:${provider}`, [...connectorDataContract(provider)!.capabilities]),
      evidence: "shared-configuration", configured: provider === "n8n" ? keys.some(key=>text(env[key])) : keys.every(key=>text(env[key])),
      revision: environmentRevision(provider,env,provider === "appsec" ? ["APPSEC_ELASTIC_URL","APPSEC_ELASTIC_SCAN_STREAM","APPSEC_ELASTIC_FINDING_STREAM"] : ["N8N_WEBHOOK_URL","N8N_MCP_URL"]),
      review: ["shared-connection-not-a-customer-binding"] });
  }
  for (const entry of metadata.delivery ?? []) add({ ...base("connectwise", "dashboard:patch_connectwise_connection:1", ["ticket-delivery"]),
    evidence: "shared-configuration", configured: true, revision: entry.revision,
    review: ["existing-ticket-routing-required"] });

  const ref = (source: string) => source === "elastic"
    ? "dashboard:elastic_dashboard_connection:1" : `dashboard:dashboard_source_connections:${source}`;
  for (const connection of metadata.connections) add({
    ...base(connection.source, ref(connection.source), ["saved-query"]), evidence: "shared-configuration",
    configured: true, revision: connection.revision, review: ["shared-connection-not-a-customer-binding"],
  });
  const configured = env.REPORTING_CUSTOMER_TILE_IDS ?? "", atlasIds = env.ATLAS_REPORTING_TILE_IDS ?? "";
  customerReportingTileIds("", configured, atlasIds); // Validate even with no tiles; never silently drop a bad mapping.
  for (const tile of metadata.tiles) {
    const companyId = reportingTileCompanyId(tile, configured, atlasIds);
    add({ ...base(tile.source, ref(tile.source), ["saved-query"]), evidence: "saved-tile",
      companyId, tileId: tile.id, revision: tile.revision,
      configured: metadata.connections.some(c => c.source === tile.source),
      review: ["tile-ownership-is-not-upstream-scope", "mirror-authority-needs-review",
        ...(companyId ? [] : ["tile-unassigned"]),
        ...(metadata.connections.some(c => c.source === tile.source) ? [] : ["saved-connection-missing"])],
    });
  }
  for (const generation of metadata.spotlight) add({
    ...base("crowdstrike", null, []), evidence: "completed-import", companyId: generation.companyId,
    scope: "historical-only", runId: generation.runId,
    review: ["import-pointer-is-not-a-connection", "app-company-id-is-not-vendor-tenant",
      ...(generation.status !== "completed" ? ["current-generation-not-completed"] : [])],
  });

  for (const candidate of candidates) {
    if (candidate.provider === "defender" && candidate.evidence === "saved-binding" && candidates.some(other =>
      other.provider === "defender" && other.evidence === "environment-match" && other.companyId === candidate.companyId &&
      other.tenantId && other.tenantId !== candidate.tenantId)) candidate.review.push("saved-environment-tenant-conflict");
    if (candidate.tenantId && candidate.companyId && candidates.some(other =>
      other.provider === candidate.provider && other.tenantId === candidate.tenantId &&
      other.companyId && other.companyId !== candidate.companyId)) candidate.review.push("vendor-tenant-has-multiple-customers");
  }
  // Stable output and fingerprint for later reviewed imports. It is not authorization,
  // a credential-version check, or a substitute for recollecting before a write.
  candidates.sort((a, b) => a.id.localeCompare(b.id));
  const result = {
    version: 1 as const, mode: "preview-only" as const,
    companies: companies.map(c => ({ id: c.id, name: c.name })).sort((a, b) => a.id.localeCompare(b.id)),
    candidates,
    limitations: ["no-connections-tested", "no-bindings-enabled", "no-credential-values-exported",
      "no-historical-finding-scan", "no-runtime-environment-reconciliation", "legacy-readers-unchanged"],
  };
  return { ...result, fingerprint: digest(result) };
}
