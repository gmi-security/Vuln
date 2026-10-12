import { createHash } from "node:crypto";
import { applicationDatabase } from "./persist";
import { DashboardError } from "./elastic-dashboard";
import { buildConnectorPreview } from "./customer-connector-preview";
import { appsecStreams, createAppSecRoutingStore, reviewedAppSecRouting } from "./customer-appsec-routing";
import { readApplicationConnectorMetadata, readSavedApplicationCompanies } from "./db/connector-metadata.mjs";
import type { AppSecReadScope } from "./elastic-appsec";

type Company = { id: string; name: string; isDemo?: boolean };
const unavailable = () => new DashboardError("AppSec customer routing is unavailable or needs renewed repository approval.", 409);
export function appsecCompanyParameter(request: Request) {
  const values = new URL(request.url).searchParams.getAll("companyId");
  if (values.length > 1 || values.length === 1 && !/^[A-Za-z0-9][A-Za-z0-9_-]{0,99}$/.test(values[0]))
    throw new DashboardError("Choose an existing customer.", 400);
  return values[0] ?? null;
}
export async function appsecCustomerSetup() {
  const reviewed = reviewedAppSecRouting(process.env.VULN_REVIEWED_APPSEC_PROVIDERS);
  if (!reviewed) return { reviewed, companies: [] };
  const db = applicationDatabase();
  if (!db) throw unavailable();
  const client = await db.connect();
  try { return { reviewed, companies: (await readSavedApplicationCompanies(client)).filter((c: Company) => !c.isDemo).map((c: Company) => ({ id: c.id, name: c.name })) }; }
  finally { client.release(); }
}

// Metadata only: no legacy findings hydration, schema creation or vendor calls.
async function current(companyId: string) {
  const env = { ...process.env };
  if (!reviewedAppSecRouting(env.VULN_REVIEWED_APPSEC_PROVIDERS)) throw unavailable();
  const db = applicationDatabase();
  if (!db) throw unavailable();
  const endpoint = env.APPSEC_ELASTIC_URL?.trim(), apiKey = env.APPSEC_ELASTIC_API_KEY?.trim();
  if (!endpoint || !apiKey) throw unavailable();
  const streams = appsecStreams(env);
  const routes = await createAppSecRoutingStore(db, env).read("appsec", async () => {
    const client = await db.connect();
    try {
      const metadata = await readApplicationConnectorMetadata(client);
      if (!metadata.companies.some((c: Company) => c.id === companyId && !c.isDemo)) throw unavailable();
      return buildConnectorPreview({ ...metadata, connections: [], tiles: [] }, env);
    } finally { client.release(); }
  });
  const route = routes.find(r => r.companyId === companyId);
  if (!route) throw unavailable();
  // Private, request-lifetime comparison only. Never persisted, logged or sent to the browser.
  const proof = createHash("sha256").update(JSON.stringify([route.bindingKey, endpoint, apiKey, streams])).digest("hex");
  const scope: AppSecReadScope = { connection: { endpoint, apiKey }, repositories: route.repositories, streams };
  return { proof, scope };
}
export async function loadCustomerAppSecScope(companyId: string | null) {
  try {
    if (!reviewedAppSecRouting(process.env.VULN_REVIEWED_APPSEC_PROVIDERS)) {
      if (companyId !== null) throw new DashboardError("Customer AppSec routing is not enabled. No organization data was returned for this customer.", 409);
      return null;
    }
    if (companyId === null) throw new DashboardError("Choose a customer to view its approved AppSec repositories.", 400);
    const pinned = await current(companyId);
    return { scope: pinned.scope, async recheck() {
      try { if ((await current(companyId)).proof !== pinned.proof) throw unavailable(); }
      catch { throw unavailable(); }
    } };
  } catch (error) { if (error instanceof DashboardError) throw error; throw unavailable(); }
}
