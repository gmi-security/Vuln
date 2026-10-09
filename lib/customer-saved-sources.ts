import type { CustomerSourceRead, CustomerSourceReadRequest } from "./customer-source-read-model";
export type SavedSource = "defender" | "crowdstrike";
export class SavedSourceError extends Error { constructor(message: string, readonly status: number) { super(message); } }
export function savedSourcePolicy(raw: string | undefined): Record<string, SavedSource[]> {
  if (!raw) return {};
  let value: unknown;
  try { value = JSON.parse(raw); } catch { throw new SavedSourceError("Saved source configuration is invalid.", 503); }
  if (!value || typeof value !== "object" || Array.isArray(value) || Object.keys(value).length > 100) throw new SavedSourceError("Saved source configuration is invalid.", 503);
  const result: Record<string, SavedSource[]> = Object.create(null);
  for (const [companyId, sources] of Object.entries(value)) {
    if (!/^[A-Za-z0-9][A-Za-z0-9_-]{0,99}$/.test(companyId) || !Array.isArray(sources) || sources.length > 2 ||
      sources.some(source => source !== "defender" && source !== "crowdstrike") || new Set(sources).size !== sources.length)
      throw new SavedSourceError("Saved source configuration is invalid.", 503);
    result[companyId] = sources as SavedSource[];
  }
  return result;
}
export function createCustomerSavedSources(deps: {
  companies: () => Promise<{id: string; name: string; isDemo?: boolean}[]>;
  read: Record<SavedSource, (request: CustomerSourceReadRequest) => Promise<CustomerSourceRead>>;
  policy: Record<string, SavedSource[]>;
}) {
  async function get(params: URLSearchParams) {
    const setup = params.get("setup") === "1";
    const companyId = params.get("companyId"), source = params.get("source");
    if (setup && (companyId !== null || source !== null || params.has("offset"))) throw new SavedSourceError("Choose a customer or request the customer list.", 400);
    if (!setup && (!companyId || !/^[A-Za-z0-9][A-Za-z0-9_-]{0,99}$/.test(companyId))) throw new SavedSourceError("Choose an existing customer.", 400);
    if (source !== null && source !== "defender" && source !== "crowdstrike") throw new SavedSourceError("Unsupported saved source.", 400);
    const rawOffset = params.get("offset") ?? "0";
    if (!/^\d+$/.test(rawOffset) || Number(rawOffset) > 1_000_000 || (!source && params.has("offset"))) throw new SavedSourceError("Invalid CVE page.", 400);
    const companies = (await deps.companies()).filter(c => !c.isDemo);
    if (new Set(companies.map(c => c.id)).size !== companies.length) throw new SavedSourceError("Customer metadata is inconsistent.", 503);
    if (setup) return { companies: companies.map(({id, name}) => ({id, name})) };
    const company = companies.find(c => c.id === companyId);
    if (!company) throw new SavedSourceError("Customer not found.", 404);
    const sources = Object.hasOwn(deps.policy, company.id) ? deps.policy[company.id] : [];
    if (!source) return { companyId: company.id, sources };
    if (!sources.includes(source)) throw new SavedSourceError("This saved source is not enabled for this customer.", 404);
    const result = await deps.read[source]({companyId: company.id, now: new Date(), staleAfterMs: 36 * 3600000, offset: Number(rawOffset), limit: 50});
    if (result.companyId !== company.id || result.source !== source) throw new SavedSourceError("Saved source scope is inconsistent.", 503);
    return result;
  }
  return { get };
}
