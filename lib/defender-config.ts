import { DefenderError, validateCredentials } from "./defender-client";
import { defenderStore } from "./defender-store";

// Like the other scanner connectors, configuration belongs to the server.
// Support the existing unnumbered variables plus explicit additional customers.
export function defenderEnvironment(env: NodeJS.ProcessEnv = process.env) {
  const prefixes = new Set(["DEFENDER",...Object.keys(env).flatMap(key=>key.match(/^(DEFENDER_\d+)_TENANT_ID$/)?.[1] ?? [])]);
  return [...prefixes].flatMap(prefix=> {
    const tenantId = env[`${prefix}_TENANT_ID`]?.trim() ?? "", clientId = env[`${prefix}_CLIENT_ID`]?.trim() ?? "";
    const clientSecret = env[`${prefix}_CLIENT_SECRET`] ?? "", customer = env[`${prefix}_CUSTOMER`]?.trim() ?? "";
    if (!tenantId && !clientId && !clientSecret && !customer) return [];
    if (!customer) throw new DefenderError(`${prefix}_CUSTOMER must identify an existing customer.`,503);
    return [{ ...validateCredentials({tenantId,clientId,clientSecret}),customer,daily:env[`${prefix}_DAILY`] !== "false" }];
  });
}
export function resolveDefenderCustomer(customer: string, companies: {id:string;name:string}[]): string {
  const id = companies.find(c=>c.id === customer);
  if (id) return id.id;
  const matches = companies.filter(c=>c.name.trim().toLowerCase() === customer.toLowerCase());
  if (matches.length !== 1) throw new DefenderError("DEFENDER_CUSTOMER must match one existing customer name or company ID. No customer was created or guessed.",503);
  return matches[0].id;
}
let syncing: Promise<void> | undefined;
export function syncDefenderEnvironment(): Promise<void> {
  if (syncing) return syncing;
  syncing = (async()=> {
    const configs = defenderEnvironment();
    if (!configs.length) return; // Existing encrypted connections remain readable.
    const { ensureHydrated,listCompanies,persistenceBlocked } = await import("./store");
    await ensureHydrated();
    if (persistenceBlocked()) throw new DefenderError("Customer storage unavailable. Defender configuration was not changed.",503);
    const companies = listCompanies(), store = defenderStore();
    const resolved = configs.map(c=>({ ...c,companyId:resolveDefenderCustomer(c.customer,companies) }));
    if (new Set(resolved.map(c=>c.companyId)).size !== resolved.length || new Set(resolved.map(c=>c.tenantId)).size !== resolved.length)
      throw new DefenderError("Each Defender tenant and customer must be configured only once.",503);
    for (const c of resolved) {
      const old = await store.connection(c.companyId);
      const previous = old ? await store.credentials(c.companyId).catch(()=>null) : null;
      if (previous?.tenantId === c.tenantId && previous.clientId === c.clientId && previous.clientSecret === c.clientSecret && old.daily === c.daily) continue;
      // Let already-queued work finish with its bound revision. Blocking the
      // worker here would otherwise strand the very run save() is waiting on.
      const latest = old ? (await store.list(c.companyId))[0] : null;
      if (latest?.status === "queued" || latest?.status === "running") continue;
      await store.save(c,"server environment");
    }
  })().finally(()=>{ syncing = undefined; });
  return syncing;
}
