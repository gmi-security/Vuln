import { DashboardError } from "./elastic-dashboard";
import { ensureHydrated, getCompany } from "./store";
import type { Company } from "./types";

export type CustomerScope = Readonly<{ companyId: string; company: Company }>;

// Compatibility boundary over the current company store. Resolve an explicit
// app company before reading its data; never infer it from a title, CVE or
// global connector. Authentication remains the caller's responsibility.
// This does NOT establish ownership of a vendor tenant or dataset.
export async function resolveCustomerScope(value: unknown): Promise<CustomerScope> {
  if (typeof value !== "string" || !value || value.length > 100) {
    throw new DashboardError("Choose an existing customer.", 400);
  }
  await ensureHydrated();
  const company = getCompany(value);
  if (!company || company.isDemo || company.id !== value) {
    throw new DashboardError("Customer not found.", 404);
  }
  return Object.freeze({ companyId: company.id, company });
}
