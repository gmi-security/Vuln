import { DashboardError } from "./elastic-dashboard";
import { ensureHydrated, getCompany } from "./store";

export async function validateDashboardCustomer(companyId: string) {
  if (!companyId || companyId.length > 100) throw new DashboardError("Choose an existing customer.",400);
  await ensureHydrated();
  const company = getCompany(companyId);
  if (!company || company.isDemo) throw new DashboardError("Customer not found.",404);
}
