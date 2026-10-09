import { resolveCustomerScope } from "./customer-scope";

export async function validateDashboardCustomer(companyId: string) {
  await resolveCustomerScope(companyId);
}
