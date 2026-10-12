const heldCustomers = new Set(["CO-229336", "CO-229438"]);

export function requiresConsolidationManualReview(companyId: string | undefined): boolean {
  return companyId !== undefined && heldCustomers.has(companyId);
}
