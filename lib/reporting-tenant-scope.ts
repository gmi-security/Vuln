export function customerFalconTenantIds(companyId: string, configured: string | undefined): string[] {
  if (companyId !== "CO-147284" || !configured) return [];
  return [...new Set(configured.split(",").map(value => value.trim().toLowerCase())
    .filter(value => /^[a-f0-9]{32}$/.test(value)))];
}
