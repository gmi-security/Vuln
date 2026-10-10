/** Safe, bounded status text shared by manual sync and the sync-all runner.
 * Raw provider errors and customer identifiers stay out of the summary.
 */
export function connectorImportWarnings(value: unknown): string[] {
  if (!value || typeof value !== "object" || Array.isArray(value)) return [];
  const result = value as Record<string, unknown>;
  const warnings: string[] = [];
  if (Array.isArray(result.errors) && result.errors.length)
    warnings.push(`${result.errors.length} import error${result.errors.length === 1 ? "" : "s"}`);
  if (Array.isArray(result.tenants)) {
    const failed = result.tenants.filter(row => row && typeof row === "object" && row.error).length;
    if (failed) warnings.push(`${failed} tenant import${failed === 1 ? "" : "s"} failed`);
  }
  if (Array.isArray(result.truncatedTenants) && result.truncatedTenants.length)
    warnings.push("Pagination limit reached; results are incomplete");
  if (Array.isArray(result.skipped)) {
    const conflicts = result.skipped.filter(row => row && typeof row === "object" && typeof row.reason === "string" &&
      /no unambiguous matching company|existing scan belongs to a different company/.test(row.reason)).length;
    if (conflicts) warnings.push(`${conflicts} customer mapping${conflicts === 1 ? "" : "s"} need review`);
  }
  return warnings;
}
