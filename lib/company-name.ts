// Normalize a company name for matching, not display: fold Unicode
// compatibility forms, map smart quotes/dashes to their ASCII equivalents,
// collapse whitespace, and lowercase. A plain .toLowerCase() comparison
// missed "Atlas Healthcare Partners" (Automate's/Tidal's name) against
// "Atlas Healthcare" (Vuln's stored name) on the first live Automate sync --
// normalizing first makes that whole class of false negative not happen
// again. Standalone module (no dependents) so every import/matching path
// across lib/store.ts and lib/spotlight-import.ts can share it without a
// circular import (lib/store.ts already imports from lib/spotlight-import.ts).
export function normalizeCompanyName(name: string): string {
  return name
    .normalize("NFKC")
    .replace(/[‘’ʼ]/g, "'")
    .replace(/[“”]/g, '"')
    .replace(/[–—]/g, "-")
    .replace(/\s+/g, " ")
    .trim()
    .toLowerCase();
}
