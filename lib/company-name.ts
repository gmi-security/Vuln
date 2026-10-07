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

// Catches the "Atlas Healthcare Partners" vs "Atlas HealthCare" class of bug
// at its root, one level past normalizeCompanyName above: two company names
// where the shorter is a whole-word prefix of the longer (not just any
// substring -- "gcon" vs "gconsulting" must NOT match) are almost certainly
// the same real customer typed two different ways, not two unrelated
// companies that happen to share a prefix. Confirmed in production twice
// with this exact heuristic: "GCON" vs "GCON Inc.", and a CrowdStrike Falcon
// tenant configured for "Atlas HealthCare" auto-creating a second, near-
// empty company instead of attaching to the existing "Atlas Healthcare
// Partners" record -- silently diverting a multi-hour sync into the wrong
// bucket. A caller about to select or auto-create a company by exact-name
// match should check this first and refuse/warn rather than proceed, since
// an exact match alone can't tell "the only company with this name" apart
// from "the only company with this EXACT name, but there's a near-duplicate
// sitting right next to it."
export function findNearDuplicateCompanyName<T extends { id: string; name: string }>(
  targetName: string,
  companies: T[],
  excludeId?: string,
): T | undefined {
  const target = normalizeCompanyName(targetName);
  return companies.find((c) => {
    if (c.id === excludeId) return false;
    const name = normalizeCompanyName(c.name);
    if (name === target) return false;
    const [shorter, longer] = name.length <= target.length ? [name, target] : [target, name];
    return longer.startsWith(`${shorter} `);
  });
}
