export function exactCompanyMatch<T extends { name: string }>(cwName: string, companies: T[]): T | null {
  const normalize = (name: string) => name.trim().replace(/\s+/g, " ").toLocaleLowerCase("en-US");
  const name = normalize(cwName);
  const matches = companies.filter(company => normalize(company.name) === name);
  return matches.length === 1 ? matches[0] : null;
}
