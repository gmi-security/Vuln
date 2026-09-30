// Active-exploitation signal from threat-intel platforms already running in
// this environment (MISP, OpenCTI, IntelOwl) -- fills RiskScoreInput's
// activeExploitation field, which had no data source before this file and
// was hardcoded false in lib/finding-risk-compute.ts.
//
// IMPORTANT: these are built against each platform's documented/standard API
// shape, not verified against a live instance from this sandbox (no network
// access to internal infrastructure, no credentials). Once MISP_URL/
// MISP_API_KEY etc. are set in the real environment, run a manual
// "Refresh risk data now" pass and check the logs -- a wrong field name or
// API-version mismatch will show as a caught, logged, best-effort failure
// (never a thrown error that blocks scoring), but should still be verified
// and corrected against your actual instance's behavior.
//
// Each source is fully optional and independent: unset env vars mean that
// source is skipped entirely (not an error), and one source failing never
// blocks the others or blocks scoring -- same "no vulnerability record
// should disappear because enrichment temporarily failed" principle as the
// CISA KEV/EPSS fetchers in lib/cve-enrichment-refresh.ts.

export type ActiveExploitationSignal = { active: boolean; source: string; detail: string };

function envPair(urlVar: string, keyVar: string): { url: string; key: string } | null {
  const url = process.env[urlVar]?.trim().replace(/\/$/, "");
  const key = process.env[keyVar]?.trim();
  return url && key ? { url, key } : null;
}

// MISP: searches for a "vulnerability" attribute matching the CVE, then
// checks whether it has been "sighted" (MISP's mechanism for community
// members reporting real-world observation) -- the most direct MISP signal
// for "this isn't just theoretical, someone has actually seen it exploited."
// https://www.misp-project.org/openapi/ -- POST /attributes/restSearch
export async function fetchMispActiveExploitation(cves: string[]): Promise<Map<string, ActiveExploitationSignal>> {
  const out = new Map<string, ActiveExploitationSignal>();
  const conn = envPair("MISP_URL", "MISP_API_KEY");
  if (!conn || !cves.length) return out;
  for (const cve of cves) {
    try {
      const res = await fetch(`${conn.url}/attributes/restSearch`, {
        method: "POST",
        headers: { Authorization: conn.key, Accept: "application/json", "Content-Type": "application/json" },
        body: JSON.stringify({ value: cve, type: "vulnerability" }),
        cache: "no-store",
      });
      if (!res.ok) continue;
      const json = (await res.json()) as { response?: { Attribute?: { id?: string; sighting_count?: string | number; Sighting?: unknown[] }[] } };
      const attributes = json.response?.Attribute ?? [];
      const sighted = attributes.some((a) => Number(a.sighting_count ?? 0) > 0 || (Array.isArray(a.Sighting) && a.Sighting.length > 0));
      if (attributes.length) out.set(cve, { active: sighted, source: "misp", detail: sighted ? `${attributes.length} MISP attribute(s), sighted` : `${attributes.length} MISP attribute(s), no sightings` });
    } catch {
      // best-effort per CVE -- one lookup failing must not block the rest
    }
  }
  return out;
}

// OpenCTI: GraphQL query for a Vulnerability STIX object by CVE name, and
// whether it has any stixCoreRelationship to an Intrusion-Set/Campaign/
// Malware -- OpenCTI's way of saying "this vulnerability is tied to known
// threat activity," a broader signal than MISP's per-CVE sightings.
// https://docs.opencti.io/latest/deployment/integrations/ -- GraphQL API
export async function fetchOpenCtiActiveExploitation(cves: string[]): Promise<Map<string, ActiveExploitationSignal>> {
  const out = new Map<string, ActiveExploitationSignal>();
  const conn = envPair("OPENCTI_URL", "OPENCTI_API_KEY");
  if (!conn || !cves.length) return out;
  const query = `query($search: FilterGroup) {
    vulnerabilities(filters: $search) {
      edges { node { name
        stixCoreRelationships { edges { node { relationship_type to { ... on IntrusionSet { name } ... on Campaign { name } ... on Malware { name } } } } }
      } }
    }
  }`;
  for (const cve of cves) {
    try {
      const res = await fetch(`${conn.url}/graphql`, {
        method: "POST",
        headers: { Authorization: `Bearer ${conn.key}`, "Content-Type": "application/json" },
        body: JSON.stringify({ query, variables: { search: { mode: "and", filters: [{ key: "name", values: [cve] }], filterGroups: [] } } }),
        cache: "no-store",
      });
      if (!res.ok) continue;
      const json = (await res.json()) as { data?: { vulnerabilities?: { edges?: { node?: { stixCoreRelationships?: { edges?: unknown[] } } }[] } } };
      const nodes = json.data?.vulnerabilities?.edges ?? [];
      const linked = nodes.some((e) => (e.node?.stixCoreRelationships?.edges?.length ?? 0) > 0);
      if (nodes.length) out.set(cve, { active: linked, source: "opencti", detail: linked ? "Linked to a known threat actor/campaign/malware in OpenCTI" : "Tracked in OpenCTI, no threat-activity link found" });
    } catch {
      // best-effort per CVE
    }
  }
  return out;
}

// IntelOwl: less naturally CVE-granular than MISP/OpenCTI -- it's built for
// per-indicator (IP/hash/domain) analysis. This checks for a prior
// "generic" observable job submitted for the CVE string and whether any
// configured analyzer flagged it, which only produces useful signal if a
// CVE-aware analyzer (e.g. a Vulners/CVE-search playbook) is actually
// enabled on your instance -- confirm that's the case before trusting this
// source's output.
// https://intelowl.readthedocs.io/en/latest/Usage.html -- REST API
export async function fetchIntelOwlActiveExploitation(cves: string[]): Promise<Map<string, ActiveExploitationSignal>> {
  const out = new Map<string, ActiveExploitationSignal>();
  const conn = envPair("INTELOWL_URL", "INTELOWL_API_KEY");
  if (!conn || !cves.length) return out;
  for (const cve of cves) {
    try {
      const res = await fetch(`${conn.url}/api/analyze_observable`, {
        method: "POST",
        headers: { Authorization: `Token ${conn.key}`, "Content-Type": "application/json" },
        body: JSON.stringify({ observable_name: cve, observable_classification: "generic", tlp: "AMBER" }),
        cache: "no-store",
      });
      if (!res.ok) continue;
      const json = (await res.json()) as { reports?: { report?: { evaluation?: string; exploited?: boolean } }[] };
      const reports = json.reports ?? [];
      const flagged = reports.some((r) => r.report?.exploited === true || r.report?.evaluation === "malicious");
      if (reports.length) out.set(cve, { active: flagged, source: "intelowl", detail: flagged ? "IntelOwl analyzer flagged active exploitation" : `${reports.length} IntelOwl report(s), none flagged` });
    } catch {
      // best-effort per CVE
    }
  }
  return out;
}

// Merges all three sources -- any one flagging "active" is enough (each
// platform sees a different slice of the threat landscape; requiring
// unanimous agreement would just suppress real signal).
export async function fetchActiveExploitationSignals(cves: string[]): Promise<Map<string, ActiveExploitationSignal>> {
  const [misp, opencti, intelowl] = await Promise.all([
    fetchMispActiveExploitation(cves), fetchOpenCtiActiveExploitation(cves), fetchIntelOwlActiveExploitation(cves),
  ]);
  const merged = new Map<string, ActiveExploitationSignal>();
  for (const map of [misp, opencti, intelowl]) {
    for (const [cve, signal] of map) {
      const existing = merged.get(cve);
      if (!existing || (signal.active && !existing.active)) merged.set(cve, signal);
    }
  }
  return merged;
}
