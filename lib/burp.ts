import type { Severity } from "@/lib/types";

// Burp Suite adapter — human-validated web-app pentest findings (class: pentest).
//
// Two ingestion paths, mirroring the other connectors:
//   1. Burp Suite Enterprise — GraphQL API (BURP_API_URL + BURP_API_KEY).
//   2. Burp Suite Professional — XML issue export uploaded from the UI.
//
// This is a ready-to-connect skeleton: the field mapping and normalizer are
// wired; point BURP_API_URL/BURP_API_KEY at a real Enterprise instance (or drop
// in an XML export) and it flows in as pentest findings.
//
// Configure with:
//   BURP_API_URL   base URL of Burp Suite Enterprise (e.g. https://burp.gmi.com)
//   BURP_API_KEY   an Enterprise API key (sent as the Authorization header)

export type BurpConfig = { url: string; apiKey: string };

export function burpConfig(): BurpConfig | null {
  const url = process.env.BURP_API_URL;
  const apiKey = process.env.BURP_API_KEY;
  if (!url || !apiKey) return null;
  return { url: url.replace(/\/+$/, ""), apiKey };
}

// Normalized issue the store consumes, independent of Burp's exact payloads.
export type BurpFinding = {
  cve: string; // a referenced CVE if present, else BURP-<type>
  title: string;
  severity: Severity;
  cvss: number;
  asset: string; // affected host/origin
  port: string;
  path: string; // request path the issue was found on
  category: string;
  description: string;
  remediation: string;
  confidence: string; // Certain / Firm / Tentative
};

const CVE_RE = /CVE-\d{4}-\d{4,}/i;

// Burp severities -> our scale. Burp uses high/medium/low/info(rmational).
function mapSeverity(raw: unknown): Severity {
  const v = String(raw ?? "").toLowerCase();
  if (v.startsWith("high")) return "High";
  if (v.startsWith("med")) return "Medium";
  if (v.startsWith("low")) return "Low";
  if (v.startsWith("crit")) return "Critical";
  return "Info";
}

// A defensible CVSS proxy from Burp severity (Burp issues rarely carry CVSS).
function severityCvss(sev: Severity): number {
  return { Critical: 9.5, High: 8.0, Medium: 5.5, Low: 3.0, Info: 0 }[sev];
}

function firstCve(...texts: string[]): string | null {
  for (const t of texts) {
    const m = String(t ?? "").match(CVE_RE);
    if (m) return m[0].toUpperCase();
  }
  return null;
}

// --- Reachability probe -----------------------------------------------------
// Safe to expose: reports only configuration + liveness, never issue data.
export async function burpStatus(): Promise<{
  configured: boolean;
  reachable: boolean;
  status: string;
  message: string;
}> {
  const config = burpConfig();
  if (!config) {
    return {
      configured: false,
      reachable: false,
      status: "Not Configured",
      message: "Set BURP_API_URL and BURP_API_KEY, or upload a Burp XML export.",
    };
  }
  try {
    const res = await fetch(`${config.url}/graphql/v1`, {
      method: "POST",
      headers: {
        Authorization: config.apiKey,
        "Content-Type": "application/json",
        Accept: "application/json",
      },
      body: JSON.stringify({ query: "query { __typename }" }),
      cache: "no-store",
    });
    return {
      configured: true,
      reachable: res.ok,
      status: res.ok ? "Connected" : `HTTP ${res.status}`,
      message: res.ok
        ? "Burp Suite Enterprise reachable."
        : await res.text().catch(() => res.statusText),
    };
  } catch (err) {
    return {
      configured: true,
      reachable: false,
      status: "Unreachable",
      message: err instanceof Error ? err.message : "Connection failed.",
    };
  }
}

// --- Enterprise GraphQL pull ------------------------------------------------
// Burp Suite Enterprise exposes scan issues via GraphQL at /graphql/v1. The
// exact schema varies by version, so this is intentionally defensive: adjust
// the query/paths to your instance's schema when you connect it.
export async function burpListIssues(): Promise<BurpFinding[]> {
  const config = burpConfig();
  if (!config) throw new Error("Burp is not configured. Set BURP_API_URL and BURP_API_KEY.");

  const query = `
    query { scans(limit: 50) { id site_name issues {
      name severity confidence path origin
      description remediation issue_type { type_index } } } }`;

  const res = await fetch(`${config.url}/graphql/v1`, {
    method: "POST",
    headers: {
      Authorization: config.apiKey,
      "Content-Type": "application/json",
      Accept: "application/json",
    },
    body: JSON.stringify({ query }),
    cache: "no-store",
  });
  if (!res.ok) {
    throw new Error(`Burp ${res.status}: ${await res.text().catch(() => res.statusText)}`);
  }
  const data: any = await res.json();
  const out: BurpFinding[] = [];
  for (const scan of data?.data?.scans ?? []) {
    for (const i of scan?.issues ?? []) {
      const severity = mapSeverity(i?.severity);
      const origin = String(i?.origin ?? scan?.site_name ?? "");
      const host = origin.replace(/^https?:\/\//, "").split("/")[0] || origin;
      const cve = firstCve(i?.name, i?.description);
      out.push({
        cve: cve ?? `BURP-${String(i?.issue_type?.type_index ?? i?.name ?? "issue")}`.toUpperCase(),
        title: String(i?.name ?? "Burp issue"),
        severity,
        cvss: severityCvss(severity),
        asset: host,
        port: origin.startsWith("https") ? "443" : origin.startsWith("http") ? "80" : "N/A",
        path: String(i?.path ?? "/"),
        category: "Web Vulnerability",
        description: String(i?.description ?? "Reported by Burp Suite."),
        remediation: String(i?.remediation ?? "See the Burp issue detail for remediation."),
        confidence: String(i?.confidence ?? "Firm"),
      });
    }
  }
  return out;
}

// --- Professional XML import ------------------------------------------------
// Burp Professional exports issues as XML (<issues><issue>...). Lightweight
// regex parse (values are wrapped in CDATA), used for the upload fallback.
// Burp elements can carry attributes (notably <host ip="...">), so allow an
// optional attribute list on the opening tag.
function tag(block: string, name: string): string {
  const m = block.match(
    new RegExp(`<${name}(?:\\s[^>]*)?>(?:<!\\[CDATA\\[)?([\\s\\S]*?)(?:\\]\\]>)?</${name}>`, "i"),
  );
  return m ? m[1].trim() : "";
}

export function parseBurpXml(text: string): BurpFinding[] {
  const out: BurpFinding[] = [];
  const blocks = text.match(/<issue\b[\s\S]*?<\/issue>/gi) ?? [];
  for (const b of blocks) {
    const severity = mapSeverity(tag(b, "severity"));
    const host = tag(b, "host").replace(/^https?:\/\//, "").split("/")[0];
    const name = tag(b, "name");
    const desc = tag(b, "issueBackground") || tag(b, "issueDetail");
    const cve = firstCve(name, desc, tag(b, "references"));
    out.push({
      cve: cve ?? `BURP-${(tag(b, "type") || name || "issue").toUpperCase()}`,
      title: name || "Burp issue",
      severity,
      cvss: severityCvss(severity),
      asset: host || tag(b, "host"),
      port: /https/i.test(tag(b, "host")) ? "443" : "80",
      path: tag(b, "path") || "/",
      category: "Web Vulnerability",
      description: desc || "Imported from a Burp Suite XML export.",
      remediation: tag(b, "remediationBackground") || "See the Burp issue detail.",
      confidence: tag(b, "confidence") || "Firm",
    });
  }
  return out;
}
