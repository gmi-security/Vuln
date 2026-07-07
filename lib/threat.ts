// Threat intelligence + environmental context → "real risk".
//
// Real risk blends three layers, the way risk-based VM tools (Tenable VPR,
// Kenna, SSVC) do:
//   1. Base impact  — the CVSS base score.
//   2. Threat       — is it exploited in the wild? (CISA KEV), how likely
//                     soon (EPSS), is a public exploit available.
//   3. Environment  — what the affected asset actually is: how exposed
//                     (internet-facing vs isolated) and how critical.
//
// A medium-CVSS bug that is actively exploited on an internet-facing crown
// jewel outranks a high-CVSS bug sitting on an isolated, low-value host.

// CISA Known Exploited Vulnerabilities — CVEs confirmed exploited in the
// wild. This is the curated subset covering the demo catalog; the deployed
// app can also refresh from the live CISA KEV feed (see refreshKevFromCisa).
export const KEV_CVES = new Set<string>([
  "CVE-2024-3400",
  "CVE-2023-4966",
  "CVE-2024-21762",
  "CVE-2021-44228",
  "CVE-2024-1709",
  "CVE-2023-34362",
  "CVE-2023-23397",
  "CVE-2024-26169",
  "CVE-2023-38831",
  "CVE-2022-22965",
  "CVE-2023-44487",
  "CVE-2021-34473",
  "CVE-2019-0708",
  "CVE-2023-27997",
  "CVE-2024-4577",
  "CVE-2022-30190",
  "CVE-2023-20198",
  "CVE-2020-1472",
  "CVE-2017-0144",
  "CVE-2021-40438",
  "CVE-2022-1388",
  "CVE-2023-22515",
  "CVE-2024-27198",
  "CVE-2018-13379",
  "CVE-2023-46805",
  "CVE-2024-47575",
  "CVE-2022-26134",
  "CVE-2024-20353",
  "CVE-2019-19781",
]);

// Runtime-mutable overlay so the live CISA feed can extend the baseline set.
const kevRuntime = new Set<string>();
// CVEs the CISA KEV catalog flags as used in ransomware campaigns — the
// highest-confidence "fix this now" signal (open-source threat-actor context).
const kevRansomware = new Set<string>();

export function isKev(cve: string): boolean {
  return KEV_CVES.has(cve) || kevRuntime.has(cve);
}

export function isKevRansomware(cve: string): boolean {
  return kevRansomware.has(cve.toUpperCase());
}

// Live EPSS (Exploit Prediction Scoring System) from FIRST.org — probability a
// CVE is exploited in the next 30 days. Batched; best-effort per batch so a
// single failure never blocks enrichment.
export async function fetchEpss(cves: string[]): Promise<Map<string, number>> {
  const out = new Map<string, number>();
  const uniq = Array.from(new Set(cves.map((c) => c.toUpperCase()))).filter((c) =>
    /^CVE-\d{4}-\d{4,}$/.test(c),
  );
  const BATCH = 80;
  for (let i = 0; i < uniq.length && i < 12_000; i += BATCH) {
    const batch = uniq.slice(i, i + BATCH);
    try {
      const res = await fetch(
        `https://api.first.org/data/v1/epss?cve=${batch.join(",")}`,
        { cache: "no-store" },
      );
      if (!res.ok) continue;
      const json = (await res.json()) as {
        data?: { cve?: string; epss?: string }[];
      };
      for (const d of json.data ?? []) {
        const v = Number(d.epss);
        if (d.cve && !Number.isNaN(v)) out.set(d.cve.toUpperCase(), v);
      }
    } catch {
      // best-effort per batch
    }
  }
  return out;
}

// Best-effort refresh from the public CISA KEV catalog. Safe to call on a
// timer from the server; failures are swallowed so scoring still works
// offline from the bundled set.
export async function refreshKevFromCisa(): Promise<number> {
  try {
    const res = await fetch(
      "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
      { cache: "no-store" },
    );
    if (!res.ok) return 0;
    const data = (await res.json()) as {
      vulnerabilities?: { cveID?: string; knownRansomwareCampaignUse?: string }[];
    };
    let added = 0;
    for (const v of data.vulnerabilities ?? []) {
      if (!v.cveID) continue;
      const id = v.cveID.toUpperCase();
      if (!kevRuntime.has(id)) {
        kevRuntime.add(id);
        added += 1;
      }
      if ((v.knownRansomwareCampaignUse ?? "").toLowerCase() === "known") {
        kevRansomware.add(id);
      }
    }
    return added;
  } catch {
    return 0;
  }
}

// --- NVD open-source CVE enrichment ----------------------------------------
// Fill in the CVSS base score (and CWE) for CVEs that came in without one —
// common when a CVE is detected by OSINT/text-match rather than a scanner.
// Uses the public NVD 2.0 API (keyless works; NVD_API_KEY raises the rate
// limit). Best-effort, cached, and capped so it never hammers the API or
// blocks enrichment.
const nvdCache = new Map<string, { cvss: number; cwe: string | null }>();

export async function fetchNvd(
  cves: string[],
  max = 25,
): Promise<Map<string, { cvss: number; cwe: string | null }>> {
  const out = new Map<string, { cvss: number; cwe: string | null }>();
  const key = process.env.NVD_API_KEY?.trim();
  const uniq = Array.from(new Set(cves.map((c) => c.toUpperCase()))).filter((c) =>
    /^CVE-\d{4}-\d{4,}$/.test(c),
  );
  let fetched = 0;
  for (const cve of uniq) {
    if (nvdCache.has(cve)) {
      out.set(cve, nvdCache.get(cve)!);
      continue;
    }
    if (fetched >= max) break;
    fetched += 1;
    try {
      const res = await fetch(
        `https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=${cve}`,
        { headers: key ? { apiKey: key } : {}, cache: "no-store" },
      );
      if (res.status === 403 || res.status === 429) break; // rate-limited; stop
      if (!res.ok) continue;
      const json: any = await res.json();
      const c = json?.vulnerabilities?.[0]?.cve;
      if (!c) continue;
      const metrics = c.metrics ?? {};
      const m =
        (metrics.cvssMetricV31 ?? metrics.cvssMetricV30 ?? metrics.cvssMetricV2 ?? [])[0]
          ?.cvssData ?? {};
      const cwe =
        c.weaknesses
          ?.flatMap((w: any) => w.description ?? [])
          .map((d: any) => d.value)
          .find((v: string) => typeof v === "string" && v.startsWith("CWE-")) ?? null;
      const entry = { cvss: Number(m.baseScore ?? 0) || 0, cwe };
      nvdCache.set(cve, entry);
      out.set(cve, entry);
    } catch {
      // best-effort per CVE
    }
    // Gentle pacing to respect NVD rate limits (looser with a key).
    await new Promise((r) => setTimeout(r, key ? 120 : 700));
  }
  return out;
}

export type AssetExposure = "Internet-facing" | "Internal" | "Isolated";
export type AssetCriticality = "Crown Jewel" | "High" | "Normal" | "Low";

const EXPOSURE_FACTOR: Record<AssetExposure, number> = {
  "Internet-facing": 1.4,
  Internal: 1.0,
  Isolated: 0.7,
};

const CRITICALITY_FACTOR: Record<AssetCriticality, number> = {
  "Crown Jewel": 1.4,
  High: 1.2,
  Normal: 1.0,
  Low: 0.8,
};

// Infer environmental context from the asset identifier. Real deployments
// would source this from a CMDB / asset inventory; these heuristics give a
// sensible default from hostnames and addresses.
export function classifyAsset(asset: string): {
  exposure: AssetExposure;
  criticality: AssetCriticality;
} {
  const a = asset.toLowerCase();

  let exposure: AssetExposure = "Internal";
  const internetHints = [
    "vpn",
    "mail",
    "web",
    "www",
    "portal",
    "edge",
    "dmz",
    "ext",
    "gw",
    "gateway",
    "public",
  ];
  const isPublicDomain = /\.(com|net|org|io|co)\b/.test(a);
  const isPublicIp =
    /\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b/.test(a) &&
    !/^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.)/.test(a);
  if (internetHints.some((h) => a.includes(h)) || isPublicDomain || isPublicIp) {
    exposure = "Internet-facing";
  }
  if (a.includes("isolated") || a.includes("ot") || a.includes("scada") || a.includes("air")) {
    exposure = "Isolated";
  }

  let criticality: AssetCriticality = "Normal";
  const crownHints = ["dc0", "dc1", "dc2", "-dc", "sql", "db-", "database", "erp", "sap", "vault", "-ca", "pki", "backup"];
  const highHints = ["prod", "esxi", "nas", "files", "app-", "mail", "vpn", "fw-"];
  const lowHints = ["ws-", "wks", "test", "dev", "lab", "print"];
  if (crownHints.some((h) => a.includes(h))) criticality = "Crown Jewel";
  else if (highHints.some((h) => a.includes(h))) criticality = "High";
  else if (lowHints.some((h) => a.includes(h))) criticality = "Low";

  return { exposure, criticality };
}

export type RiskPriority = "Critical" | "High" | "Medium" | "Low" | "Info";

export function riskPriority(score: number): RiskPriority {
  if (score >= 80) return "Critical";
  if (score >= 60) return "High";
  if (score >= 40) return "Medium";
  if (score >= 20) return "Low";
  return "Info";
}

// Compose the three layers into a 0-100 real-risk score. Each layer is a
// 0-1 factor and they multiply, so a finding only approaches 100 when the
// vulnerability is severe AND exploited in the wild AND on an exposed,
// critical asset. CVSS alone can't saturate the score — that's the point of
// risk-based prioritization.
export function computeRealRisk(input: {
  cvss: number;
  kev: boolean;
  epss: number;
  exploitAvailable: boolean;
  exposure: AssetExposure;
  criticality: AssetCriticality;
  ransomware?: boolean;
}): { score: number; priority: RiskPriority } {
  const epss = Math.max(0, Math.min(1, input.epss));

  // Impact: normalized CVSS base score.
  const impact = Math.max(0, Math.min(1, input.cvss / 10));

  // Threat: likelihood/evidence of real-world exploitation. A KEV used in
  // ransomware campaigns is the strongest signal, so it saturates the layer.
  const threat = Math.min(
    1,
    0.2 +
      (input.kev ? 0.5 : 0) +
      (input.ransomware ? 0.25 : 0) +
      (input.exploitAvailable ? 0.2 : 0) +
      0.3 * epss,
  );

  // Environment: how exposed and how critical the affected asset is,
  // normalized to a 0.65–1.0 band (an isolated, low-value host still carries
  // some risk; a crown jewel on the internet carries the most).
  const prod =
    EXPOSURE_FACTOR[input.exposure] * CRITICALITY_FACTOR[input.criticality];
  const envNorm = 0.65 + 0.35 * ((prod - 0.56) / 1.4);

  const score = Math.max(0, Math.min(100, Math.round(100 * impact * threat * envNorm)));
  return { score, priority: riskPriority(score) };
}
