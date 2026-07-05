// GMI GRC (OpenGRC) integration.
//
// OpenGRC is a Laravel/Filament GRC platform (Sanctum bearer-token auth). We
// push vulnerability-derived risks and compliance posture into it so audit and
// compliance live in one place. Resources used: /api/risks (and /api/assets).
//
// Configure with:
//   GRC_API_URL    base URL (e.g. http://64.227.55.62:8080)
//   GRC_API_TOKEN  Sanctum token from Profile Settings

export type GrcConfig = {
  baseUrl: string;
  token: string;
};

export function grcConfig(): GrcConfig | null {
  const baseUrl = process.env.GRC_API_URL;
  const token = process.env.GRC_API_TOKEN;
  if (!baseUrl || !token) return null;
  return { baseUrl: baseUrl.replace(/\/+$/, ""), token };
}

async function grcRequest(
  config: GrcConfig,
  method: string,
  path: string,
  body?: unknown,
): Promise<any> {
  const res = await fetch(`${config.baseUrl}${path}`, {
    method,
    headers: {
      Authorization: `Bearer ${config.token}`,
      Accept: "application/json",
      ...(body ? { "Content-Type": "application/json" } : {}),
    },
    body: body ? JSON.stringify(body) : undefined,
    cache: "no-store",
  });
  if (!res.ok) {
    throw new Error(
      `GRC ${method} ${path} failed: ${res.status} ${await res.text().catch(() => res.statusText)}`,
    );
  }
  return res.json().catch(() => ({}));
}

// Read-only probe to learn the live OpenGRC schema (standards + risk fields)
// before pushing, so the payload matches this instance.
export async function grcProbe(): Promise<{
  configured: boolean;
  standards: unknown[];
  riskFields: string[];
  riskSample: unknown;
  error?: string;
}> {
  const config = grcConfig();
  if (!config) return { configured: false, standards: [], riskFields: [], riskSample: null };
  try {
    const [standards, risks] = await Promise.all([
      grcRequest(config, "GET", "/api/standards?per_page=50").catch(() => null),
      grcRequest(config, "GET", "/api/risks?per_page=1").catch(() => null),
    ]);
    const stdList = standards?.data ?? standards ?? [];
    const riskList = risks?.data ?? risks ?? [];
    const sample = Array.isArray(riskList) ? riskList[0] : null;
    return {
      configured: true,
      standards: (Array.isArray(stdList) ? stdList : []).map((s: any) => ({
        id: s?.id,
        name: s?.name ?? s?.code ?? s?.title,
      })),
      riskFields: sample ? Object.keys(sample) : [],
      riskSample: sample,
    };
  } catch (err) {
    return {
      configured: true,
      standards: [],
      riskFields: [],
      riskSample: null,
      error: err instanceof Error ? err.message : "probe failed",
    };
  }
}

// Matches the OpenGRC `Risk` table's NOT-NULL-without-default columns: `name`,
// `code` (unique), and `description`. Everything else (status, inherent_*,
// residual_*) carries a DB default, so we don't need to send it.
//
// NOTE: the OpenGRC REST API (LeeMangold/OpenGRC) ships a RiskController whose
// validateStore/validateUpdate only whitelist a subset of columns, and Laravel's
// $request->validate() strips anything not in the rules before it reaches
// Risk::create(). So a field only lands in the row if the server-side rules
// list it. The GMI OpenGRC instance has been patched to whitelist `name` and
// `code`; we send both (plus description) here to match.
export type GrcRisk = {
  name: string;
  code: string;
  description: string;
};

// Build a unique, human-legible risk code (OpenGRC requires `code` to be unique
// and non-null). Company slug + base36 timestamp keeps re-pushes collision-free.
function riskCode(companyName: string): string {
  const slug = companyName
    .toUpperCase()
    .replace(/[^A-Z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "")
    .slice(0, 24);
  return `VULN-${slug || "RISK"}-${Date.now().toString(36).toUpperCase()}`;
}

export async function grcCreateRisk(risk: GrcRisk): Promise<{ id: unknown }> {
  const config = grcConfig();
  if (!config) throw new Error("GRC is not configured.");
  const data = await grcRequest(config, "POST", "/api/risks", risk);
  return { id: data?.data?.id ?? data?.id ?? null };
}

export type GrcFrameworkEvidence = {
  name: string;
  score: number;
  overall: string;
  failing: { id: string; title: string; detail: string }[];
};

export function buildRisk(input: {
  companyName: string;
  compositeScore: number;
  openTotal: number;
  criticalOpen: number;
  kevOpen: number;
  asvFailing: number;
  overall: string;
  topFindings: { cve: string; title: string; asset: string; realRisk: number }[];
  frameworks?: GrcFrameworkEvidence[];
}): GrcRisk {
  const lines = input.topFindings
    .slice(0, 10)
    .map(
      (f) =>
        `- [${f.realRisk}] ${f.cve} — ${f.title} on ${f.asset}`,
    )
    .join("\n");

  // Control-level compliance evidence across every mapped framework, so the GRC
  // record carries pass/fail per control — not just an aggregate risk number.
  const complianceBlock =
    input.frameworks && input.frameworks.length
      ? [
          ``,
          `Compliance posture (control-level evidence):`,
          ...input.frameworks.flatMap((fw) => {
            const head = `- ${fw.name}: ${fw.overall} (${fw.score}/100)`;
            const controls = fw.failing.length
              ? fw.failing.map((c) => `    · ${c.id} ${c.title} — FAIL: ${c.detail}`)
              : [`    · all mapped controls passing`];
            return [head, ...controls];
          }),
        ]
      : [];

  const description = [
    `Aggregated vulnerability risk for ${input.companyName} (source: GMI Vuln console).`,
    ``,
    `Composite risk: ${input.compositeScore}/100 · Overall: ${input.overall}`,
    `Open findings: ${input.openTotal} · Critical: ${input.criticalOpen} · Actively exploited (KEV): ${input.kevOpen} · ASV-failing (CVSS ≥ 4.0, internet-facing): ${input.asvFailing}`,
    ...complianceBlock,
    ``,
    `Top findings:`,
    lines || "- none",
  ].join("\n");

  return {
    name: `Unremediated vulnerabilities — ${input.companyName}`,
    code: riskCode(input.companyName),
    description,
  };
}
