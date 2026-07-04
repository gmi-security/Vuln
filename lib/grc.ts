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

export type GrcRisk = {
  title: string;
  description: string;
  // OpenGRC scores risk on 1-5 likelihood × impact; we derive from real risk.
  inherent_likelihood: number;
  inherent_impact: number;
  residual_likelihood: number;
  residual_impact: number;
  status: string;
};

// Map a 0-100 score to OpenGRC's 1-5 scale.
function to5(score: number): number {
  return Math.max(1, Math.min(5, Math.ceil(score / 20)));
}

export async function grcCreateRisk(risk: GrcRisk): Promise<{ id: unknown }> {
  const config = grcConfig();
  if (!config) throw new Error("GRC is not configured.");
  const data = await grcRequest(config, "POST", "/api/risks", risk);
  return { id: data?.data?.id ?? data?.id ?? null };
}

export function buildRisk(input: {
  companyName: string;
  compositeScore: number;
  openTotal: number;
  criticalOpen: number;
  kevOpen: number;
  asvFailing: number;
  overall: string;
  topFindings: { cve: string; title: string; asset: string; realRisk: number }[];
}): GrcRisk {
  const lines = input.topFindings
    .slice(0, 10)
    .map(
      (f) =>
        `- [${f.realRisk}] ${f.cve} — ${f.title} on ${f.asset}`,
    )
    .join("\n");
  const description = [
    `Aggregated vulnerability risk for ${input.companyName} (source: GMI Vuln console).`,
    ``,
    `Composite risk: ${input.compositeScore}/100 · PCI DSS 4.0: ${input.overall}`,
    `Open findings: ${input.openTotal} · Critical: ${input.criticalOpen} · Actively exploited (KEV): ${input.kevOpen} · ASV-failing (CVSS ≥ 4.0, internet-facing): ${input.asvFailing}`,
    ``,
    `Top findings:`,
    lines || "- none",
  ].join("\n");

  const impact = to5(input.compositeScore);
  const likelihood = to5(
    Math.min(100, input.kevOpen * 10 + input.asvFailing * 4 + input.criticalOpen * 3),
  );
  return {
    title: `Unremediated vulnerabilities — ${input.companyName}`,
    description,
    inherent_likelihood: likelihood,
    inherent_impact: impact,
    residual_likelihood: likelihood,
    residual_impact: impact,
    status: "Active",
  };
}
