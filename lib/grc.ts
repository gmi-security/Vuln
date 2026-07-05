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

// End-to-end connection test for every read path: verifies reachability, token
// validity, and the live schema of each OpenGRC resource we integrate with
// (risks, standards, controls, implementations). Never throws.
export async function grcProbe(): Promise<{
  configured: boolean;
  reachable: boolean;
  authOk: boolean;
  risksCount: number;
  standardsCount: number;
  controlsCount: number;
  implementationsCount: number;
  standards: { id: unknown; name: unknown }[];
  riskFields: string[];
  riskSample: unknown;
  controlFields: string[];
  controlSample: unknown;
  error?: string;
}> {
  const base = {
    configured: true,
    reachable: false,
    authOk: false,
    risksCount: 0,
    standardsCount: 0,
    controlsCount: 0,
    implementationsCount: 0,
    standards: [] as { id: unknown; name: unknown }[],
    riskFields: [] as string[],
    riskSample: null as unknown,
    controlFields: [] as string[],
    controlSample: null as unknown,
  };
  const config = grcConfig();
  if (!config) return { ...base, configured: false };

  const count = (res: any, list: any[]): number =>
    Number(
      res?.meta?.total ??
        res?.total ??
        res?.meta?.pagination?.total ??
        res?.pagination?.total ??
        (Array.isArray(list) ? list.length : 0),
    );
  const listOf = (res: any): any[] =>
    res?.data ?? (Array.isArray(res) ? res : []) ?? [];

  // Anchor call on /api/risks: success => reachable + authOk; a 401 => reachable
  // but bad token; a network error => not reachable.
  let risksRes: any;
  try {
    risksRes = await grcRequest(config, "GET", "/api/risks?per_page=1");
  } catch (err) {
    const msg = err instanceof Error ? err.message : "probe failed";
    const is401 = / 401\b/.test(msg);
    return {
      ...base,
      reachable: is401 || / 4\d\d| 5\d\d/.test(msg),
      authOk: false,
      error: msg,
    };
  }

  const riskList = listOf(risksRes);
  const sample = Array.isArray(riskList) ? riskList[0] : null;
  const out = {
    ...base,
    reachable: true,
    authOk: true,
    risksCount: count(risksRes, riskList),
    riskFields: sample ? Object.keys(sample) : [],
    riskSample: sample,
  };

  // Best-effort reads of the other resources (don't fail the whole probe).
  const [std, ctl, impl] = await Promise.all([
    grcRequest(config, "GET", "/api/standards?per_page=50").catch(() => null),
    grcRequest(config, "GET", "/api/controls?per_page=1").catch(() => null),
    grcRequest(config, "GET", "/api/implementations?per_page=1").catch(() => null),
  ]);
  const stdList = listOf(std);
  const ctlList = listOf(ctl);
  const ctlSample = Array.isArray(ctlList) ? ctlList[0] : null;
  out.standardsCount = count(std, stdList);
  out.controlsCount = count(ctl, ctlList);
  out.implementationsCount = count(impl, listOf(impl));
  out.standards = (Array.isArray(stdList) ? stdList : []).map((s: any) => ({
    id: s?.id,
    name: s?.name ?? s?.code ?? s?.title,
  }));
  out.controlFields = ctlSample ? Object.keys(ctlSample) : [];
  out.controlSample = ctlSample;
  return out;
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

// Stable, deterministic per-company risk code (OpenGRC requires `code` unique +
// non-null). STABLE — no timestamp — so re-pushes resolve to the SAME record
// and update it instead of creating duplicate governance entries.
export function riskCode(companyName: string): string {
  const slug = companyName
    .toUpperCase()
    .replace(/[^A-Z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "")
    .slice(0, 32);
  return `VULN-${slug || "RISK"}`;
}

export async function grcCreateRisk(risk: GrcRisk): Promise<{ id: unknown }> {
  const config = grcConfig();
  if (!config) throw new Error("GRC is not configured.");
  const data = await grcRequest(config, "POST", "/api/risks", risk);
  return { id: data?.data?.id ?? data?.id ?? null };
}

// Find an existing risk id by our stable code (preferred) or exact name.
// Paginates defensively so it works whether or not the index honors ?search.
async function grcFindRiskId(
  config: GrcConfig,
  code: string,
  name: string,
): Promise<unknown | null> {
  for (let page = 1; page <= 20; page += 1) {
    const res = await grcRequest(
      config,
      "GET",
      `/api/risks?page=${page}&per_page=100`,
    ).catch(() => null);
    const list: any[] = res?.data ?? (Array.isArray(res) ? res : []) ?? [];
    if (!Array.isArray(list) || list.length === 0) break;
    const hit =
      list.find((r) => r?.code === code) ?? list.find((r) => r?.name === name);
    if (hit) return hit.id;
    const meta = res?.meta;
    if (meta && Number(meta.current_page) >= Number(meta.last_page)) break;
    if (list.length < 100) break;
  }
  return null;
}

// Idempotent push: update the company's canonical risk if it exists, else
// create it. Guarantees one governance record per company, always current.
export async function grcUpsertRisk(
  risk: GrcRisk,
): Promise<{ id: unknown; created: boolean }> {
  const config = grcConfig();
  if (!config) throw new Error("GRC is not configured.");
  const existingId = await grcFindRiskId(config, risk.code, risk.name);
  if (existingId != null) {
    const data = await grcRequest(config, "PUT", `/api/risks/${existingId}`, risk);
    return { id: data?.data?.id ?? data?.id ?? existingId, created: false };
  }
  const data = await grcRequest(config, "POST", "/api/risks", risk);
  return { id: data?.data?.id ?? data?.id ?? null, created: true };
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
