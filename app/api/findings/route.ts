import { NextResponse } from "next/server";
import { ensureHydrated, listFindings, withSlaInfo } from "@/lib/store";

export const dynamic = "force-dynamic";

const DEFAULT_LIMIT = 200;
const MAX_LIMIT = 1000;

export async function GET(request: Request) {
  await ensureHydrated();
  const { searchParams } = new URL(request.url);
  const scanId = searchParams.get("scanId") ?? undefined;
  const companyId = searchParams.get("companyId") ?? undefined;
  const kindParam = searchParams.get("kind");
  const kind =
    kindParam === "osint" || kindParam === "pentest" || kindParam === "all"
      ? kindParam
      : "vuln";
  const severity = searchParams.get("severity") ?? undefined;
  const status = searchParams.get("status") ?? undefined;
  const connector = searchParams.get("connector") ?? undefined;
  const exploitOnly = searchParams.get("exploit") === "1";
  const overdueOnly = searchParams.get("overdue") === "1";
  const q = (searchParams.get("q") ?? "").trim().toLowerCase();
  const limitParam = Number.parseInt(searchParams.get("limit") ?? "", 10);
  const limit = Number.isFinite(limitParam)
    ? Math.min(Math.max(limitParam, 1), MAX_LIMIT)
    : DEFAULT_LIMIT;
  const offsetParam = Number.parseInt(searchParams.get("offset") ?? "", 10);
  const offset =
    Number.isFinite(offsetParam) && offsetParam > 0 ? offsetParam : 0;

  // listFindings already returns real-risk display order; filter server-side
  // so the client only ever receives a single page of results. Decorating
  // with SLA info up front lets overdue=1 filter on the computed field.
  let findings = listFindings({ scanId, companyId, kind }).map(withSlaInfo);
  if (overdueOnly) findings = findings.filter((f) => f.overdue);
  if (severity) findings = findings.filter((f) => f.severity === severity);
  if (status) findings = findings.filter((f) => f.status === status);
  if (connector) findings = findings.filter((f) => f.connector === connector);
  if (exploitOnly) findings = findings.filter((f) => f.exploitAvailable);
  if (q) {
    findings = findings.filter((f) =>
      `${f.cve} ${f.title} ${f.asset} ${f.category} ${f.companyName}`
        .toLowerCase()
        .includes(q),
    );
  }

  const total = findings.length;
  return NextResponse.json({
    findings: findings.slice(offset, offset + limit),
    total,
    limit,
    offset,
  });
}
