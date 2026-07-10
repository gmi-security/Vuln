import { NextResponse } from "next/server";
import {
  ensureHydrated,
  getCompany,
  listFindings,
  withSlaInfo,
} from "@/lib/store";
import { emailConfigured, sendRemediationEmail } from "@/lib/alerts";
import type { Finding } from "@/lib/types";

export const dynamic = "force-dynamic";

const MAX_FINDINGS = 100;

// Remediation handoff: email each affected customer ONE list of the selected
// findings (title, CVE, severity, asset, SLA due date). Test customers are
// never emailed. Note: findings carry no notes/history field, so the handoff
// is not recorded on the finding itself.
export async function POST(request: Request) {
  await ensureHydrated();
  let body: { findingIds?: unknown };
  try {
    body = await request.json();
  } catch {
    return NextResponse.json({ error: "Invalid JSON body." }, { status: 400 });
  }
  const ids = body.findingIds;
  if (
    !Array.isArray(ids) ||
    ids.length === 0 ||
    ids.some((id) => typeof id !== "string")
  ) {
    return NextResponse.json(
      { error: "findingIds must be a non-empty array of strings." },
      { status: 400 },
    );
  }
  if (ids.length > MAX_FINDINGS) {
    return NextResponse.json(
      { error: `At most ${MAX_FINDINGS} findings per handoff.` },
      { status: 400 },
    );
  }

  const wanted = new Set(ids as string[]);
  const byCompany = new Map<string, Finding[]>();
  for (const f of listFindings()) {
    if (!wanted.has(f.id)) continue;
    const list = byCompany.get(f.companyId) ?? [];
    list.push(f);
    byCompany.set(f.companyId, list);
  }

  const sent: { companyId: string; count: number }[] = [];
  const skipped: { companyId: string; reason: string }[] = [];
  for (const [companyId, findings] of byCompany) {
    const company = getCompany(companyId);
    if (!company) {
      skipped.push({ companyId, reason: "company not found" });
      continue;
    }
    if (/splashworks/i.test(company.name)) {
      skipped.push({ companyId, reason: "test customer" });
      continue;
    }
    if (!emailConfigured()) {
      skipped.push({ companyId, reason: "email not configured" });
      continue;
    }
    if (!company.contactEmail) {
      skipped.push({ companyId, reason: "no contact email" });
      continue;
    }
    const ok = await sendRemediationEmail({
      to: company.contactEmail,
      contactName: company.contactName,
      companyName: company.name,
      companyId,
      findings: findings.map(withSlaInfo).map((f) => ({
        title: f.title,
        cve: f.cve,
        severity: f.severity,
        asset: f.asset,
        dueAt: f.dueAt ?? null,
      })),
    });
    if (ok) sent.push({ companyId, count: findings.length });
    else skipped.push({ companyId, reason: "email send failed" });
  }

  return NextResponse.json({ sent, skipped });
}
