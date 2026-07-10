import { NextResponse } from "next/server";
import {
  buildCustomerReportData,
  ensureHydrated,
  markReportSent,
} from "@/lib/store";
import {
  buildCustomerReportHtml,
  emailConfigured,
  sendEmail,
} from "@/lib/alerts";

export const dynamic = "force-dynamic";

// Loose "looks like an email" check for optional cc entries — the real
// validation is Resend's; this just rejects obvious garbage early.
const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const MAX_CC = 5;

// POST /api/report/[companyId]/send — email the full customer report (with a
// what-changed delta once a previous send exists) to the company contact.
// Session-authed by the edge proxy like every other /api route.
export async function POST(
  request: Request,
  { params }: { params: Promise<{ companyId: string }> },
) {
  await ensureHydrated();
  const { companyId } = await params;

  // No body required; optionally { cc?: string[] }.
  let cc: string[] = [];
  const body = (await request.json().catch(() => ({}))) as { cc?: unknown };
  if (body.cc !== undefined) {
    if (
      !Array.isArray(body.cc) ||
      body.cc.some((x) => typeof x !== "string" || !EMAIL_RE.test(x.trim()))
    ) {
      return NextResponse.json(
        { error: "cc must be an array of email addresses." },
        { status: 400 },
      );
    }
    cc = (body.cc as string[]).map((x) => x.trim());
    if (cc.length > MAX_CC) {
      return NextResponse.json(
        { error: `cc is limited to ${MAX_CC} addresses.` },
        { status: 400 },
      );
    }
  }

  const data = buildCustomerReportData(companyId);
  if ("error" in data) {
    if (data.error === "Company not found.") {
      return NextResponse.json({ error: data.error }, { status: 404 });
    }
    // Test customer — never email outward.
    return NextResponse.json(
      { error: "This is a test customer — reports are not sent externally." },
      { status: 400 },
    );
  }
  if (!data.company.contactEmail) {
    return NextResponse.json(
      { error: "This company has no contact email on file." },
      { status: 400 },
    );
  }
  if (!emailConfigured()) {
    return NextResponse.json(
      { error: "Email is not configured (RESEND_API_KEY / REPORT_FROM_EMAIL)." },
      { status: 503 },
    );
  }

  const { subject, html } = buildCustomerReportHtml({
    companyId: data.company.id,
    companyName: data.company.name,
    contactName: data.company.contactName,
    generatedAt: data.report.generatedAt,
    posture: data.report.posture,
    openBySeverity: {
      Critical: data.report.sla.bySeverity.Critical.open,
      High: data.report.sla.bySeverity.High.open,
      Medium: data.report.sla.bySeverity.Medium.open,
      Low: data.report.sla.bySeverity.Low.open,
      Info: data.report.sla.bySeverity.Info.open,
    },
    sla: data.report.sla,
    topRisks: data.topRisks,
    delta: data.delta,
  });

  const ok = await sendEmail({
    to: [data.company.contactEmail, ...cc],
    subject,
    html,
  });
  if (!ok) {
    return NextResponse.json(
      { error: "Email send failed — see server logs." },
      { status: 502 },
    );
  }

  markReportSent(companyId);
  return NextResponse.json({
    sent: true,
    to: data.company.contactEmail,
    cc,
    delta: data.delta !== null,
  });
}
