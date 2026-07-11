import type { Severity } from "@/lib/types";

// Outbound notifications: Slack (incoming webhook) and email (Resend HTTP
// API — plain fetch, no SDK). Every sender is best-effort: 10s timeout,
// errors logged and swallowed, never thrown to callers. A channel whose env
// vars are missing is skipped silently (one boot-time log notes the config),
// so alerting degrades to a no-op rather than breaking syncs.
//
// Env:
//   SLACK_WEBHOOK_URL — Slack incoming webhook for the ops channel.
//   RESEND_API_KEY    — Resend API key for all outbound email.
//   REPORT_FROM_EMAIL — verified from-address for Resend sends.
//   ALERT_EMAIL       — ops inbox for alert emails (optional).
//   NEXTAUTH_URL      — console base URL used for links in messages.

const SEND_TIMEOUT_MS = 10_000;
const RESEND_API_URL = "https://api.resend.com/emails";

export function slackConfigured(): boolean {
  return Boolean(process.env.SLACK_WEBHOOK_URL?.trim());
}

// Email needs both the API key and a verified from-address.
export function emailConfigured(): boolean {
  return Boolean(
    process.env.RESEND_API_KEY?.trim() && process.env.REPORT_FROM_EMAIL?.trim(),
  );
}

function alertInbox(): string {
  return process.env.ALERT_EMAIL?.trim() ?? "";
}

// Console base URL for links in messages ("" when NEXTAUTH_URL is unset —
// formatters then emit plain text without a link).
export function consoleBaseUrl(): string {
  return (process.env.NEXTAUTH_URL ?? "").trim().replace(/\/+$/, "");
}

// One log line per process describing which channels are live, so a missing
// env var is diagnosable without spamming every send.
let configLogged = false;
function logConfigOnce(): void {
  if (configLogged) return;
  configLogged = true;
  const parts = [
    `slack=${slackConfigured() ? "on" : "off (SLACK_WEBHOOK_URL unset)"}`,
    `email=${
      emailConfigured()
        ? "on"
        : "off (RESEND_API_KEY / REPORT_FROM_EMAIL unset)"
    }`,
    `alertInbox=${alertInbox() ? "set" : "unset"}`,
  ];
  console.log(`[alerts] channels: ${parts.join(", ")}`);
}

// --- low-level senders -------------------------------------------------------

// Post a message to the Slack webhook. Returns whether the send succeeded.
export async function sendSlack(text: string): Promise<boolean> {
  logConfigOnce();
  if (!slackConfigured()) return false;
  try {
    const res = await fetch(process.env.SLACK_WEBHOOK_URL!.trim(), {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ text }),
      signal: AbortSignal.timeout(SEND_TIMEOUT_MS),
    });
    if (!res.ok) {
      console.error(`[alerts] slack send failed: HTTP ${res.status}`);
      return false;
    }
    return true;
  } catch (err) {
    console.error(
      "[alerts] slack send failed:",
      err instanceof Error ? err.message : err,
    );
    return false;
  }
}

// Send an email through the Resend HTTP API. Returns whether it succeeded.
export async function sendEmail(input: {
  to: string | string[];
  subject: string;
  html: string;
  text?: string;
}): Promise<boolean> {
  logConfigOnce();
  if (!emailConfigured()) return false;
  const to = Array.isArray(input.to) ? input.to : [input.to];
  if (to.length === 0 || to.some((t) => !t.trim())) return false;
  try {
    const res = await fetch(RESEND_API_URL, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${process.env.RESEND_API_KEY!.trim()}`,
      },
      body: JSON.stringify({
        from: process.env.REPORT_FROM_EMAIL!.trim(),
        to,
        subject: input.subject,
        html: input.html,
        ...(input.text ? { text: input.text } : {}),
      }),
      signal: AbortSignal.timeout(SEND_TIMEOUT_MS),
    });
    if (!res.ok) {
      const body = await res.text().catch(() => "");
      console.error(
        `[alerts] email send failed: HTTP ${res.status} ${body.slice(0, 300)}`,
      );
      return false;
    }
    return true;
  } catch (err) {
    console.error(
      "[alerts] email send failed:",
      err instanceof Error ? err.message : err,
    );
    return false;
  }
}

function escapeHtml(text: string): string {
  return text
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

// One-line operational alert to every configured channel (Slack + ops inbox).
// Used by the connector-health watchdog for degraded/recovered transitions.
export async function sendOpsAlert(subject: string, text: string): Promise<void> {
  const inbox = process.env.ALERT_EMAIL?.trim() ?? "";
  await Promise.all([
    sendSlack(`*${subject}*\n${text}`),
    inbox
      ? sendEmail({ to: inbox, subject, html: `<p>${escapeHtml(text)}</p>`, text })
      : Promise.resolve(false),
  ]);
}

// --- config verification (POST /api/alerts/test) -------------------------------

export type AlertTestResult = {
  slack: boolean;
  email: boolean;
  errors?: string[];
};

// Send a test message to every configured channel so the UI can verify the
// alerting config end to end.
export async function sendTestAlert(): Promise<AlertTestResult> {
  const errors: string[] = [];
  const base = consoleBaseUrl();
  const stamp = new Date().toISOString();

  let slack = false;
  if (!slackConfigured()) {
    errors.push("slack: SLACK_WEBHOOK_URL is not set");
  } else {
    slack = await sendSlack(
      `gmi-vuln: test alert — channel is configured correctly.${base ? ` <${base}/dashboard|Open console>` : ""}`,
    );
    if (!slack) errors.push("slack: webhook post failed (see server logs)");
  }

  let email = false;
  if (!emailConfigured()) {
    errors.push("email: RESEND_API_KEY / REPORT_FROM_EMAIL is not set");
  } else if (!alertInbox()) {
    errors.push("email: ALERT_EMAIL is not set");
  } else {
    email = await sendEmail({
      to: alertInbox(),
      subject: "gmi-vuln test alert",
      html: `<p>This is a test alert from the gmi-vuln console (${escapeHtml(stamp)}). Email alerting is configured correctly.</p>${base ? `<p><a href="${base}/dashboard">Open console</a></p>` : ""}`,
      text: `gmi-vuln test alert (${stamp}). Email alerting is configured correctly.`,
    });
    if (!email) errors.push("email: Resend send failed (see server logs)");
  }

  return errors.length ? { slack, email, errors } : { slack, email };
}

// --- post-sync alert evaluation ------------------------------------------------

export type SyncAlertFinding = {
  companyId: string;
  companyName: string;
  cve: string;
  title: string;
  severity: Severity;
  kev: boolean;
  ransomware: boolean;
};

export type SyncAlertInput = {
  // Configured connectors whose sync errored.
  failures: { connector: string; error?: string }[];
  // New Critical/High findings since the last alert evaluation (the caller
  // filters by firstSeen and excludes test customers).
  newSevere: SyncAlertFinding[];
  // New KEV / ransomware-linked findings — called out separately as the
  // drop-everything section (may overlap with newSevere).
  newThreat: SyncAlertFinding[];
};

function groupByCompany(
  findings: SyncAlertFinding[],
): { companyName: string; items: SyncAlertFinding[] }[] {
  const byCompany = new Map<string, { companyName: string; items: SyncAlertFinding[] }>();
  for (const f of findings) {
    const entry = byCompany.get(f.companyId) ?? { companyName: f.companyName, items: [] };
    entry.items.push(f);
    byCompany.set(f.companyId, entry);
  }
  return Array.from(byCompany.values()).sort((a, b) => b.items.length - a.items.length);
}

// "AcmeCorp (2: CVE-x, CVE-y), Beta Inc (1: CVE-z)" — top 3 CVEs per company.
function companySummary(findings: SyncAlertFinding[]): string {
  return groupByCompany(findings)
    .map((g) => {
      const cves = Array.from(
        new Set(g.items.map((f) => f.cve || f.title).filter(Boolean)),
      ).slice(0, 3);
      return `${g.companyName} (${g.items.length}: ${cves.join(", ")})`;
    })
    .join(", ");
}

// Build the compact alert text. Returns null when there is nothing to say.
function buildSyncAlertText(input: SyncAlertInput): string | null {
  const lines: string[] = [];

  if (input.failures.length > 0) {
    const detail = input.failures
      .map((f) => `${f.connector}${f.error ? ` (${f.error})` : ""}`)
      .join(", ");
    lines.push(
      `gmi-vuln: ${input.failures.length} connector sync failure${input.failures.length === 1 ? "" : "s"} — ${detail}`,
    );
  }

  if (input.newSevere.length > 0) {
    const crits = input.newSevere.filter((f) => f.severity === "Critical").length;
    const highs = input.newSevere.length - crits;
    const counts = [
      crits ? `${crits} new Critical${crits === 1 ? "" : "s"}` : "",
      highs ? `${highs} new High${highs === 1 ? "" : "s"}` : "",
    ]
      .filter(Boolean)
      .join(", ");
    const kevCount = input.newSevere.filter((f) => f.kev).length;
    lines.push(
      `gmi-vuln: ${counts} — ${companySummary(input.newSevere)}${kevCount ? ` · ${kevCount} KEV` : ""}`,
    );
  }

  if (input.newThreat.length > 0) {
    const ransomware = input.newThreat.filter((f) => f.ransomware).length;
    lines.push(
      `gmi-vuln: DROP EVERYTHING — ${input.newThreat.length} new actively-exploited (KEV) finding${input.newThreat.length === 1 ? "" : "s"}${ransomware ? `, ${ransomware} ransomware-linked` : ""} — ${companySummary(input.newThreat)}`,
    );
  }

  return lines.length ? lines.join("\n") : null;
}

// Evaluate + send the post-sync alert to all configured channels. Never throws.
export async function sendSyncAlerts(input: SyncAlertInput): Promise<void> {
  try {
    const text = buildSyncAlertText(input);
    if (!text) return;
    const base = consoleBaseUrl();
    await sendSlack(base ? `${text}\n<${base}/findings|Open console>` : text);
    if (alertInbox()) {
      const html = `<pre style="font-family:inherit;white-space:pre-wrap;">${escapeHtml(text)}</pre>${base ? `<p><a href="${base}/findings">Open console</a></p>` : ""}`;
      await sendEmail({
        to: alertInbox(),
        subject: "gmi-vuln: sync alerts",
        html,
        text,
      });
    }
  } catch (err) {
    console.error(
      "[alerts] sync alert evaluation failed:",
      err instanceof Error ? err.message : err,
    );
  }
}

// --- remediation handoff email --------------------------------------------------

export type RemediationEmailFinding = {
  title: string;
  cve: string;
  severity: Severity;
  asset: string;
  dueAt: string | null;
};

// One remediation email per company: a plain, professional list of the
// findings being handed off, with their SLA due dates.
export async function sendRemediationEmail(input: {
  to: string;
  contactName: string;
  companyName: string;
  companyId: string;
  findings: RemediationEmailFinding[];
}): Promise<boolean> {
  const base = consoleBaseUrl();
  const rows = input.findings
    .map(
      (f) => `<tr>
        <td style="padding:6px 10px;border-bottom:1px solid #e2e5ea;">${escapeHtml(f.title)}</td>
        <td style="padding:6px 10px;border-bottom:1px solid #e2e5ea;">${escapeHtml(f.cve || "—")}</td>
        <td style="padding:6px 10px;border-bottom:1px solid #e2e5ea;">${escapeHtml(f.severity)}</td>
        <td style="padding:6px 10px;border-bottom:1px solid #e2e5ea;">${escapeHtml(f.asset)}</td>
        <td style="padding:6px 10px;border-bottom:1px solid #e2e5ea;">${f.dueAt ? escapeHtml(f.dueAt.slice(0, 10)) : "—"}</td>
      </tr>`,
    )
    .join("");
  const html = `
    <div style="font-family:Arial,Helvetica,sans-serif;color:#1a202c;max-width:720px;">
      <p>Hello${input.contactName ? ` ${escapeHtml(input.contactName)}` : ""},</p>
      <p>The following ${input.findings.length === 1 ? "vulnerability requires" : `${input.findings.length} vulnerabilities require`} remediation on your environment. Due dates reflect the remediation SLA for each severity.</p>
      <table style="border-collapse:collapse;width:100%;font-size:14px;">
        <thead>
          <tr style="text-align:left;background:#f4f6f8;">
            <th style="padding:6px 10px;">Finding</th>
            <th style="padding:6px 10px;">CVE</th>
            <th style="padding:6px 10px;">Severity</th>
            <th style="padding:6px 10px;">Asset</th>
            <th style="padding:6px 10px;">Due</th>
          </tr>
        </thead>
        <tbody>${rows}</tbody>
      </table>
      ${base ? `<p style="margin-top:16px;"><a href="${base}/report/${encodeURIComponent(input.companyId)}">View your full security report</a></p>` : ""}
      <p>Please reach out to your security team with any questions.</p>
    </div>`;
  return sendEmail({
    to: input.to,
    subject: `Action required: ${input.findings.length} security finding${input.findings.length === 1 ? "" : "s"} to remediate — ${input.companyName}`,
    html,
  });
}

// --- monthly executive summary email ---------------------------------------------

export type MonthlyReportInput = {
  to: string;
  contactName: string;
  companyName: string;
  companyId: string;
  month: string; // "YYYY-MM"
  openBySeverity: Record<Severity, number>;
  compositeScore: number;
  compositeBand: string;
  mttrDays: number | null;
  topRisks: { cve: string; title: string; asset: string; realRisk: number }[];
};

export async function sendMonthlyReportEmail(
  input: MonthlyReportInput,
): Promise<boolean> {
  const base = consoleBaseUrl();
  const sev: Severity[] = ["Critical", "High", "Medium", "Low", "Info"];
  const sevCells = sev
    .map(
      (x) =>
        `<td style="padding:6px 12px;text-align:center;border:1px solid #e2e5ea;"><div style="font-size:18px;font-weight:bold;">${input.openBySeverity[x]}</div><div style="font-size:12px;color:#5a6472;">${x}</div></td>`,
    )
    .join("");
  const riskRows = input.topRisks
    .map(
      (r) =>
        `<tr>
          <td style="padding:6px 10px;border-bottom:1px solid #e2e5ea;">${escapeHtml(r.cve || "—")}</td>
          <td style="padding:6px 10px;border-bottom:1px solid #e2e5ea;">${escapeHtml(r.title)}</td>
          <td style="padding:6px 10px;border-bottom:1px solid #e2e5ea;">${escapeHtml(r.asset)}</td>
          <td style="padding:6px 10px;border-bottom:1px solid #e2e5ea;text-align:right;">${r.realRisk}</td>
        </tr>`,
    )
    .join("");
  const html = `
    <div style="font-family:Arial,Helvetica,sans-serif;color:#1a202c;max-width:720px;">
      <h2 style="margin:0 0 4px;">Monthly Security Summary — ${escapeHtml(input.companyName)}</h2>
      <p style="margin:0 0 16px;color:#5a6472;">${escapeHtml(input.month)}</p>
      <p>Hello${input.contactName ? ` ${escapeHtml(input.contactName)}` : ""}, here is your monthly vulnerability posture summary.</p>
      <table style="border-collapse:collapse;margin:12px 0;"><tr>${sevCells}</tr></table>
      <p>
        Composite risk score: <strong>${input.compositeScore}/100 (${escapeHtml(input.compositeBand)})</strong><br/>
        Mean time to remediate (90 days): <strong>${input.mttrDays === null ? "n/a" : `${input.mttrDays} days`}</strong>
      </p>
      ${
        riskRows
          ? `<h3 style="margin:16px 0 6px;">Top risks</h3>
      <table style="border-collapse:collapse;width:100%;font-size:14px;">
        <thead><tr style="text-align:left;background:#f4f6f8;">
          <th style="padding:6px 10px;">CVE</th><th style="padding:6px 10px;">Finding</th><th style="padding:6px 10px;">Asset</th><th style="padding:6px 10px;text-align:right;">Risk</th>
        </tr></thead>
        <tbody>${riskRows}</tbody>
      </table>`
          : ""
      }
      ${base ? `<p style="margin-top:16px;"><a href="${base}/report/${encodeURIComponent(input.companyId)}">View the full interactive report</a></p>` : ""}
    </div>`;
  return sendEmail({
    to: input.to,
    subject: `Monthly security summary (${input.month}) — ${input.companyName}`,
    html,
  });
}

// --- on-demand customer report email ----------------------------------------
// Full scan report + "what changed" update, sent to the customer contact on
// demand from the console. Email-client-safe: tables + inline styles only.

export type CustomerReportEmailInput = {
  companyId: string;
  companyName: string;
  contactName: string;
  generatedAt: string; // ISO
  posture: { compositeScore: number; compositeBand: string; exposureScore: number };
  openBySeverity: Record<Severity, number>;
  sla: {
    bySeverity: Record<Severity, { open: number; overdue: number }>;
    mttrDays: number | null;
  };
  topRisks: {
    severity: Severity;
    cve: string;
    title: string;
    asset: string;
    dueAt: string | null;
  }[];
  delta: {
    since: string | null;
    newFindings: number;
    newCriticals: {
      cve: string;
      title: string;
      asset: string;
      severity: Severity;
      dueAt: string | null;
    }[];
    resolvedFindings: number;
  } | null;
};

const EMAIL_CELL = "padding:6px 10px;border-bottom:1px solid #e2e5ea;";
const EMAIL_HEAD_ROW = "text-align:left;background:#f4f6f8;";
const EMAIL_SECTION_TITLE =
  "margin:22px 0 6px;font-size:15px;color:#1a202c;";

const EMAIL_SEVERITY_COLOR: Record<Severity, string> = {
  Critical: "#b91c1c",
  High: "#c2410c",
  Medium: "#a16207",
  Low: "#3f6212",
  Info: "#5a6472",
};

function emailDate(iso: string | null): string {
  return iso ? iso.slice(0, 10) : "—";
}

// Full customer report email (subject + HTML). Subject reads "Security
// update" when a delta section is present, "Security report" for the
// baseline (first) send.
export function buildCustomerReportHtml(input: CustomerReportEmailInput): {
  subject: string;
  html: string;
} {
  const base = consoleBaseUrl();
  const generated = new Date(input.generatedAt);
  const monthYear = generated.toLocaleDateString("en-US", {
    month: "long",
    year: "numeric",
  });
  const reportDate = generated.toLocaleDateString("en-US", {
    year: "numeric",
    month: "long",
    day: "numeric",
  });
  const subject = `${input.delta ? "Security update" : "Security report"} — ${input.companyName} — ${monthYear}`;

  const sev: Severity[] = ["Critical", "High", "Medium", "Low", "Info"];
  const slaSev: Severity[] = ["Critical", "High", "Medium", "Low"];

  const severityCells = sev
    .map(
      (x) =>
        `<td style="padding:8px 14px;text-align:center;border:1px solid #e2e5ea;"><div style="font-size:20px;font-weight:bold;color:${input.openBySeverity[x] > 0 ? EMAIL_SEVERITY_COLOR[x] : "#1a202c"};">${input.openBySeverity[x]}</div><div style="font-size:12px;color:#5a6472;">${x}</div></td>`,
    )
    .join("");

  const slaRows = slaSev
    .map((x) => {
      const row = input.sla.bySeverity[x] ?? { open: 0, overdue: 0 };
      return `<tr>
        <td style="${EMAIL_CELL}font-weight:bold;color:${EMAIL_SEVERITY_COLOR[x]};">${x}</td>
        <td style="${EMAIL_CELL}text-align:right;">${row.open}</td>
        <td style="${EMAIL_CELL}text-align:right;font-weight:bold;color:${row.overdue > 0 ? "#b91c1c" : "#15803d"};">${row.overdue}</td>
      </tr>`;
    })
    .join("");

  // "Since your last report" (delta) vs baseline wording.
  let deltaSection: string;
  if (input.delta) {
    const d = input.delta;
    const newCritRows = d.newCriticals
      .map(
        (f) => `<tr>
          <td style="${EMAIL_CELL}font-weight:bold;color:${EMAIL_SEVERITY_COLOR[f.severity]};">${escapeHtml(f.severity)}</td>
          <td style="${EMAIL_CELL}">${escapeHtml(f.cve || "—")}</td>
          <td style="${EMAIL_CELL}">${escapeHtml(f.title)}</td>
          <td style="${EMAIL_CELL}">${escapeHtml(f.asset)}</td>
          <td style="${EMAIL_CELL}">${escapeHtml(emailDate(f.dueAt))}</td>
        </tr>`,
      )
      .join("");
    deltaSection = `
      <h3 style="${EMAIL_SECTION_TITLE}">Since your last report (${escapeHtml(emailDate(d.since))})</h3>
      <table style="border-collapse:collapse;margin:8px 0;"><tr>
        <td style="padding:8px 14px;text-align:center;border:1px solid #e2e5ea;"><div style="font-size:20px;font-weight:bold;color:${d.newFindings > 0 ? "#b91c1c" : "#1a202c"};">${d.newFindings}</div><div style="font-size:12px;color:#5a6472;">New findings</div></td>
        <td style="padding:8px 14px;text-align:center;border:1px solid #e2e5ea;"><div style="font-size:20px;font-weight:bold;color:#15803d;">${d.resolvedFindings}</div><div style="font-size:12px;color:#5a6472;">Resolved</div></td>
      </tr></table>
      ${
        newCritRows
          ? `<p style="margin:8px 0 4px;font-size:13px;color:#5a6472;">New Critical / High findings:</p>
      <table style="border-collapse:collapse;width:100%;font-size:13px;">
        <thead><tr style="${EMAIL_HEAD_ROW}">
          <th style="padding:6px 10px;">Severity</th><th style="padding:6px 10px;">CVE</th><th style="padding:6px 10px;">Finding</th><th style="padding:6px 10px;">Asset</th><th style="padding:6px 10px;">Due</th>
        </tr></thead>
        <tbody>${newCritRows}</tbody>
      </table>`
          : `<p style="margin:8px 0;font-size:13px;color:#15803d;">No new Critical or High findings since the last report.</p>`
      }`;
  } else {
    deltaSection = `
      <h3 style="${EMAIL_SECTION_TITLE}">Baseline report</h3>
      <p style="margin:6px 0;font-size:13px;color:#5a6472;">This is your first report from GMI Security Operations — it establishes the baseline. Future reports will highlight what changed since the previous one.</p>`;
  }

  const riskRows = input.topRisks
    .map(
      (r) => `<tr>
        <td style="${EMAIL_CELL}font-weight:bold;color:${EMAIL_SEVERITY_COLOR[r.severity]};">${escapeHtml(r.severity)}</td>
        <td style="${EMAIL_CELL}">${escapeHtml(r.cve || "—")}</td>
        <td style="${EMAIL_CELL}">${escapeHtml(r.title)}</td>
        <td style="${EMAIL_CELL}">${escapeHtml(r.asset)}</td>
        <td style="${EMAIL_CELL}">${escapeHtml(emailDate(r.dueAt))}</td>
      </tr>`,
    )
    .join("");

  const html = `
    <div style="font-family:Arial,Helvetica,sans-serif;color:#1a202c;max-width:720px;">
      <div style="border-bottom:2px solid #1a202c;padding-bottom:10px;margin-bottom:14px;">
        <div style="font-size:12px;letter-spacing:2px;color:#5a6472;text-transform:uppercase;">GMI Security Operations</div>
        <h2 style="margin:4px 0 2px;">${input.delta ? "Security Update" : "Security Report"} — ${escapeHtml(input.companyName)}</h2>
        <div style="font-size:13px;color:#5a6472;">${escapeHtml(reportDate)}</div>
      </div>

      <p>Hello${input.contactName ? ` ${escapeHtml(input.contactName)}` : ""}, here is your ${input.delta ? "security update" : "full security report"} covering vulnerability posture, remediation SLA performance, and top risks.</p>

      <h3 style="${EMAIL_SECTION_TITLE}">Security posture</h3>
      <p style="margin:6px 0;">
        Composite risk score: <strong>${input.posture.compositeScore}/100 (${escapeHtml(input.posture.compositeBand)})</strong><br/>
        Exposure score: <strong>${input.posture.exposureScore}/100</strong><br/>
        Mean time to remediate (90 days): <strong>${input.sla.mttrDays === null ? "n/a" : `${input.sla.mttrDays} days`}</strong>
      </p>

      <h3 style="${EMAIL_SECTION_TITLE}">Open findings by severity</h3>
      <table style="border-collapse:collapse;margin:8px 0;"><tr>${severityCells}</tr></table>

      <h3 style="${EMAIL_SECTION_TITLE}">Remediation SLA performance</h3>
      <table style="border-collapse:collapse;width:100%;max-width:420px;font-size:13px;">
        <thead><tr style="${EMAIL_HEAD_ROW}">
          <th style="padding:6px 10px;">Severity</th><th style="padding:6px 10px;text-align:right;">Open</th><th style="padding:6px 10px;text-align:right;">Past due</th>
        </tr></thead>
        <tbody>${slaRows}</tbody>
      </table>

      ${deltaSection}

      ${
        riskRows
          ? `<h3 style="${EMAIL_SECTION_TITLE}">Top risks</h3>
      <table style="border-collapse:collapse;width:100%;font-size:13px;">
        <thead><tr style="${EMAIL_HEAD_ROW}">
          <th style="padding:6px 10px;">Severity</th><th style="padding:6px 10px;">CVE</th><th style="padding:6px 10px;">Finding</th><th style="padding:6px 10px;">Asset</th><th style="padding:6px 10px;">Due</th>
        </tr></thead>
        <tbody>${riskRows}</tbody>
      </table>`
          : `<p style="margin:8px 0;font-size:13px;color:#15803d;">No open risks — the remediation queue is clear.</p>`
      }

      ${base ? `<p style="margin-top:18px;"><a href="${base}/report/${encodeURIComponent(input.companyId)}" style="color:#1d4ed8;">View the full interactive report</a></p>` : ""}
      <p style="margin-top:14px;font-size:13px;color:#5a6472;">Questions about anything in this report? Reach out to your GMI contact — we are happy to walk through the details.</p>
    </div>`;

  return { subject, html };
}
