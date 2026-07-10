"use client";

import React, { useEffect, useState } from "react";
import TrendChart, { type TrendSnapshot } from "@/components/TrendChart";
import { compositeColor } from "@/lib/format";

// SLA rollup severities shown in the report (Info carries no SLA).
const SLA_SEVERITIES = ["Critical", "High", "Medium", "Low"] as const;

type SlaSummary = {
  bySeverity: Partial<Record<string, { open: number; overdue: number }>>;
  mttrDays: number | null;
};

type ExecReport = {
  generatedAt: string;
  company: { id: string; name: string; industry: string };
  posture: { compositeScore: number; compositeBand: string; exposureScore: number };
  findings: { open: number; critical: number; high: number; kevOpen: number };
  ssvc: { act: number; attend: number; overdue: number; kevOverdue: number };
  compliance: { framework: string; overall: string; score: number }[];
  attackSurface: {
    total: number;
    exposedAssets: number;
    leakedCredentials: number;
    webVulnerabilities: number;
  };
  financial: { ale: number };
  topRisks: {
    cve: string;
    title: string;
    asset: string;
    realRisk: number;
    decision: string;
    kev: boolean;
  }[];
  // Optional until the backend deploy lands / data accumulates.
  sla?: SlaSummary | null;
  trend?: TrendSnapshot[] | null;
};

function money(n: number): string {
  if (n >= 1_000_000) return `$${(n / 1_000_000).toFixed(1)}M`;
  if (n >= 1_000) return `$${Math.round(n / 1_000)}K`;
  return `$${n}`;
}

const overallColor: Record<string, string> = {
  Pass: "#16a34a",
  "At Risk": "#f59e0b",
  Fail: "#dc2626",
  Info: "#64748b",
};

const decisionColor: Record<string, string> = {
  Act: "#dc2626",
  Attend: "#ea580c",
  "Track*": "#f59e0b",
  Track: "#64748b",
};

function Stat({ label, value, color }: { label: string; value: React.ReactNode; color?: string }) {
  return (
    <div style={{ border: "1px solid #e2e8f0", borderRadius: 10, padding: "12px 14px" }}>
      <div style={{ fontSize: 22, fontWeight: 700, color: color ?? "#0f172a" }}>{value}</div>
      <div style={{ fontSize: 11, color: "#64748b", marginTop: 2 }}>{label}</div>
    </div>
  );
}

export default function VulnExecReport({ companyId }: { companyId: string }) {
  const [report, setReport] = useState<ExecReport | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    void fetch(`/api/report/${companyId}`, { cache: "no-store" })
      .then(async (r) => {
        if (!r.ok) throw new Error((await r.json()).error ?? "Failed to load report.");
        return r.json();
      })
      // sla/trend are additive contract fields — accept them on the report
      // object or at the payload root, whichever the backend ships.
      .then((j) =>
        setReport({
          ...j.report,
          sla: j.report?.sla ?? j.sla ?? null,
          trend: j.report?.trend ?? j.trend ?? null,
        }),
      )
      .catch((e) => setError(e instanceof Error ? e.message : "Failed to load report."));
  }, [companyId]);

  if (error) return <div style={{ padding: 40, fontFamily: "system-ui", color: "#dc2626" }}>{error}</div>;
  if (!report) return <div style={{ padding: 40, fontFamily: "system-ui", color: "#64748b" }}>Loading report…</div>;

  const date = new Date(report.generatedAt).toLocaleDateString("en-US", {
    year: "numeric",
    month: "long",
    day: "numeric",
  });

  return (
    <div className="report-root" style={{ background: "#f1f5f9", minHeight: "100vh", padding: 24 }}>
      <style>{`
        @page { margin: 14mm; }
        @media print {
          .no-print { display: none !important; }
          html, body { background: #fff !important; }
          .report-root { background: #fff !important; padding: 0 !important; }
          .sheet {
            box-shadow: none !important;
            margin: 0 !important;
            max-width: 100% !important;
            border-radius: 0 !important;
            padding: 0 !important;
            color: #0f172a !important;
          }
          .avoid-break { break-inside: avoid; page-break-inside: avoid; }
          a { color: inherit !important; text-decoration: none !important; }
        }
      `}</style>

      <div className="no-print" style={{ maxWidth: 820, margin: "0 auto 16px", display: "flex", justifyContent: "space-between", alignItems: "center", fontFamily: "system-ui" }}>
        <div style={{ fontSize: 13, color: "#475569" }}>Board / QBR one-pager — use your browser to Print → Save as PDF.</div>
        <button
          onClick={() => window.print()}
          style={{ background: "#b30e14", color: "#fff", border: 0, borderRadius: 8, padding: "8px 16px", fontSize: 13, fontWeight: 600, cursor: "pointer" }}
        >
          Print / Save as PDF
        </button>
      </div>

      <div
        className="sheet"
        style={{
          maxWidth: 820,
          margin: "0 auto",
          background: "#fff",
          color: "#0f172a",
          borderRadius: 12,
          padding: 32,
          boxShadow: "0 10px 40px rgba(0,0,0,0.12)",
          fontFamily: "system-ui, -apple-system, sans-serif",
        }}
      >
        {/* Header */}
        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", borderBottom: "2px solid #b30e14", paddingBottom: 14 }}>
          <div>
            <div style={{ fontSize: 12, letterSpacing: 2, color: "#b30e14", fontWeight: 700, textTransform: "uppercase" }}>GMI Security · Executive Report</div>
            <div style={{ fontSize: 26, fontWeight: 800, marginTop: 4 }}>{report.company.name}</div>
            <div style={{ fontSize: 13, color: "#64748b" }}>{report.company.industry || "Vulnerability & compliance posture"}</div>
          </div>
          <div style={{ textAlign: "right", fontSize: 12, color: "#64748b" }}>
            <div>{date}</div>
            <div style={{ marginTop: 2, fontWeight: 600, color: "#b30e14" }}>CONFIDENTIAL</div>
          </div>
        </div>

        {/* Posture hero */}
        <div className="avoid-break" style={{ display: "flex", gap: 20, alignItems: "center", margin: "18px 0" }}>
          <div style={{ textAlign: "center", minWidth: 120, border: "1px solid #e2e8f0", borderRadius: 12, padding: "14px 8px" }}>
            <div style={{ fontSize: 44, fontWeight: 800, lineHeight: 1, color: compositeColor(report.posture.compositeScore) }}>
              {report.posture.compositeScore}
            </div>
            <div style={{ fontSize: 11, color: "#64748b", marginTop: 4 }}>Composite risk /100</div>
            <div style={{ fontSize: 12, fontWeight: 700, marginTop: 4, color: compositeColor(report.posture.compositeScore) }}>
              {report.posture.compositeBand}
            </div>
          </div>
          <div style={{ flex: 1, display: "grid", gridTemplateColumns: "repeat(3, 1fr)", gap: 10 }}>
            <Stat label="Open findings" value={report.findings.open} />
            <Stat label="Critical" value={report.findings.critical} color="#dc2626" />
            <Stat label="Actively exploited (KEV)" value={report.findings.kevOpen} color={report.findings.kevOpen ? "#dc2626" : "#0f172a"} />
            <Stat label="SSVC: Act now" value={report.ssvc.act} color={report.ssvc.act ? "#dc2626" : "#0f172a"} />
            <Stat label="Past remediation SLA" value={report.ssvc.overdue} color={report.ssvc.overdue ? "#ea580c" : "#0f172a"} />
            <Stat label="Est. annual risk exposure" value={money(report.financial.ale)} color="#b30e14" />
          </div>
        </div>

        {/* Compliance */}
        <div className="avoid-break" style={{ marginTop: 8 }}>
          <div style={{ fontSize: 12, fontWeight: 700, textTransform: "uppercase", letterSpacing: 1, color: "#334155", marginBottom: 8 }}>Compliance posture</div>
          <div style={{ display: "grid", gridTemplateColumns: "repeat(3, 1fr)", gap: 8 }}>
            {report.compliance.map((c) => (
              <div key={c.framework} style={{ border: "1px solid #e2e8f0", borderRadius: 8, padding: "8px 10px", display: "flex", justifyContent: "space-between", alignItems: "center" }}>
                <div style={{ fontSize: 12, color: "#334155", maxWidth: 150 }}>{c.framework}</div>
                <div style={{ textAlign: "right" }}>
                  <div style={{ fontSize: 15, fontWeight: 700, color: overallColor[c.overall] ?? "#64748b" }}>{c.score}</div>
                  <div style={{ fontSize: 10, color: overallColor[c.overall] ?? "#64748b", fontWeight: 600 }}>{c.overall}</div>
                </div>
              </div>
            ))}
          </div>
        </div>

        {/* Attack surface */}
        <div className="avoid-break" style={{ marginTop: 16 }}>
          <div style={{ fontSize: 12, fontWeight: 700, textTransform: "uppercase", letterSpacing: 1, color: "#334155", marginBottom: 8 }}>External attack surface (OSINT)</div>
          <div style={{ display: "grid", gridTemplateColumns: "repeat(4, 1fr)", gap: 10 }}>
            <Stat label="Total exposures" value={report.attackSurface.total} />
            <Stat label="Exposed assets" value={report.attackSurface.exposedAssets} />
            <Stat label="Leaked credentials" value={report.attackSurface.leakedCredentials} color={report.attackSurface.leakedCredentials ? "#dc2626" : "#0f172a"} />
            <Stat label="Web weaknesses" value={report.attackSurface.webVulnerabilities} />
          </div>
        </div>

        {/* SLA performance */}
        {report.sla ? (
          <div className="avoid-break" style={{ marginTop: 16 }}>
            <div style={{ fontSize: 12, fontWeight: 700, textTransform: "uppercase", letterSpacing: 1, color: "#334155", marginBottom: 8 }}>SLA performance</div>
            <div style={{ display: "flex", gap: 14, alignItems: "stretch" }}>
              <div style={{ flex: 1 }}>
                <table style={{ width: "100%", borderCollapse: "collapse", fontSize: 12 }}>
                  <thead>
                    <tr style={{ textAlign: "left", color: "#64748b", borderBottom: "1px solid #e2e8f0" }}>
                      <th style={{ padding: "6px 4px" }}>Severity</th>
                      <th style={{ padding: "6px 4px", textAlign: "right" }}>Open</th>
                      <th style={{ padding: "6px 4px", textAlign: "right" }}>Past SLA</th>
                    </tr>
                  </thead>
                  <tbody>
                    {SLA_SEVERITIES.map((sev) => {
                      const row = report.sla?.bySeverity?.[sev] ?? { open: 0, overdue: 0 };
                      return (
                        <tr key={sev} style={{ borderBottom: "1px solid #f1f5f9" }}>
                          <td style={{ padding: "6px 4px", fontWeight: 600 }}>{sev}</td>
                          <td style={{ padding: "6px 4px", textAlign: "right" }}>{row.open}</td>
                          <td style={{ padding: "6px 4px", textAlign: "right", fontWeight: 700, color: row.overdue > 0 ? "#dc2626" : "#16a34a" }}>
                            {row.overdue}
                          </td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              </div>
              <div style={{ minWidth: 150, border: "1px solid #e2e8f0", borderRadius: 10, padding: "12px 14px", display: "flex", flexDirection: "column", justifyContent: "center" }}>
                <div style={{ fontSize: 26, fontWeight: 800, color: "#0f172a" }}>
                  {report.sla.mttrDays !== null && report.sla.mttrDays !== undefined ? `${report.sla.mttrDays}d` : "—"}
                </div>
                <div style={{ fontSize: 11, color: "#64748b", marginTop: 2 }}>Mean time to remediate</div>
              </div>
            </div>
          </div>
        ) : null}

        {/* Trend */}
        {(report.trend?.length ?? 0) >= 2 ? (
          <div className="avoid-break" style={{ marginTop: 16 }}>
            <div style={{ fontSize: 12, fontWeight: 700, textTransform: "uppercase", letterSpacing: 1, color: "#334155", marginBottom: 8 }}>Trend — open findings, last 90 days</div>
            <TrendChart snapshots={report.trend ?? []} theme="light" />
          </div>
        ) : null}

        {/* Top risks */}
        <div className="avoid-break" style={{ marginTop: 16 }}>
          <div style={{ fontSize: 12, fontWeight: 700, textTransform: "uppercase", letterSpacing: 1, color: "#334155", marginBottom: 8 }}>Top priorities</div>
          <table style={{ width: "100%", borderCollapse: "collapse", fontSize: 12 }}>
            <thead>
              <tr style={{ textAlign: "left", color: "#64748b", borderBottom: "1px solid #e2e8f0" }}>
                <th style={{ padding: "6px 4px" }}>Action</th>
                <th style={{ padding: "6px 4px" }}>Finding</th>
                <th style={{ padding: "6px 4px" }}>Asset</th>
                <th style={{ padding: "6px 4px", textAlign: "right" }}>Risk</th>
              </tr>
            </thead>
            <tbody>
              {report.topRisks.map((r, i) => (
                <tr key={i} style={{ borderBottom: "1px solid #f1f5f9" }}>
                  <td style={{ padding: "6px 4px" }}>
                    <span style={{ color: decisionColor[r.decision] ?? "#64748b", fontWeight: 700 }}>{r.decision}</span>
                    {r.kev ? <span style={{ color: "#dc2626", fontWeight: 700 }}> · KEV</span> : null}
                  </td>
                  <td style={{ padding: "6px 4px" }}>{r.cve} — {r.title.slice(0, 60)}</td>
                  <td style={{ padding: "6px 4px", color: "#64748b" }}>{r.asset}</td>
                  <td style={{ padding: "6px 4px", textAlign: "right", fontWeight: 700, color: compositeColor(r.realRisk) }}>{r.realRisk}</td>
                </tr>
              ))}
              {report.topRisks.length === 0 ? (
                <tr><td colSpan={4} style={{ padding: "10px 4px", color: "#16a34a" }}>No open priorities — queue is clear.</td></tr>
              ) : null}
            </tbody>
          </table>
        </div>

        {/* Footer / methodology */}
        <div style={{ marginTop: 18, paddingTop: 10, borderTop: "1px solid #e2e8f0", fontSize: 10, color: "#94a3b8", lineHeight: 1.5 }}>
          Prioritization uses CISA SSVC (Act/Attend/Track) from exploitation (CISA KEV, EPSS, public exploit), exposure, and asset criticality. Estimated annual risk exposure is an ALE model (single-loss-expectancy by severity × annual rate of occurrence weighted by exploitation and exposure) — an order-of-magnitude planning figure, not an actuarial value. Generated by the GMI Vuln console.
        </div>
      </div>
    </div>
  );
}
