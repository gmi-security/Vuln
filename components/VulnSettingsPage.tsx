"use client";

import React, { useEffect, useRef, useState } from "react";
import { BellRing, CalendarClock, Timer } from "lucide-react";
import VulnShell from "@/components/VulnShell";
import { PanelCard, inputClass, primaryButtonClass } from "@/components/ui";
import { severityClass } from "@/lib/format";
import type { Severity } from "@/lib/types";

type ScheduleSettings = {
  autoSyncEnabled: boolean;
  autoSyncIntervalHours: number;
  alertsEnabled: boolean;
  monthlyReportsEnabled: boolean;
};

type SlaSeverity = Exclude<Severity, "Info">;
type SlaSettings = Record<SlaSeverity, number>;

const DEFAULT_SCHEDULE: ScheduleSettings = {
  autoSyncEnabled: false,
  autoSyncIntervalHours: 24,
  alertsEnabled: false,
  monthlyReportsEnabled: false,
};

// Default remediation windows (days) — shown until the backend returns values.
const DEFAULT_SLA: SlaSettings = { Critical: 7, High: 30, Medium: 60, Low: 90 };

const SLA_SEVERITIES: SlaSeverity[] = ["Critical", "High", "Medium", "Low"];

function clampInt(raw: string, min: number, max: number, fallback: number): number {
  const n = Math.round(Number(raw));
  if (!Number.isFinite(n)) return fallback;
  return Math.min(max, Math.max(min, n));
}

async function patchSettings(
  patch: Record<string, unknown>,
): Promise<{ ok: true } | { ok: false; error: string }> {
  try {
    const res = await fetch("/api/settings", {
      method: "PATCH",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(patch),
    });
    if (!res.ok) {
      const json = await res.json().catch(() => ({}));
      return {
        ok: false,
        error: json.error ?? `Save failed (HTTP ${res.status}).`,
      };
    }
    return { ok: true };
  } catch {
    return { ok: false, error: "Failed to reach the API — setting not saved." };
  }
}

function Toggle({
  checked,
  onChange,
  label,
}: {
  checked: boolean;
  onChange: () => void;
  label: string;
}) {
  return (
    <button
      role="switch"
      aria-checked={checked}
      aria-label={label}
      onClick={onChange}
      className={[
        "relative h-7 w-12 shrink-0 rounded-full border transition",
        checked
          ? "border-[rgba(179,14,20,0.5)] bg-[rgba(179,14,20,0.4)]"
          : "border-zinc-700 bg-zinc-800",
      ].join(" ")}
    >
      <span
        className={[
          "absolute top-0.5 h-5 w-5 rounded-full bg-white transition-all",
          checked ? "left-[26px]" : "left-0.5",
        ].join(" ")}
      />
    </button>
  );
}

function SettingRow({
  title,
  hint,
  control,
}: {
  title: string;
  hint: string;
  control: React.ReactNode;
}) {
  return (
    <div className="flex items-center justify-between gap-4 rounded-2xl border border-zinc-900 bg-[#090909] px-4 py-3.5">
      <div className="min-w-0">
        <div className="text-sm font-medium text-white">{title}</div>
        <p className="mt-1 text-xs text-zinc-500">{hint}</p>
      </div>
      {control}
    </div>
  );
}

export default function VulnSettingsPage() {
  const [schedule, setSchedule] = useState<ScheduleSettings>(DEFAULT_SCHEDULE);
  const [sla, setSla] = useState<SlaSettings>(DEFAULT_SLA);
  const [slaDraft, setSlaDraft] = useState<Record<SlaSeverity, string>>({
    Critical: String(DEFAULT_SLA.Critical),
    High: String(DEFAULT_SLA.High),
    Medium: String(DEFAULT_SLA.Medium),
    Low: String(DEFAULT_SLA.Low),
  });
  const [intervalDraft, setIntervalDraft] = useState(
    String(DEFAULT_SCHEDULE.autoSyncIntervalHours),
  );
  const [loaded, setLoaded] = useState(false);

  // Per-card feedback: transient "Saved" flash or a sticky error.
  const [scheduleMsg, setScheduleMsg] = useState<string | null>(null);
  const [scheduleError, setScheduleError] = useState<string | null>(null);
  const [slaMsg, setSlaMsg] = useState<string | null>(null);
  const [slaError, setSlaError] = useState<string | null>(null);
  const [slaSaving, setSlaSaving] = useState(false);

  const [testBusy, setTestBusy] = useState(false);
  const [testError, setTestError] = useState<string | null>(null);
  const [testResult, setTestResult] = useState<{
    slack: boolean;
    email: boolean;
    errors?: string[];
  } | null>(null);

  const flashTimer = useRef<ReturnType<typeof setTimeout> | null>(null);
  function flash(setter: (v: string | null) => void) {
    setter("Saved.");
    if (flashTimer.current) clearTimeout(flashTimer.current);
    flashTimer.current = setTimeout(() => {
      setScheduleMsg(null);
      setSlaMsg(null);
    }, 2500);
  }
  useEffect(
    () => () => {
      if (flashTimer.current) clearTimeout(flashTimer.current);
    },
    [],
  );

  useEffect(() => {
    let cancelled = false;
    void fetch("/api/settings", { cache: "no-store" })
      .then((res) => (res.ok ? res.json() : null))
      .then((json) => {
        if (cancelled || !json?.settings) return;
        const s = json.settings;
        const nextSchedule: ScheduleSettings = {
          ...DEFAULT_SCHEDULE,
          ...(s.schedule ?? {}),
        };
        const nextSla: SlaSettings = { ...DEFAULT_SLA, ...(s.sla ?? {}) };
        setSchedule(nextSchedule);
        setSla(nextSla);
        setIntervalDraft(String(nextSchedule.autoSyncIntervalHours));
        setSlaDraft({
          Critical: String(nextSla.Critical),
          High: String(nextSla.High),
          Medium: String(nextSla.Medium),
          Low: String(nextSla.Low),
        });
      })
      .catch(() => undefined) // defaults stay in place
      .finally(() => {
        if (!cancelled) setLoaded(true);
      });
    return () => {
      cancelled = true;
    };
  }, []);

  // Optimistic write of one schedule field, rolled back if the PATCH fails.
  async function setScheduleField<K extends keyof ScheduleSettings>(
    key: K,
    value: ScheduleSettings[K],
  ) {
    const prev = schedule;
    setSchedule({ ...schedule, [key]: value });
    setScheduleError(null);
    const result = await patchSettings({ schedule: { [key]: value } });
    if (!result.ok) {
      setSchedule(prev);
      if (key === "autoSyncIntervalHours") {
        setIntervalDraft(String(prev.autoSyncIntervalHours));
      }
      setScheduleError(result.error);
      return;
    }
    flash(setScheduleMsg);
  }

  function commitInterval() {
    const value = clampInt(intervalDraft, 1, 168, schedule.autoSyncIntervalHours);
    setIntervalDraft(String(value));
    if (value !== schedule.autoSyncIntervalHours) {
      void setScheduleField("autoSyncIntervalHours", value);
    }
  }

  async function saveSla() {
    setSlaError(null);
    setSlaMsg(null);
    const next = {} as SlaSettings;
    for (const sev of SLA_SEVERITIES) {
      next[sev] = clampInt(slaDraft[sev], 1, 365, sla[sev]);
    }
    setSlaDraft({
      Critical: String(next.Critical),
      High: String(next.High),
      Medium: String(next.Medium),
      Low: String(next.Low),
    });
    setSlaSaving(true);
    const result = await patchSettings({ sla: next });
    setSlaSaving(false);
    if (!result.ok) {
      setSlaError(result.error);
      return;
    }
    setSla(next);
    flash(setSlaMsg);
  }

  async function sendTestAlert() {
    setTestBusy(true);
    setTestError(null);
    setTestResult(null);
    try {
      const res = await fetch("/api/alerts/test", { method: "POST" });
      if (!res.ok) {
        const json = await res.json().catch(() => ({}));
        setTestError(json.error ?? `Test failed (HTTP ${res.status}).`);
        return;
      }
      const json = await res.json();
      setTestResult({
        slack: Boolean(json.slack),
        email: Boolean(json.email),
        errors: json.errors,
      });
    } catch {
      setTestError("Failed to reach the API — no test sent.");
    } finally {
      setTestBusy(false);
    }
  }

  return (
    <VulnShell
      eyebrow="Settings"
      title="Console settings"
      subtitle="Automation schedule, alert delivery, and the remediation SLA policy applied to every customer's findings."
    >
      <div className="grid gap-5 xl:grid-cols-2">
        <PanelCard
          eyebrow="Automation"
          description="Recurring connector syncs and monthly customer reports"
          actions={
            scheduleMsg ? (
              <span className="text-sm text-emerald-300">{scheduleMsg}</span>
            ) : undefined
          }
          className="xl:col-span-2"
        >
          <div className="grid gap-3 lg:grid-cols-3">
            <SettingRow
              title="Auto-sync connectors"
              hint="Pull fresh results from every configured connector on a schedule."
              control={
                <Toggle
                  checked={schedule.autoSyncEnabled}
                  onChange={() =>
                    void setScheduleField(
                      "autoSyncEnabled",
                      !schedule.autoSyncEnabled,
                    )
                  }
                  label="Auto-sync connectors"
                />
              }
            />
            <SettingRow
              title="Sync interval"
              hint="Hours between automatic syncs (1–168)."
              control={
                <div className="flex items-center gap-2">
                  <input
                    type="number"
                    min={1}
                    max={168}
                    value={intervalDraft}
                    disabled={!loaded}
                    onChange={(e) => setIntervalDraft(e.target.value)}
                    onBlur={commitInterval}
                    onKeyDown={(e) => {
                      if (e.key === "Enter") commitInterval();
                    }}
                    className={`${inputClass} h-[44px] w-24 text-center`}
                    aria-label="Sync interval in hours"
                  />
                  <span className="text-xs text-zinc-500">hrs</span>
                </div>
              }
            />
            <SettingRow
              title="Monthly customer reports"
              hint="Email each customer's executive report on the 1st of the month."
              control={
                <Toggle
                  checked={schedule.monthlyReportsEnabled}
                  onChange={() =>
                    void setScheduleField(
                      "monthlyReportsEnabled",
                      !schedule.monthlyReportsEnabled,
                    )
                  }
                  label="Monthly customer reports"
                />
              }
            />
          </div>
          {scheduleError ? (
            <p className="mt-3 text-xs text-[#ff4d57]">{scheduleError}</p>
          ) : null}
          <p className="mt-3 flex items-start gap-2 text-xs text-zinc-500">
            <CalendarClock size={14} className="mt-0.5 shrink-0 text-zinc-600" />
            Slack alerts and report email delivery require the SLACK_WEBHOOK_URL
            and RESEND_API_KEY environment variables to be set in DigitalOcean —
            toggles here have no effect until those are configured.
          </p>
        </PanelCard>

        <PanelCard
          eyebrow="Alerting"
          description="Push new-Critical and SLA-breach alerts to Slack and email"
        >
          <SettingRow
            title="Alerts enabled"
            hint="Notify on new Critical findings, KEV additions, and SLA breaches."
            control={
              <Toggle
                checked={schedule.alertsEnabled}
                onChange={() =>
                  void setScheduleField("alertsEnabled", !schedule.alertsEnabled)
                }
                label="Alerts enabled"
              />
            }
          />
          <div className="mt-4 flex flex-wrap items-center gap-3">
            <button
              onClick={() => void sendTestAlert()}
              disabled={testBusy}
              className={`${primaryButtonClass} disabled:opacity-50`}
            >
              <BellRing size={16} />
              {testBusy ? "Sending…" : "Send test alert"}
            </button>
            {testError ? (
              <span className="text-xs text-[#ff4d57]">{testError}</span>
            ) : null}
          </div>
          {testResult ? (
            <div className="mt-4 space-y-1.5 rounded-2xl border border-zinc-900 bg-[#090909] px-4 py-3 text-sm">
              <div
                className={
                  testResult.slack ? "text-emerald-300" : "text-zinc-500"
                }
              >
                Slack: {testResult.slack ? "delivered" : "not delivered"}
              </div>
              <div
                className={
                  testResult.email ? "text-emerald-300" : "text-zinc-500"
                }
              >
                Email: {testResult.email ? "delivered" : "not delivered"}
              </div>
              {(testResult.errors ?? []).map((err, i) => (
                <div key={i} className="text-xs text-amber-300">
                  {err}
                </div>
              ))}
            </div>
          ) : null}
        </PanelCard>

        <PanelCard
          eyebrow="Remediation SLAs"
          description="Days allowed to remediate an open finding, by severity"
          actions={
            slaMsg ? (
              <span className="text-sm text-emerald-300">{slaMsg}</span>
            ) : undefined
          }
        >
          <div className="space-y-3">
            {SLA_SEVERITIES.map((sev) => (
              <div
                key={sev}
                className="flex items-center justify-between gap-4 rounded-2xl border border-zinc-900 bg-[#090909] px-4 py-3"
              >
                <span
                  className={`inline-flex rounded-full px-3 py-1 text-xs font-medium ${severityClass[sev]}`}
                >
                  {sev}
                </span>
                <div className="flex items-center gap-2">
                  <input
                    type="number"
                    min={1}
                    max={365}
                    value={slaDraft[sev]}
                    disabled={!loaded}
                    onChange={(e) =>
                      setSlaDraft((prev) => ({ ...prev, [sev]: e.target.value }))
                    }
                    className={`${inputClass} h-[44px] w-24 text-center`}
                    aria-label={`${sev} SLA in days`}
                  />
                  <span className="w-9 text-xs text-zinc-500">days</span>
                </div>
              </div>
            ))}
          </div>
          <div className="mt-4 flex items-center gap-3">
            <button
              onClick={() => void saveSla()}
              disabled={slaSaving || !loaded}
              className={`${primaryButtonClass} disabled:opacity-50`}
            >
              <Timer size={16} />
              {slaSaving ? "Saving…" : "Save SLAs"}
            </button>
            {slaError ? (
              <span className="text-xs text-[#ff4d57]">{slaError}</span>
            ) : null}
          </div>
          <p className="mt-3 text-xs text-zinc-500">
            Due dates are computed from each finding&apos;s first-seen date;
            findings past their window show as Overdue on the Findings page and
            in customer reports.
          </p>
        </PanelCard>
      </div>
    </VulnShell>
  );
}
