import { NextResponse } from "next/server";
import {
  ensureHydrated,
  getSettings,
  updateSettings,
  type SettingsPatch,
} from "@/lib/store";
import type { ScheduleSettings, SlaSettings, SlaSeverity } from "@/lib/types";

export const dynamic = "force-dynamic";

export async function GET() {
  await ensureHydrated();
  return NextResponse.json({ settings: getSettings() });
}

const SLA_SEVERITIES: SlaSeverity[] = ["Critical", "High", "Medium", "Low"];

export async function PATCH(request: Request) {
  await ensureHydrated();
  let body: {
    autoScanNewAssets?: unknown;
    schedule?: Record<string, unknown>;
    sla?: Record<string, unknown>;
  };
  try {
    body = await request.json();
  } catch {
    return NextResponse.json({ error: "Invalid JSON body." }, { status: 400 });
  }

  const patch: SettingsPatch = {};
  if (typeof body.autoScanNewAssets === "boolean") {
    patch.autoScanNewAssets = body.autoScanNewAssets;
  }

  if (body.schedule && typeof body.schedule === "object") {
    const sched: Partial<ScheduleSettings> = {};
    const sc = body.schedule;
    for (const key of [
      "autoSyncEnabled",
      "alertsEnabled",
      "monthlyReportsEnabled",
    ] as const) {
      const value = sc[key];
      if (value === undefined) continue;
      if (typeof value !== "boolean") {
        return NextResponse.json(
          { error: `schedule.${key} must be a boolean.` },
          { status: 400 },
        );
      }
      sched[key] = value;
    }
    if (sc.autoSyncIntervalHours !== undefined) {
      const hours = Number(sc.autoSyncIntervalHours);
      if (!Number.isFinite(hours) || hours < 1 || hours > 168) {
        return NextResponse.json(
          { error: "schedule.autoSyncIntervalHours must be between 1 and 168." },
          { status: 400 },
        );
      }
      sched.autoSyncIntervalHours = Math.round(hours);
    }
    if (Object.keys(sched).length > 0) patch.schedule = sched;
  }

  if (body.sla && typeof body.sla === "object") {
    const sla: Partial<SlaSettings> = {};
    for (const sev of SLA_SEVERITIES) {
      const value = body.sla[sev];
      if (value === undefined) continue;
      const days = Number(value);
      if (!Number.isFinite(days) || days < 1 || days > 365) {
        return NextResponse.json(
          { error: `sla.${sev} must be between 1 and 365 days.` },
          { status: 400 },
        );
      }
      sla[sev] = Math.round(days);
    }
    if (Object.keys(sla).length > 0) patch.sla = sla;
  }

  return NextResponse.json({ settings: updateSettings(patch) });
}
