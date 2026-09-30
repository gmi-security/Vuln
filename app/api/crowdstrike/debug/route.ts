import { NextResponse } from "next/server";
import { getCsDevicesSyncStatus, getCsSpotlightSyncStatusDurable } from "@/lib/store";
import { falconConfigs, falconProbeCounts } from "@/lib/crowdstrike";

export const dynamic = "force-dynamic";

// Return current sync status plus bounded count queries for each tenant.
// A debug GET must not duplicate an uncapped Spotlight sync.
export async function GET() {
  const configs = falconConfigs();
  if (!configs.length) {
    return NextResponse.json({ error: "CrowdStrike not configured." }, { status: 400 });
  }

  const devices = getCsDevicesSyncStatus();
  const spotlight = await getCsSpotlightSyncStatusDurable();

  const probes = await Promise.all(
    configs.map(async (config) => {
      try {
        const counts = await falconProbeCounts(config);
        return {
          label: config.label,
          customerName: config.customerName ?? "(internal — GMI's own estate)",
          baseUrl: config.baseUrl,
          ...counts,
        };
      } catch (err) {
        return {
          label: config.label,
          customerName: config.customerName ?? "(internal — GMI's own estate)",
          baseUrl: config.baseUrl,
          error: err instanceof Error ? err.message : String(err),
        };
      }
    }),
  );

  return NextResponse.json({ devices, spotlight, tenants: probes });
}
