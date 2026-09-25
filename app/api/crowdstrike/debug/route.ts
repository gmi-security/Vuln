import { NextResponse } from "next/server";
import { getCsDevicesSyncStatus, getCsSpotlightSyncStatus } from "@/lib/store";
import { falconConfigs, falconListAssets, spotlightListFindings } from "@/lib/crowdstrike";

export const dynamic = "force-dynamic";

// Quick diagnostic: returns current sync status + a direct probe of the
// CrowdStrike API per configured tenant (host count + spotlight vuln count).
// Useful for confirming whether a tenant's API client has real data vs
// returning empty, and which company each tenant is pinned to.
export async function GET() {
  const configs = falconConfigs();
  if (!configs.length) {
    return NextResponse.json({ error: "CrowdStrike not configured." }, { status: 400 });
  }

  const devices = getCsDevicesSyncStatus();
  const spotlight = getCsSpotlightSyncStatus();

  const probes = await Promise.all(
    configs.map(async (config) => {
      try {
        const [assets, spotlight] = await Promise.all([
          falconListAssets(config).catch((e: unknown) => ({ error: e instanceof Error ? e.message : String(e) })),
          spotlightListFindings(config).catch((e: unknown) => ({ error: e instanceof Error ? e.message : String(e) })),
        ]);
        const spotlightOk = "findings" in spotlight;
        return {
          label: config.label,
          customerName: config.customerName ?? "(internal — GMI's own estate)",
          baseUrl: config.baseUrl,
          hostsReturned: Array.isArray(assets) ? assets.length : null,
          hostsError: !Array.isArray(assets) ? (assets as any).error : null,
          spotlightFindingsReturned: spotlightOk ? spotlight.findings.length : null,
          spotlightTruncated: spotlightOk ? spotlight.truncated : null,
          spotlightError: !spotlightOk ? (spotlight as any).error : null,
          sampleHost: Array.isArray(assets) && assets.length ? assets[0] : null,
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
