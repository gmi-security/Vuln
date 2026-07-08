import { NextResponse } from "next/server";
import { getCsDevicesSyncStatus, getCsSpotlightSyncStatus } from "@/lib/store";
import { falconConfig, falconListAssets, spotlightListFindings } from "@/lib/crowdstrike";

export const dynamic = "force-dynamic";

// Quick diagnostic: returns current sync status + a direct probe of the
// CrowdStrike API (host count + spotlight vuln count). Useful for confirming
// whether the API client has real data vs returning empty.
export async function GET() {
  const config = falconConfig();
  if (!config) {
    return NextResponse.json({ error: "CrowdStrike not configured." }, { status: 400 });
  }

  const devices = getCsDevicesSyncStatus();
  const spotlight = getCsSpotlightSyncStatus();

  // Probe the API directly — catch errors and surface them.
  let probe: Record<string, unknown> = {};
  try {
    const [assets, findings] = await Promise.all([
      falconListAssets().catch((e: unknown) => ({ error: e instanceof Error ? e.message : String(e) })),
      spotlightListFindings().catch((e: unknown) => ({ error: e instanceof Error ? e.message : String(e) })),
    ]);
    probe = {
      hostsReturned: Array.isArray(assets) ? assets.length : null,
      hostsError: !Array.isArray(assets) ? (assets as any).error : null,
      spotlightFindingsReturned: Array.isArray(findings) ? findings.length : null,
      spotlightError: !Array.isArray(findings) ? (findings as any).error : null,
      sampleHost: Array.isArray(assets) && assets.length ? assets[0] : null,
    };
  } catch (err) {
    probe = { error: err instanceof Error ? err.message : String(err) };
  }

  return NextResponse.json({ devices, spotlight, probe, baseUrl: config.baseUrl });
}
