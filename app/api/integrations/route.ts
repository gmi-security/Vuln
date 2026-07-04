import { NextResponse } from "next/server";
import { tidalConfig } from "@/lib/tidal";

export const dynamic = "force-dynamic";

// Non-scanner integrations (asset inventory, etc.), reported the same way as
// scanner connectors so the Connectors page can render their config state.
export async function GET() {
  const tidal = tidalConfig();
  return NextResponse.json({
    integrations: [
      {
        id: "tidal",
        name: "Tidal.io",
        vendor: "Tidal",
        kind: "Asset Inventory (environment context)",
        description:
          "Per-customer asset inventory — hostname, addresses, owner, business criticality, and environment. Feeds the environmental layer of real-risk scoring so exposure and criticality come from your authoritative inventory instead of hostname heuristics.",
        capabilities: [
          "Asset inventory sync",
          "Owner & criticality",
          "Environment / exposure",
          "Customer mapping",
        ],
        envVars: ["TIDAL_API_URL", "TIDAL_API_KEY", "TIDAL_PROFILE_ID"],
        configured: Boolean(tidal),
        status: tidal ? "Connected" : "Demo Mode",
        docsUrl: "https://tidal.io/services",
      },
    ],
  });
}
