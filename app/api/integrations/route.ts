import { NextResponse } from "next/server";
import { tidalConfig } from "@/lib/tidal";
import { intuneConfig } from "@/lib/intune";
import { falconConfig } from "@/lib/crowdstrike";
import { grcConfig } from "@/lib/grc";

export const dynamic = "force-dynamic";

// Non-scanner integrations (asset inventory, etc.), reported the same way as
// scanner connectors so the Connectors page can render their config state.
export async function GET() {
  const tidal = tidalConfig();
  const intune = intuneConfig();
  const falcon = falconConfig();
  const grc = grcConfig();
  return NextResponse.json({
    integrations: [
      {
        id: "tidal",
        name: "Tidal.io",
        vendor: "Tidal",
        kind: "Asset Inventory (environment context)",
        description:
          "Per-customer asset inventory — hostname, addresses, owner, business criticality, and environment. Signs in to the Tidal portal with your email + password and pulls the live inventory (CSV export upload is available as a fallback). Feeds the environmental layer of real-risk scoring so exposure and criticality come from your authoritative inventory instead of hostname heuristics.",
        capabilities: [
          "Live inventory sync",
          "Owner & criticality",
          "Environment / exposure",
          "Customer mapping",
        ],
        envVars: ["TIDAL_EMAIL", "TIDAL_PASSWORD"],
        configured: Boolean(tidal),
        status: tidal ? "Connected" : "Not Configured",
        docsUrl: "https://app.portal.tidal.io/dashboard",
      },
      {
        id: "intune",
        name: "Microsoft Intune",
        vendor: "Microsoft",
        kind: "Endpoint Inventory (managed devices)",
        description:
          "Managed-device inventory from Intune / Endpoint Manager via Microsoft Graph — device name, OS, primary user, compliance, and ownership. Endpoints attach to your own organization and feed the environmental layer of real-risk scoring.",
        capabilities: [
          "Managed device sync",
          "OS & primary user",
          "Compliance & ownership",
          "Endpoint context",
        ],
        envVars: ["INTUNE_TENANT_ID", "INTUNE_CLIENT_ID", "INTUNE_CLIENT_SECRET"],
        configured: Boolean(intune),
        status: intune ? "Connected" : "Demo Mode",
        docsUrl:
          "https://learn.microsoft.com/en-us/graph/api/resources/intune-devices-manageddevice",
      },
      {
        id: "crowdstrike-devices",
        name: "CrowdStrike Falcon (devices)",
        vendor: "CrowdStrike",
        kind: "Endpoint Inventory (sensor hosts)",
        description:
          "Falcon host inventory — which endpoints have a sensor (the scan/coverage perspective). Devices attach to your own organization as known assets; their Spotlight vulnerabilities flow in through the CrowdStrike scanner connector (the vuln perspective).",
        capabilities: [
          "Host inventory sync",
          "OS & IP addresses",
          "Coverage perspective",
          "Pairs with Spotlight vulns",
        ],
        envVars: ["FALCON_CLIENT_ID", "FALCON_CLIENT_SECRET", "FALCON_CLOUD"],
        configured: Boolean(falcon),
        status: falcon ? "Connected" : "Demo Mode",
        docsUrl: "https://falcon.crowdstrike.com/documentation/page/host-and-host-group-management-apis",
      },
      {
        id: "grc",
        name: "GMI GRC (OpenGRC)",
        vendor: "OpenGRC",
        kind: "Governance, Risk & Compliance",
        description:
          "Pushes vulnerability-derived risks and PCI DSS 4.0 compliance posture into your GRC platform as risk records, so audit and compliance evidence lives in one place.",
        capabilities: [
          "Push risks",
          "PCI DSS posture",
          "Audit evidence",
          "Per-client mapping",
        ],
        envVars: ["GRC_API_URL", "GRC_API_TOKEN"],
        configured: Boolean(grc),
        status: grc ? "Connected" : "Demo Mode",
        docsUrl: `${(process.env.GRC_API_URL ?? "").replace(/\/+$/, "") || "https://www.opengrc.com"}/app/dashboard`,
      },
    ],
  });
}
