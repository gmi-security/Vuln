import { NextResponse } from "next/server";
import { elasticVulnEnabled } from "@/lib/elastic-vuln-server";
import { remediationUiEnabled } from "@/lib/remediation-server";

export const dynamic = "force-dynamic";

// Session-protected navigation capability check; never accesses the database.
export function GET() {
  return NextResponse.json({ enabled: elasticVulnEnabled(),
    ...(elasticVulnEnabled() && remediationUiEnabled() ? { remediationEnabled: true } : {}),
  }, {
    headers: { "Cache-Control": "private, no-store" },
  });
}
