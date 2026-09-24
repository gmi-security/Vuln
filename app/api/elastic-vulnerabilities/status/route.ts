import { NextResponse } from "next/server";
import { elasticVulnEnabled } from "@/lib/elastic-vuln-server";

export const dynamic = "force-dynamic";

// Session-protected navigation capability check; never accesses the database.
export function GET() {
  return NextResponse.json({ enabled: elasticVulnEnabled() }, {
    headers: { "Cache-Control": "private, no-store" },
  });
}
