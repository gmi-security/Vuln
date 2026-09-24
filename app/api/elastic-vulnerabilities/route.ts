import { NextResponse } from "next/server";
import { elasticVulnEnabled, getElasticCoverageView } from "@/lib/elastic-vuln-server";

export const dynamic = "force-dynamic";

// Covered by the existing session gate in proxy.ts.
export async function GET() {
  if (!elasticVulnEnabled()) {
    return NextResponse.json({ error: "Not found" }, { status: 404 });
  }
  const view = await getElasticCoverageView();
  return NextResponse.json(view, {
    status: view.mode === "unavailable" ? 503 : 200,
    headers: { "Cache-Control": "private, no-store" },
  });
}
