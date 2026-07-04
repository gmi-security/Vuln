import { NextResponse } from "next/server";
import { listScans, startScan } from "@/lib/store";
import type { ConnectorId } from "@/lib/types";

export const dynamic = "force-dynamic";

export async function GET() {
  return NextResponse.json({ scans: listScans() });
}

export async function POST(request: Request) {
  let body: {
    name?: string;
    connector?: ConnectorId;
    profile?: string;
    targets?: string[] | string;
  };
  try {
    body = await request.json();
  } catch {
    return NextResponse.json({ error: "Invalid JSON body." }, { status: 400 });
  }

  const validConnectors: ConnectorId[] = ["nessus", "vulners", "crowdstrike", "qualys"];
  if (!body.connector || !validConnectors.includes(body.connector)) {
    return NextResponse.json({ error: "Unknown connector." }, { status: 400 });
  }

  const targets = (
    Array.isArray(body.targets) ? body.targets : String(body.targets ?? "").split(/[\n,]+/)
  )
    .map((t) => t.trim())
    .filter(Boolean);

  const result = await startScan({
    name: (body.name ?? "").trim(),
    connector: body.connector,
    profile: body.profile || "standard",
    targets,
  });

  if ("error" in result) {
    return NextResponse.json({ error: result.error }, { status: 400 });
  }
  return NextResponse.json({ scan: result }, { status: 201 });
}
