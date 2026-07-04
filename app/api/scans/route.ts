import { NextResponse } from "next/server";
import { ensureHydrated, listScans, startScan } from "@/lib/store";
import type { ConnectorId } from "@/lib/types";

export const dynamic = "force-dynamic";

export async function GET(request: Request) {
  await ensureHydrated();
  const { searchParams } = new URL(request.url);
  const companyId = searchParams.get("companyId") ?? undefined;
  const folderId = searchParams.get("folderId") ?? undefined;
  return NextResponse.json({ scans: await listScans({ companyId, folderId }) });
}

export async function POST(request: Request) {
  await ensureHydrated();
  let body: {
    name?: string;
    connector?: ConnectorId;
    profile?: string;
    targets?: string[] | string;
    companyId?: string;
    folderId?: string;
    folderName?: string;
  };
  try {
    body = await request.json();
  } catch {
    return NextResponse.json({ error: "Invalid JSON body." }, { status: 400 });
  }

  const validConnectors: ConnectorId[] = ["nessus", "vulners", "crowdstrike", "defender", "qualys"];
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
    companyId: body.companyId,
    folderId: body.folderId,
    folderName: body.folderName,
  });

  if ("error" in result) {
    return NextResponse.json({ error: result.error }, { status: 400 });
  }
  return NextResponse.json({ scan: result }, { status: 201 });
}
