import { NextResponse } from "next/server";
import { ensureHydrated, startCsSpotlightSync, getCsSpotlightSyncStatus,
  getCsSpotlightSyncStatusDurable } from "@/lib/store";

export const dynamic = "force-dynamic";

export async function POST(request: Request) {
  await ensureHydrated();
  let companyId: string | undefined;
  const raw = await request.text();
  if (raw.trim()) {
    try {
      const body = JSON.parse(raw);
      if (body.companyId !== undefined && (typeof body.companyId !== "string" || !body.companyId.trim())) {
        return NextResponse.json({ error: "companyId must be a nonempty string." }, { status: 400 });
      }
      companyId = body.companyId;
    } catch {
      return NextResponse.json({ error: "Invalid JSON body." }, { status: 400 });
    }
  }
  const launch = startCsSpotlightSync(companyId);
  if (!launch.started && launch.error) {
    return NextResponse.json({ error: launch.error }, { status: 400 });
  }
  return NextResponse.json({ status: getCsSpotlightSyncStatus() });
}

export async function GET() {
  return NextResponse.json({ status: await getCsSpotlightSyncStatusDurable() });
}
