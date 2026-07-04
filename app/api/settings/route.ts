import { NextResponse } from "next/server";
import { ensureHydrated, getSettings, updateSettings } from "@/lib/store";

export const dynamic = "force-dynamic";

export async function GET() {
  await ensureHydrated();
  return NextResponse.json({ settings: getSettings() });
}

export async function PATCH(request: Request) {
  await ensureHydrated();
  let body: { autoScanNewAssets?: boolean };
  try {
    body = await request.json();
  } catch {
    return NextResponse.json({ error: "Invalid JSON body." }, { status: 400 });
  }
  const patch: { autoScanNewAssets?: boolean } = {};
  if (typeof body.autoScanNewAssets === "boolean") {
    patch.autoScanNewAssets = body.autoScanNewAssets;
  }
  return NextResponse.json({ settings: updateSettings(patch) });
}
