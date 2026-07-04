import { NextResponse } from "next/server";
import { getSettings, updateSettings } from "@/lib/store";

export const dynamic = "force-dynamic";

export async function GET() {
  return NextResponse.json({ settings: getSettings() });
}

export async function PATCH(request: Request) {
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
