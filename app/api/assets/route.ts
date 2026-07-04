import { NextResponse } from "next/server";
import { ensureHydrated, listAssets } from "@/lib/store";

export const dynamic = "force-dynamic";

export async function GET(request: Request) {
  await ensureHydrated();
  const { searchParams } = new URL(request.url);
  const companyId = searchParams.get("companyId") ?? undefined;
  return NextResponse.json({ assets: listAssets({ companyId }) });
}
