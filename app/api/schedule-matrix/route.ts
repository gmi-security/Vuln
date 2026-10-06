import { NextResponse } from "next/server";
import { ensureHydrated, nessusOffsetScheduleMatrix } from "@/lib/store";

export const dynamic = "force-dynamic";

export async function GET() {
  await ensureHydrated();
  return NextResponse.json(await nessusOffsetScheduleMatrix());
}
