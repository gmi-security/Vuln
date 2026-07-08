import { NextResponse } from "next/server";
import { vulnersStatus } from "@/lib/vulners";

export const dynamic = "force-dynamic";

export async function GET() {
  const status = await vulnersStatus();
  return NextResponse.json(status, { status: status.reachable ? 200 : 503 });
}
