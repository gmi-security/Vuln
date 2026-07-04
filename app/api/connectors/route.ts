import { NextResponse } from "next/server";
import { getConnectors } from "@/lib/connectors";

export const dynamic = "force-dynamic";

export async function GET() {
  return NextResponse.json({ connectors: getConnectors() });
}
