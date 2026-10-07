import { NextResponse } from "next/server";
import { getConnectors } from "@/lib/connectors";
import { defenderStore } from "@/lib/defender-store";

export const dynamic = "force-dynamic";

export async function GET() {
  const connectors = getConnectors();
  const defender = connectors.find(row => row.id === "defender");
  if (defender) {
    const configured = process.env.DATABASE_URL ? (await defenderStore().list().catch(() => [])).length > 0 : false;
    defender.configured = configured;
    defender.status = configured ? "Connected" : "Not Configured";
    defender.envVars = [];
  }
  return NextResponse.json({ connectors });
}
