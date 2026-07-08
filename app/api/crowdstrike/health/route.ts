import { NextResponse } from "next/server";
import { falconConfig } from "@/lib/crowdstrike";

export const dynamic = "force-dynamic";

export async function GET() {
  const config = falconConfig();
  if (!config) {
    return NextResponse.json(
      {
        configured: false,
        reachable: false,
        status: "Not Configured",
        message: "Set FALCON_CLIENT_ID, FALCON_CLIENT_SECRET, and FALCON_CLOUD.",
      },
      { status: 503 },
    );
  }

  try {
    const res = await fetch(`${config.baseUrl}/oauth2/token`, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        client_id: config.clientId,
        client_secret: config.clientSecret,
      }),
      cache: "no-store",
    });
    if (!res.ok) {
      const text = await res.text().catch(() => res.statusText);
      return NextResponse.json(
        { configured: true, reachable: false, status: `HTTP ${res.status}`, message: text },
        { status: 503 },
      );
    }
    const data: any = await res.json();
    if (!data?.access_token) {
      return NextResponse.json(
        { configured: true, reachable: false, status: "Auth Failed", message: "No access token returned." },
        { status: 503 },
      );
    }
    return NextResponse.json({
      configured: true,
      reachable: true,
      status: "Connected",
      message: `Falcon API reachable (${config.baseUrl}).`,
    });
  } catch (err) {
    return NextResponse.json(
      {
        configured: true,
        reachable: false,
        status: "Unreachable",
        message: err instanceof Error ? err.message : "Connection failed.",
      },
      { status: 503 },
    );
  }
}
