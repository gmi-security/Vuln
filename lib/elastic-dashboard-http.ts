import { getServerSession } from "next-auth";
import { NextResponse } from "next/server";
import { authOptions } from "./auth";
import { DashboardError } from "./elastic-dashboard";
import { elasticVulnEnabled } from "./elastic-vuln-server";

export async function dashboardAccess(request?: Request, mutation = false) {
  if (!elasticVulnEnabled()) throw new DashboardError("Not found", 404);
  const session = await getServerSession(authOptions);
  const user = session?.user as { email?: string; name?: string; orgMember?: boolean } | undefined;
  if (!user || user.orgMember === false) throw new DashboardError("Unauthorized", 401);
  // All signed-in organization members can manage this shared dashboard.
  const canManage = true;
  if (request && mutation) {
    const expected = new URL(process.env.NEXTAUTH_URL || request.url).origin;
    if (request.headers.get("origin") !== expected) throw new DashboardError("Invalid request origin.", 403);
  }
  return { canManage, actor: user.email || user.name || "organization-member" };
}

export async function dashboardBody(request: Request): Promise<unknown> {
  if (!request.headers.get("content-type")?.startsWith("application/json")) throw new DashboardError("Expected application/json", 415);
  const reader = request.body?.getReader();
  if (!reader) throw new DashboardError("Missing request body.");
  const chunks: Uint8Array[] = [];
  let bytes = 0;
  try {
    while (true) {
      const { value, done } = await reader.read();
      if (done) break;
      bytes += value.byteLength;
      if (bytes > 32 * 1024) { await reader.cancel(); throw new DashboardError("Request exceeds 32 KiB.", 413); }
      chunks.push(value);
    }
    try { return JSON.parse(Buffer.concat(chunks).toString("utf8")); }
    catch { throw new DashboardError("Invalid JSON body."); }
  } finally { reader.releaseLock(); }
}

export function dashboardJson(value: unknown, status = 200) {
  return NextResponse.json(value, { status, headers: { "Cache-Control": "private, no-store" } });
}

export function dashboardFailure(error: unknown) {
  return dashboardJson({ error: error instanceof DashboardError ? error.message : "Dashboard storage is unavailable. Try again shortly." },
    error instanceof DashboardError ? error.status : 503);
}
