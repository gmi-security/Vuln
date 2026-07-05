import { NextResponse } from "next/server";
import { ensureHydrated, grcAssessment } from "@/lib/store";

export const dynamic = "force-dynamic";

// Token-protected assessment feed for the OpenGRC server-side sync. Emits every
// client's per-control effectiveness + implementation status + evidence, mapped
// to OpenGRC control codes. Requires ?token= or x-admin-token = ADMIN_TOKEN.
export async function GET(request: Request) {
  const token =
    new URL(request.url).searchParams.get("token") ??
    request.headers.get("x-admin-token") ??
    "";
  if (!process.env.ADMIN_TOKEN || token !== process.env.ADMIN_TOKEN) {
    return NextResponse.json({ error: "Unauthorized." }, { status: 401 });
  }
  await ensureHydrated();
  const assessment = grcAssessment();
  assessment.generatedAt = new Date().toISOString();
  return NextResponse.json(assessment);
}
