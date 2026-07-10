import { NextResponse } from "next/server";
import { adminTokenOk } from "@/lib/admin-auth";
import { ensureHydrated, grcAssessment } from "@/lib/store";

export const dynamic = "force-dynamic";

// Token-protected assessment feed for the OpenGRC server-side sync. Emits every
// client's per-control effectiveness + implementation status + evidence, mapped
// to OpenGRC control codes. Requires Authorization: Bearer or x-admin-token =
// ADMIN_TOKEN (see lib/admin-auth.ts).
export async function GET(request: Request) {
  if (!adminTokenOk(request)) {
    return NextResponse.json({ error: "Unauthorized." }, { status: 401 });
  }
  await ensureHydrated();
  const assessment = grcAssessment();
  assessment.generatedAt = new Date().toISOString();
  return NextResponse.json(assessment);
}
