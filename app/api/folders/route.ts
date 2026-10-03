import { NextResponse } from "next/server";
import { createFolder, ensureHydrated, listFolders } from "@/lib/store";
import { stringFieldError } from "@/lib/validate";

export const dynamic = "force-dynamic";

export async function GET(request: Request) {
  await ensureHydrated();
  const { searchParams } = new URL(request.url);
  const companyId = searchParams.get("companyId") ?? undefined;
  return NextResponse.json({ folders: listFolders(companyId) });
}

export async function POST(request: Request) {
  await ensureHydrated();
  let body: { companyId?: string; name?: string };
  try {
    body = await request.json();
  } catch {
    return NextResponse.json({ error: "Invalid JSON body." }, { status: 400 });
  }
  if (!body.companyId) {
    return NextResponse.json({ error: "companyId is required." }, { status: 400 });
  }
  const fieldError = stringFieldError(body, ["companyId", "name"]);
  if (fieldError) return NextResponse.json({ error: fieldError }, { status: 400 });
  const result = createFolder(body.companyId, body.name ?? "");
  if ("error" in result) {
    return NextResponse.json({ error: result.error }, { status: 400 });
  }
  return NextResponse.json({ folder: result }, { status: 201 });
}
