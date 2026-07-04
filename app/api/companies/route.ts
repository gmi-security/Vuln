import { NextResponse } from "next/server";
import { createCompany, ensureHydrated, listCompanies } from "@/lib/store";

export const dynamic = "force-dynamic";

export async function GET() {
  await ensureHydrated();
  return NextResponse.json({ companies: listCompanies() });
}

export async function POST(request: Request) {
  await ensureHydrated();
  let body: {
    name?: string;
    industry?: string;
    contactName?: string;
    contactEmail?: string;
  };
  try {
    body = await request.json();
  } catch {
    return NextResponse.json({ error: "Invalid JSON body." }, { status: 400 });
  }
  const result = createCompany({
    name: body.name ?? "",
    industry: body.industry,
    contactName: body.contactName,
    contactEmail: body.contactEmail,
  });
  if ("error" in result) {
    return NextResponse.json({ error: result.error }, { status: 400 });
  }
  return NextResponse.json({ company: result }, { status: 201 });
}
