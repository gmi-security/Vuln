import { NextResponse } from "next/server";
import { ensureHydrated, importTidalInventory } from "@/lib/store";
import { parseTidalCsv } from "@/lib/tidal";

export const dynamic = "force-dynamic";

// Offline portal export with the existing header matching. The store refuses
// this name-based path when reviewed live-session routing is enabled.
export async function POST(request: Request) {
  await ensureHydrated();

  let csv = "";
  const contentType = request.headers.get("content-type") ?? "";
  try {
    if (contentType.includes("multipart/form-data")) {
      const form = await request.formData();
      const file = form.get("file");
      if (file && typeof file !== "string") {
        csv = await file.text();
      } else {
        csv = String(form.get("csv") ?? "");
      }
    } else if (contentType.includes("application/json")) {
      const body = await request.json();
      csv = String(body?.csv ?? "");
    } else {
      csv = await request.text();
    }
  } catch {
    return NextResponse.json({ error: "Could not read the uploaded file." }, { status: 400 });
  }

  csv = csv.trim();
  if (!csv) {
    return NextResponse.json(
      { error: "No CSV content received. Export your inventory from Tidal and upload the file." },
      { status: 400 },
    );
  }

  let assets;
  try {
    assets = parseTidalCsv(csv);
  } catch {
    return NextResponse.json(
      { error: "Could not parse the CSV. Check that it's a valid comma-separated export." },
      { status: 400 },
    );
  }
  if (assets.length === 0) {
    return NextResponse.json(
      {
        error:
          "No rows parsed from the CSV. Make sure the first line is a header row (e.g. Hostname, IP Address, Customer, Business Criticality).",
      },
      { status: 400 },
    );
  }

  const result = await importTidalInventory(assets);
  if ("error" in result) return NextResponse.json({error:result.error},{status:409});
  return NextResponse.json({ result: { ...result, rowsParsed: assets.length } });
}
