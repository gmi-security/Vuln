import { NextResponse } from "next/server";
import { ensureHydrated, importNmapScan, flushNow } from "@/lib/store";
import { parseNmapXml } from "@/lib/nmap";

export const dynamic = "force-dynamic";

// Accepts an nmap -oX XML export (uploaded from the Connectors page), parses
// the <host>/<port> entries, attaches ground-truth open-port facts to assets,
// and raises exposed-service findings — the same path the runner pull uses,
// minus the runner.
export async function POST(request: Request) {
  await ensureHydrated();

  let xml = "";
  const contentType = request.headers.get("content-type") ?? "";
  try {
    if (contentType.includes("multipart/form-data")) {
      const form = await request.formData();
      const file = form.get("file");
      if (file && typeof file !== "string") {
        xml = await file.text();
      } else {
        xml = String(form.get("xml") ?? "");
      }
    } else if (contentType.includes("application/json")) {
      const body = await request.json();
      xml = String(body?.xml ?? "");
    } else {
      xml = await request.text();
    }
  } catch {
    return NextResponse.json({ error: "Could not read the uploaded file." }, { status: 400 });
  }

  xml = xml.trim();
  if (!xml) {
    return NextResponse.json(
      { error: "No XML content received. Run nmap with -oX and upload the output file." },
      { status: 400 },
    );
  }

  let hosts;
  try {
    hosts = parseNmapXml(xml);
  } catch {
    return NextResponse.json(
      { error: "Could not parse the XML. Check that it's nmap -oX output." },
      { status: 400 },
    );
  }
  if (hosts.length === 0) {
    return NextResponse.json(
      {
        error:
          "No hosts parsed from the XML. Make sure it's an nmap -oX export containing <host> entries.",
      },
      { status: 400 },
    );
  }

  const result = importNmapScan(hosts);
  await flushNow();
  return NextResponse.json({ result: { ...result, hostsParsed: hosts.length } });
}
