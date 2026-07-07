import { NextResponse } from "next/server";
import { ensureHydrated, importBurpFindings, flushNow } from "@/lib/store";
import { parseBurpXml } from "@/lib/burp";

export const dynamic = "force-dynamic";

// Burp Suite Professional exports issues as XML. This accepts the raw export
// (uploaded from the Connectors page), parses the <issue> blocks, and loads
// them as pentest-class findings — the same path the Enterprise API pull uses,
// minus the credentials.
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
      { error: "No XML content received. Export issues from Burp Suite and upload the file." },
      { status: 400 },
    );
  }

  let items;
  try {
    items = parseBurpXml(xml);
  } catch {
    return NextResponse.json(
      { error: "Could not parse the XML. Check that it's a valid Burp Suite issue export." },
      { status: 400 },
    );
  }
  if (items.length === 0) {
    return NextResponse.json(
      {
        error:
          "No issues parsed from the XML. Make sure it's a Burp Suite export containing <issue> entries.",
      },
      { status: 400 },
    );
  }

  const result = importBurpFindings(items);
  await flushNow();
  return NextResponse.json({ result: { ...result, issuesParsed: items.length } });
}
