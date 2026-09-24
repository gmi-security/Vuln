import { NextResponse } from "next/server";
import { parseAssetCoverage } from "@/lib/elastic-vuln";
import { elasticVulnEnabled, elasticIngestAuthorized, saveAssetCoverage } from "@/lib/elastic-vuln-server";

export const dynamic = "force-dynamic";
const MAX_BYTES = 16 * 1024;

export async function POST(request: Request) {
  if (!elasticVulnEnabled()) return NextResponse.json({ error: "Not found" }, { status: 404 });
  if (!elasticIngestAuthorized(request)) return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
  if (process.env.ELASTIC_VULN_SAMPLE_DATA === "true") {
    return NextResponse.json({ error: "Disable sample mode before ingesting live results." }, { status: 409 });
  }
  if (!request.headers.get("content-type")?.toLowerCase().startsWith("application/json")) {
    return NextResponse.json({ error: "Expected application/json" }, { status: 415 });
  }
  const reader = request.body?.getReader();
  if (!reader) return NextResponse.json({ error: "Missing body" }, { status: 400 });
  let snapshot;
  try {
    const chunks: Uint8Array[] = [];
    let length = 0;
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      length += value.byteLength;
      if (length > MAX_BYTES) {
        await reader.cancel();
        return NextResponse.json({ error: "Body too large" }, { status: 413 });
      }
      chunks.push(value);
    }
    snapshot = parseAssetCoverage(JSON.parse(Buffer.concat(chunks).toString("utf8")));
  } catch {
    return NextResponse.json({ error: "Invalid asset-coverage snapshot." }, { status: 400 });
  } finally {
    reader.releaseLock();
  }
  try {
    const updated = await saveAssetCoverage(snapshot);
    return NextResponse.json({ accepted: true, updated });
  } catch {
    return NextResponse.json({ error: "Snapshot storage unavailable. Retry later." }, { status: 503 });
  }
}
