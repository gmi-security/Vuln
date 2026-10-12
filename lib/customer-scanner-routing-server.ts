import { applicationDatabase } from "./persist";
import { createScannerRoutingStore, reviewedScannerProviders, type RoutedScannerProvider } from "./customer-scanner-routing";

/** Pins approved routes for one import. It never hydrates findings or creates schema.
 * Missing/stale approval cannot fall back to company-name matching in routed mode.
 */
export async function loadReviewedScannerRoutes(provider: RoutedScannerProvider) {
  const env = { ...process.env };
  if (!reviewedScannerProviders(env.VULN_REVIEWED_SCANNER_PROVIDERS).includes(provider)) return null;
  const db = applicationDatabase();
  if (!db) throw new Error("Scanner routing storage is unavailable.");
  try {
    const { readApplicationConnectorMetadata } = await import("./db/connector-metadata.mjs");
    const { buildConnectorPreview } = await import("./customer-connector-preview");
    return await createScannerRoutingStore(db).read(provider, async () => {
      const client = await db.connect();
      try { return buildConnectorPreview({ ...await readApplicationConnectorMetadata(client), connections: [], tiles: [] }, env); }
      finally { client.release(); }
    });
  } catch {
    throw new Error("Reviewed scanner routing is unavailable or needs renewed approval. No legacy routing was used.");
  }
}
