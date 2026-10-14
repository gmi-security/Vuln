import { applicationDatabase } from "./persist";
import { createInventoryRoutingStore, reviewedInventoryProviders, type RoutedInventoryProvider } from "./customer-inventory-routing";

/** Pins approved routes for one import. It never hydrates findings or creates schema.
 * Missing/stale approval cannot fall back to company-name matching in routed mode.
 */
export async function loadReviewedInventoryRoutes(provider: RoutedInventoryProvider) {
  const env = { ...process.env };
  if (!reviewedInventoryProviders(env.VULN_REVIEWED_INVENTORY_PROVIDERS).includes(provider)) return null;
  const db = applicationDatabase();
  if (!db) throw new Error("Inventory routing storage is unavailable.");
  try {
    const { readApplicationConnectorMetadata } = await import("./db/connector-metadata.mjs");
    const { buildConnectorPreview } = await import("./customer-connector-preview");
    return await createInventoryRoutingStore(db).read(provider, async () => {
      const client = await db.connect();
      try { return buildConnectorPreview({ ...await readApplicationConnectorMetadata(client), connections: [], tiles: [] }, env); }
      finally { client.release(); }
    });
  } catch {
    throw new Error("Reviewed inventory routing is unavailable or needs renewed approval. No legacy routing was used.");
  }
}
