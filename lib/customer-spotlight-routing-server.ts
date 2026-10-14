import { applicationDatabase } from "./persist";
import { createSpotlightRoutingStore, reviewedSpotlightProviders, type RoutedSpotlightProvider } from "./customer-spotlight-routing";

/** Pins approved routes for one import. It never hydrates findings or creates schema.
 * Missing/stale approval cannot fall back to company-name matching in routed mode.
 */
export async function loadReviewedSpotlightRoutes(provider: RoutedSpotlightProvider) {
  const env = { ...process.env };
  if (!reviewedSpotlightProviders(env.VULN_REVIEWED_SPOTLIGHT_PROVIDERS).includes(provider)) return null;
  const db = applicationDatabase();
  if (!db) throw new Error("Spotlight routing storage is unavailable.");
  try {
    const { readApplicationConnectorMetadata } = await import("./db/connector-metadata.mjs");
    const { buildConnectorPreview } = await import("./customer-connector-preview");
    return await createSpotlightRoutingStore(db).read(provider, async () => {
      const client = await db.connect();
      try { return buildConnectorPreview({ ...await readApplicationConnectorMetadata(client), connections: [], tiles: [] }, env); }
      finally { client.release(); }
    });
  } catch {
    throw new Error("Reviewed spotlight routing is unavailable or needs renewed approval. No legacy routing was used.");
  }
}
