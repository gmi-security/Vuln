import type { Pool } from "pg";
import type { QueryDefinition } from "./elastic-dashboard";

export const EXPRT_RANKED_CVES: QueryDefinition = {
  id: "crowdstrike-exprt-ranked-cves",
  title: "Open CVEs — ranked by ExPRT",
  description: "CrowdStrike ExPRT rating first, then unique affected devices. Open/reopened findings, including suppressed findings. CVSS severity is shown separately; unrated CVEs are excluded.",
  source: "crowdstrike",
  query: "status:['open','reopen']",
  crowdstrike: { dataset: "vulnerabilities", view: "exprt-cves", measure: "hosts", groupBy: "cve", top: 100, history: false },
  display: "table",
  refreshMinutes: 1440,
  enabled: true,
};

export async function installExprtRankedCveTile(db: Pool): Promise<void> {
  const client = await db.connect();
  try {
    await client.query("BEGIN");
    await client.query("SELECT pg_advisory_xact_lock(804201)");
    const eligible = await client.query(`SELECT 1
      WHERE EXISTS (SELECT 1 FROM dashboard_source_connections WHERE source = 'crowdstrike')
      AND NOT EXISTS (SELECT 1 FROM elastic_dashboard_queries WHERE id = $1)`, [EXPRT_RANKED_CVES.id]);
    if (eligible.rowCount) {
      // Preserve the current visible order, including legacy NULL positions,
      // before appending. MAX(display_order) alone would precede NULL rows.
      await client.query(`WITH ordered AS (
        SELECT id, row_number() OVER (ORDER BY display_order NULLS LAST, id = 'asset-coverage' DESC, id) - 1 AS position
        FROM elastic_dashboard_queries WHERE deleted_at IS NULL
      ) UPDATE elastic_dashboard_queries AS tile SET display_order = ordered.position::int
        FROM ordered WHERE tile.id = ordered.id`);
      await client.query(`INSERT INTO elastic_dashboard_queries (id, definition, display_order)
        SELECT $1, $2::jsonb, COALESCE(MAX(display_order), -1) + 1
        FROM elastic_dashboard_queries WHERE deleted_at IS NULL`,
      [EXPRT_RANKED_CVES.id, JSON.stringify(EXPRT_RANKED_CVES)]);
      await client.query(`INSERT INTO elastic_dashboard_audit (actor, action, query_id)
        VALUES ('system', 'query.exprt-ranked-cves.installed', $1)`, [EXPRT_RANKED_CVES.id]);
    }
    await client.query("COMMIT");
  } catch (error) { await client.query("ROLLBACK"); throw error; }
  finally { client.release(); }
}
