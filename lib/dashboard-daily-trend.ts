import type { Pool, PoolClient } from "pg";
import type { QueryDefinition } from "./elastic-dashboard";

export const DAILY_OPEN_VULNERABILITIES: QueryDefinition = {
  id: "crowdstrike-daily-open-vulnerabilities",
  title: "Open vulnerabilities — daily snapshots",
  description: "Open and reopened CrowdStrike findings, including suppressed findings. One saved observation per UTC day; not unique CVEs. History starts with the first successful collection.",
  source: "crowdstrike",
  query: "status:['open','reopen']",
  crowdstrike: { dataset: "vulnerabilities", measure: "findings", groupBy: "none", top: 10, history: true },
  display: "line",
  chart: { category: "day", value: "findings" },
  refreshMinutes: 1440,
  enabled: true,
};

// Install the requested saved tile once for an already connected dashboard.
// A fixed ID makes startup idempotent and preserves edits and soft deletions.
export async function installDailyOpenVulnerabilityTile(db: Pool | PoolClient): Promise<void> {
  await db.query(`WITH added AS (
    INSERT INTO elastic_dashboard_queries (id, definition, display_order)
    SELECT $1, $2::jsonb,
      (SELECT COALESCE(MAX(display_order), -1) + 1 FROM elastic_dashboard_queries)
    WHERE EXISTS (SELECT 1 FROM dashboard_source_connections WHERE source = 'crowdstrike')
    ON CONFLICT (id) DO NOTHING
    RETURNING id
  ) INSERT INTO elastic_dashboard_audit (actor, action, query_id)
    SELECT 'system', 'query.daily-open-trend.installed', id FROM added`,
  [DAILY_OPEN_VULNERABILITIES.id, JSON.stringify(DAILY_OPEN_VULNERABILITIES)]);
}
