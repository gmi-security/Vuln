export type QueryResult = {
  columns: { name: string; type: string }[];
  rows: (string | number | boolean | null)[][];
  truncated: boolean;
};

export class DashboardError extends Error {
  constructor(message: string, public status = 400) { super(message); }
}
export type QueryDefinition = {
  id: string;
  title: string;
  query: string;
  display: "auto" | "metrics" | "table";
  refreshMinutes: number;
  enabled: boolean;
};
export type DashboardQuery = QueryDefinition & {
  result: QueryResult | null;
  refreshedAt: string | null;
  attemptedAt: string | null;
  error: string | null;
};
export type ElasticDashboard = {
  canManage: boolean;
  storageReady: boolean;
  connected: boolean;
  endpoint?: string;
  queries: DashboardQuery[];
};

export const DEFAULT_COVERAGE: QueryDefinition = {
  id: "asset-coverage", title: "Asset coverage", display: "auto", refreshMinutes: 15, enabled: true,
  query: `FROM logs-crowdstrike.discover_asset-*
| WHERE @timestamp >= NOW() - 25 hours
| EVAL last_seen = TO_DATETIME(last_seen_timestamp), age_days = DATE_DIFF("day", TO_DATETIME(last_seen_timestamp), NOW())
| WHERE last_seen >= NOW() - 7 days AND last_seen <= NOW()
| STATS managed = COUNT_DISTINCT(id) WHERE entity_type == "managed",
        unmanaged = COUNT_DISTINCT(id) WHERE entity_type == "unmanaged"
| EVAL coverage_pct = CASE(managed + unmanaged > 0, ROUND(managed * 100.0 / (managed + unmanaged), 1), null)`,
};

export function validateQuery(query: unknown): string {
  if (typeof query !== "string" || !query.trim() || query.length > 16_000) {
    throw new DashboardError("Enter an ES|QL query of at most 16,000 characters.");
  }
  return query.trim();
}

export function parseDefinition(value: unknown, id: string): QueryDefinition {
  if (!value || typeof value !== "object") throw new DashboardError("Invalid query definition.");
  const body = value as Record<string, unknown>;
  if (!/^[a-zA-Z0-9-]{1,64}$/.test(id)) throw new DashboardError("Invalid query ID.");
  if (typeof body.title !== "string" || !body.title.trim() || body.title.length > 100) throw new DashboardError("Enter a title of at most 100 characters.");
  if (!["auto", "metrics", "table"].includes(String(body.display))) throw new DashboardError("Choose a display type.");
  if (typeof body.refreshMinutes !== "number" || ![5, 15, 30, 60].includes(body.refreshMinutes)) throw new DashboardError("Choose a refresh interval: 5, 15, 30, or 60 minutes.");
  if (typeof body.enabled !== "boolean") throw new DashboardError("Invalid refresh setting.");
  return { id, title: body.title.trim(), query: validateQuery(body.query), display: body.display as QueryDefinition["display"],
    refreshMinutes: body.refreshMinutes, enabled: body.enabled };
}

export function parseQueryResult(value: unknown, warning = false): QueryResult {
  if (!value || typeof value !== "object") throw new DashboardError("Elastic returned an invalid response.");
  const body = value as Record<string, unknown>;
  if (warning || body.is_partial === true || body.is_running === true || body.error) {
    throw new DashboardError("Elastic returned warnings or incomplete results. The previous result was retained.");
  }
  if (!Array.isArray(body.columns) || body.columns.length < 1 || body.columns.length > 32 ||
      !Array.isArray(body.values) || body.values.length > 101) throw new DashboardError("Return at most 32 columns and 100 rows for a dashboard tile.");
  const names = new Set<string>();
  const columns = body.columns.map((column: unknown) => {
    if (!column || typeof column !== "object") throw new DashboardError("Invalid result column.");
    const item = column as Record<string, unknown>;
    if (typeof item.name !== "string" || item.name.length > 256 || names.has(item.name) || typeof item.type !== "string") throw new DashboardError("Invalid or duplicate column name.");
    names.add(item.name);
    return { name: item.name, type: item.type };
  });
  const rows = body.values.slice(0, 100).map((row: unknown) => {
    if (!Array.isArray(row) || row.length !== columns.length) throw new DashboardError("Invalid result row.");
    return row.map((cell: unknown) => {
      if (cell === null || typeof cell === "boolean") return cell;
      if (typeof cell === "number" && Number.isFinite(cell)) return cell;
      if (typeof cell === "string") return cell.slice(0, 2000);
      if (Array.isArray(cell)) return JSON.stringify(cell).slice(0, 2000);
      throw new DashboardError("Unsupported result value.");
    });
  });
  return { columns, rows, truncated: body.values.length > 100 };
}

export function canShowMetrics(result: QueryResult): boolean {
  return result.rows.length === 1 && result.rows[0].every((value) => value === null || typeof value === "number");
}

export function columnLabel(name: string): string {
  return name.replace(/_pct$/i, " percentage").replace(/[_.]/g, " ").replace(/^./, (char) => char.toUpperCase());
}
