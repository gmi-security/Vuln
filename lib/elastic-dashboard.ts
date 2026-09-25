export type QueryResult = {
  columns: { name: string; type: string }[];
  rows: (string | number | boolean | null)[][];
  truncated: boolean;
  note?: string;
};

export class DashboardError extends Error {
  constructor(message: string, public status = 400) { super(message); }
}
export type DashboardSource = "elastic" | "crowdstrike";
export type CrowdStrikeOptions = {
  dataset: "vulnerabilities";
  view?: "summary" | "patch-worklist" | "severity-counts" | "cve-devices";
  measure: "findings" | "cves" | "hosts";
  groupBy: "none" | "host" | "severity" | "priority" | "status" | "cve";
  top: number;
  history: boolean;
};
export const DEFAULT_CROWDSTRIKE: CrowdStrikeOptions = {
  dataset: "vulnerabilities", measure: "findings", groupBy: "none", top: 10, history: false,
};
export type QueryInput = { query: string; source?: DashboardSource; crowdstrike?: CrowdStrikeOptions };
export type QueryDefinition = QueryInput & {
  id: string;
  title: string;
  description?: string;
  query: string;
  display: "auto" | "metrics" | "table" | "bar" | "line" | "doughnut";
  chart?: { category: string; value: string };
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
  crowdstrike?: { connected: boolean; region?: string };
  queries: DashboardQuery[];
};

export function querySource(value: { source?: unknown }): DashboardSource {
  if (value.source === undefined || value.source === "elastic") return "elastic";
  if (value.source === "crowdstrike") return "crowdstrike";
  throw new DashboardError("Choose a supported dashboard source.");
}

export function parseQueryInput(value: unknown): QueryInput {
  if (!value || typeof value !== "object") throw new DashboardError("Invalid query input.");
  const body = value as Record<string, unknown>;
  if (querySource(body) === "elastic") return { query: validateQuery(body.query) };
  if (typeof body.query !== "string" || !body.query.trim() || body.query.length > 4000 || /[\x00-\x1f\x7f]/.test(body.query)) {
    throw new DashboardError("Enter an FQL filter on one line, up to 4,000 characters.");
  }
  const options = body.crowdstrike as CrowdStrikeOptions | undefined;
  if (!options || options.dataset !== "vulnerabilities") throw new DashboardError("Choose the Vulnerabilities dataset.");
  if (options.view !== undefined && !["summary", "patch-worklist", "severity-counts", "cve-devices"].includes(options.view)) throw new DashboardError("Choose a supported vulnerability view.");
  if (!["findings", "cves", "hosts"].includes(options.measure) ||
      !["none", "host", "severity", "priority", "status", "cve"].includes(options.groupBy) ||
      ![10, 25, 50, 100].includes(options.top) || typeof options.history !== "boolean") {
    throw new DashboardError("Choose a valid measure, grouping, top limit, and history setting.");
  }
  if (options.history && options.groupBy !== "none") throw new DashboardError("Daily history requires no grouping. Use a separate tile for grouped results.");
  if (options.view === "patch-worklist" && (options.history || options.groupBy !== "none" || options.measure !== "findings")) {
    throw new DashboardError("Patch worklists use findings with no grouping or daily history.");
  }
  if (options.view === "severity-counts" && (options.history || options.groupBy !== "none" || options.measure !== "findings")) {
    throw new DashboardError("Severity counts use finding totals with no additional grouping or daily history.");
  }
  if (options.view === "cve-devices" && (options.history || options.groupBy !== "cve" || options.measure !== "hosts")) {
    throw new DashboardError("The CVE device table uses unique hosts grouped by CVE, with no daily history.");
  }
  return { source: "crowdstrike", query: body.query.trim(), crowdstrike: {
    dataset: options.dataset, measure: options.measure, groupBy: options.groupBy, top: options.top, history: options.history,
    ...(options.view && options.view !== "summary" ? { view: options.view } : {}),
  } };
}

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
  if (body.description !== undefined && (typeof body.description !== "string" || body.description.length > 600)) throw new DashboardError("Keep the tile description under 600 characters.");
  if (!["auto", "metrics", "table", "bar", "line", "doughnut"].includes(String(body.display))) throw new DashboardError("Choose a display type.");
  let chart: QueryDefinition["chart"];
  if (isChartDisplay(String(body.display))) {
    const mapping = body.chart as QueryDefinition["chart"];
    if (!mapping || typeof mapping.category !== "string" || typeof mapping.value !== "string" ||
        !mapping.category || !mapping.value || mapping.category.length > 256 || mapping.value.length > 256 || mapping.category === mapping.value) {
      throw new DashboardError("Preview the query and choose different category and numeric value columns.");
    }
    chart = { category: mapping.category, value: mapping.value };
  }
  if (typeof body.refreshMinutes !== "number" || ![5, 15, 30, 60, 1440].includes(body.refreshMinutes)) throw new DashboardError("Choose a refresh interval: 5, 15, 30, 60 minutes, or daily.");
  if (typeof body.enabled !== "boolean") throw new DashboardError("Invalid refresh setting.");
  const input = parseQueryInput(body);
  if (input.crowdstrike?.view === "patch-worklist" && !["auto", "table"].includes(String(body.display))) throw new DashboardError("Use Table for a patch worklist.");
  if (input.crowdstrike?.view === "severity-counts" && !["auto", "metrics", "table"].includes(String(body.display))) throw new DashboardError("Use Number cards or Table for severity counts.");
  if (input.crowdstrike?.view === "cve-devices" && !["auto", "table"].includes(String(body.display))) throw new DashboardError("Use Table for affected devices by CVE.");
  return { id, title: body.title.trim(), ...input, display: body.display as QueryDefinition["display"],
    ...(typeof body.description === "string" && body.description.trim() ? { description: body.description.trim() } : {}),
    refreshMinutes: body.refreshMinutes, enabled: body.enabled, ...(chart ? { chart } : {}) };
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
  return name.replace(/_pct$/i, " percentage").replace(/[_.]/g, " ").replace(/\bcves\b/gi, "CVEs").replace(/^./, (char) => char.toUpperCase());
}

export function isChartDisplay(display: string): display is "bar" | "line" | "doughnut" {
  return ["bar", "line", "doughnut"].includes(display);
}

export function numericColumn(type: string): boolean {
  return ["byte", "short", "integer", "long", "unsigned_long", "float", "half_float", "double", "scaled_float", "counter_long", "counter_double", "counter_integer"].includes(type);
}

export function suggestChart(result: QueryResult): QueryDefinition["chart"] {
  const value = result.columns.find((column) => numericColumn(column.type));
  const category = result.columns.find((column) => !numericColumn(column.type)) ?? result.columns.find((column) => column.name !== value?.name);
  return value && category ? { category: category.name, value: value.name } : undefined;
}

export function chartData(result: QueryResult, definition: Pick<QueryDefinition, "display" | "chart">) {
  const mapping = definition.chart;
  if (!mapping || mapping.category === mapping.value) throw new DashboardError("Choose category and value columns to preview the chart.");
  const categoryIndex = result.columns.findIndex((column) => column.name === mapping.category);
  const valueIndex = result.columns.findIndex((column) => column.name === mapping.value);
  if (categoryIndex < 0 || valueIndex < 0) throw new DashboardError("A selected chart column is missing. Edit the query and choose its columns again.");
  if (!numericColumn(result.columns[valueIndex].type)) throw new DashboardError("The chart value column must be numeric.");
  const categoryType = result.columns[categoryIndex].type;
  const scale = numericColumn(categoryType) ? "number" : ["date", "datetime", "date_nanos"].includes(categoryType) ? "time" : "category";
  const seen = new Set<string>();
  const points = result.rows.map((row) => {
    const raw = row[categoryIndex];
    if (raw === null) throw new DashboardError("Chart categories cannot be null. Filter or name missing categories in ES|QL.");
    const label = String(raw);
    if (seen.has(label)) throw new DashboardError("Return one row per category. Aggregate duplicates with STATS ... BY before charting.");
    seen.add(label);
    const value = row[valueIndex];
    if (value !== null && (typeof value !== "number" || !Number.isFinite(value))) throw new DashboardError("Chart values must be finite numbers or null.");
    if (definition.display === "doughnut" && value !== null && value < 0) throw new DashboardError("Doughnut charts require non-negative values. Use a bar or line chart for negatives.");
    const x = scale === "number" ? Number(raw) : scale === "time" ? Date.parse(label) : 0;
    if (scale !== "category" && !Number.isFinite(x)) throw new DashboardError("The chart category contains an invalid number or date.");
    return { label, value: value as number | null, x };
  });
  if (definition.display === "line" && scale !== "category") points.sort((a, b) => a.x - b.x);
  return { points, scale, category: mapping.category, value: mapping.value };
}

export function validateDisplayResult(result: QueryResult, definition: Pick<QueryDefinition, "display" | "chart">): void {
  if (definition.display === "metrics" && !canShowMetrics(result)) throw new DashboardError("Number cards require one row of numeric columns. Choose Table or Automatic.");
  if (isChartDisplay(definition.display)) chartData(result, definition);
}
