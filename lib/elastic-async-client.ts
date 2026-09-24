import { setTimeout as delay } from "node:timers/promises";
import { DashboardError, parseQueryResult, validateQuery, type QueryResult } from "./elastic-dashboard";
import { elasticJsonRequest, type ElasticConnection } from "./elastic-query-client";

// Individual HTTP calls remain short. Elasticsearch does the long-running work.
export async function executeEsqlAsync(connection: ElasticConnection, query: string, budgetMs = 300_000): Promise<QueryResult> {
  const deadline = Date.now() + Math.min(budgetMs, 300_000);
  let id: string | undefined;
  let warning = false;
  try {
    let reply = await elasticJsonRequest(connection, "/_query/async?format=json&allow_partial_results=false", "POST", {
      query: `${validateQuery(query)}\n| LIMIT 101`, columnar: false,
      wait_for_completion_timeout: "1s", keep_alive: "10m", keep_on_completion: false,
    });
    while (true) {
      if (typeof reply.body.id === "string" && reply.body.id.length <= 4096) id = reply.body.id;
      warning ||= reply.warning;
      if (reply.body.is_running !== true) return parseQueryResult(reply.body, warning);
      if (!id) throw new DashboardError("Elastic did not return an async query ID.");
      if (Date.now() >= deadline) throw new DashboardError("Elastic query exceeded the five-minute execution limit. Narrow the query or use a summary index.");
      await delay(Math.min(2000, Math.max(0, deadline - Date.now())));
      if (Date.now() >= deadline) throw new DashboardError("Elastic query exceeded the five-minute execution limit. Narrow the query or use a summary index.");
      reply = await elasticJsonRequest(connection, `/_query/async/${encodeURIComponent(id)}?wait_for_completion_timeout=1s&format=json`, "GET");
    }
  } finally {
    // Same key owns this query; no cluster-management privilege is required.
    // Elastic expires it after ten minutes if cleanup cannot reach the cluster.
    if (id) await elasticJsonRequest(connection, `/_query/async/${encodeURIComponent(id)}`, "DELETE").catch(() => {});
  }
}
