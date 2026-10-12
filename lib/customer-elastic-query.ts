import { DashboardError, type QueryResult } from "./elastic-dashboard";
import { customerEsql, resolvedElasticIndices } from "./customer-elastic-scope";
import { elasticJsonRequest, executeEsql, type ElasticConnection } from "./elastic-query-client";
import { executeEsqlAsync } from "./elastic-async-client";

// The first reviewed adapter is for Elastic Stack, not Serverless cross-project
// search. This metadata-only check is also used when replacing the saved key:
// saving a credential must not require querying an arbitrary customer's data.
export async function checkReviewedElasticConnection(connection: ElasticConnection) {
  const { body, warning } = await elasticJsonRequest(connection, "/", "GET");
  const version = body.version as { build_flavor?: string; number?: string } | undefined;
  if (warning || version?.build_flavor !== "default" || !/^\d+\.\d+\.\d+/.test(version.number ?? ""))
    throw new DashboardError("Reviewed Elasticsearch queries require a verified Elastic Stack deployment. Serverless and cross-project sources need a separate adapter.", 409);
}

export async function executeCustomerEsql(connection: ElasticConnection, query: string, background: boolean, datasets: string[]): Promise<QueryResult> {
  try {
    const scoped = customerEsql(query, datasets);
    await checkReviewedElasticConnection(connection);
    const { body, warning } = await elasticJsonRequest(connection,
      `/_resolve/index/${scoped.datasets.map(encodeURIComponent).join(",")}?expand_wildcards=none`, "GET");
    if (warning) throw new Error("Elasticsearch dataset resolution returned a warning. Review the source before querying.");
    const names = resolvedElasticIndices(scoped.datasets, body);
    // Pin this request to the resolved physical indexes. Never send an alias,
    // user wildcard or data stream name that can expand again during the query.
    const bounded = `FROM ${names.map(name => `"${name}"`).join(", ")}${scoped.suffix}`;
    if (bounded.length > 16000) throw new Error("Approved dataset expansion is too large. Narrow the tile to fewer datasets.");
    const result = background ? await executeEsqlAsync(connection, bounded) : await executeEsql(connection, bounded);
    return { ...result, note: [result.note, "Scoped to this customer's approved datasets. FROM patterns are restricted to those datasets; data stream rollover after collection begins is included on the next refresh."].filter(Boolean).join(" ") };
  } catch (error) {
    if (error instanceof DashboardError) throw error;
    throw new DashboardError(error instanceof Error ? error.message : "Customer Elasticsearch scope could not be verified.", 409);
  }
}
