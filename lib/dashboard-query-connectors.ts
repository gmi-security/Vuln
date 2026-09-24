import { executeEsql, openConnection, type ElasticConnection } from "./elastic-query-client";
import { executeEsqlAsync } from "./elastic-async-client";
import { executeCrowdStrike, openCrowdStrike } from "./crowdstrike-dashboard-client";
import { type CrowdStrikeConnection } from "./crowdstrike-dashboard";
import { type DashboardSource, type QueryInput, type QueryResult } from "./elastic-dashboard";

type Connector = {
  label: string;
  open: (secret: string) => unknown;
  execute: (connection: unknown, input: QueryInput, background: boolean) => Promise<QueryResult>;
};
// All tiles use the same store, job worker, refresh schedule and renderer.
// Only the connector understands the upstream API and its credentials.
export const DASHBOARD_CONNECTORS: Record<DashboardSource, Connector> = {
  elastic: { label: "Elasticsearch", open: openConnection,
    execute: (connection, input, background) => background ? executeEsqlAsync(connection as ElasticConnection, input.query) : executeEsql(connection as ElasticConnection, input.query) },
  crowdstrike: { label: "CrowdStrike", open: openCrowdStrike,
    execute: (connection, input) => executeCrowdStrike(connection as CrowdStrikeConnection, input) },
};
