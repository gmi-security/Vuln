import type { PoolClient } from "pg";
import type { Finding } from "./types";
import type { SpotlightRoute } from "./customer-spotlight-routing";
import { reviewedSpotlightProviders } from "./customer-spotlight-routing";
import { loadReviewedSpotlightRoutes } from "./customer-spotlight-routing-server";
import { applicationDatabase } from "./persist";
import { DashboardError } from "./elastic-dashboard";

/** Evidence for a saved source generation, distinct from a live query proof. */
export type StoredSpotlightScopeProof = { version: 1; companyId: string; runId: string; cid: string; bindingKey: string };
export type StoredSpotlightContext = { reviewed: boolean; route: SpotlightRoute | null };
const fail = (message: string): never => { throw new DashboardError(message, 409); };
const stale = () => fail("Saved CrowdStrike evidence needs a completed import under the current customer approval. Refresh the reviewed import and prepare the CVE again.");

export async function storedSpotlightContext(companyId: string): Promise<StoredSpotlightContext> {
  try {
    const routes = await loadReviewedSpotlightRoutes("crowdstrike");
    return { reviewed: routes !== null, route: routes?.find(route => route.companyId === companyId) ?? null };
  } catch { return fail("Reviewed CrowdStrike source ownership is unavailable or needs renewed approval. No legacy source fallback was used."); }
}

/** Constant-size metadata lookups. Publication already validated the entire v4
 * generation; page requests must not repeat that multi-million-row aggregation.
 */
export async function storedSpotlightProof(client: Pick<PoolClient, "query">, context: StoredSpotlightContext,
  companyId: string, runId: string): Promise<StoredSpotlightScopeProof | null> {
  if (!context.reviewed) return null;
  const route = context.route;
  if (!route || route.companyId !== companyId) return stale();
  const tables = (await client.query("SELECT to_regclass('public.spotlight_import_runs') AS runs, to_regclass('public.spotlight_import_run_scopes') AS scopes")).rows[0];
  if (!tables?.runs || !tables?.scopes) return stale();
  const row = (await client.query(`SELECT r.tenant_key,r.status,r.finished_at,r.checkpoint_version,r.expected_count,r.hydrated_count,
    pin.company_id,pin.cid,pin.binding_key FROM spotlight_import_runs r
    JOIN spotlight_import_run_scopes pin ON pin.run_id=r.id WHERE r.id=$1::uuid`, [runId])).rows[0];
  const expected = Number(row?.expected_count);
  if (!row || row.tenant_key !== companyId || row.company_id !== companyId || row.status !== "completed" || !row.finished_at ||
      row.checkpoint_version !== 4 || !Number.isSafeInteger(expected) || expected <= 0 || Number(row.hydrated_count) !== expected ||
      row.cid !== route.sourceScope || row.binding_key !== route.bindingKey) return stale();
  return { version: 1, companyId, runId, cid: route.sourceScope, bindingKey: route.bindingKey };
}

/** RAM CrowdStrike findings have no retained CID/generation proof. A mixed
 * finding also cannot be split safely into independent source assessments.
 */
export function reviewedPlatformFindings(findings: Finding[], context: StoredSpotlightContext, hasGeneration: boolean) {
  return findings.filter(row => reviewedPlatformFinding(row,context,hasGeneration));
}
export function reviewedPlatformFinding(row: Finding, context: StoredSpotlightContext, hasGeneration: boolean): boolean {
    if (!context.reviewed) return !hasGeneration || row.connector.toLowerCase() !== "crowdstrike";
    const sources = new Set([row.connector, ...(row.seenBy ?? [])].map(source => source.toLowerCase()));
    if (!sources.has("crowdstrike")) return true;
    if (sources.size > 1 || row.defender?.active) return fail("This CVE has merged CrowdStrike and other source evidence. Source ownership must be reconciled before showing or preparing it.");
    if (!hasGeneration) return stale();
    return false;
}

/** Rechecks approval/configuration and the current generation after other async
 * work. Caller holds no app-pool client, so a one-client pool cannot deadlock.
 */
export async function recheckStoredSpotlightProof(proof: StoredSpotlightScopeProof | null) {
  if (!proof) return;
  const context = await storedSpotlightContext(proof.companyId);
  if (!context.reviewed || proof.version !== 1 || context.route?.bindingKey !== proof.bindingKey || context.route.sourceScope !== proof.cid) return stale();
  const db = applicationDatabase();
  if (!db) throw new DashboardError("Source database is unavailable.", 503);
  const client = await db.connect();
  try {
    await client.query("BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY");
    await client.query("SET LOCAL statement_timeout = '15s'");
    const tables = (await client.query("SELECT to_regclass('public.spotlight_import_current') AS current")).rows[0];
    if (!tables?.current) return stale();
    const current = (await client.query("SELECT run_id FROM spotlight_import_current WHERE tenant_key=$1", [proof.companyId])).rows[0];
    if (current?.run_id !== proof.runId) return stale();
    await storedSpotlightProof(client, context, proof.companyId, proof.runId);
    await client.query("COMMIT");
  } catch (error) { await client.query("ROLLBACK").catch(() => {}); throw error; }
  finally { client.release(); }
}

export type StoredSpotlightPacket = { source?: string; appCompanyId?: string; connectors?: string[];
  storedSpotlightScope?: StoredSpotlightScopeProof; tenantId?: string; hostScope?: string[];
  deviceCves?: { cid: string; hostId: string; cve: string }[] };
export async function assertStoredSpotlightPacketScope(packet: StoredSpotlightPacket) {
  if (packet.source !== "stored-findings") return;
  // Default-off preserves rollback behavior. It is not a provider kill switch.
  let reviewed: boolean;
  try { reviewed = reviewedSpotlightProviders(process.env.VULN_REVIEWED_SPOTLIGHT_PROVIDERS).includes("crowdstrike"); }
  catch { return fail("Reviewed Spotlight routing configuration is invalid."); }
  if (!reviewed) return;
  const sources = new Set((packet.connectors ?? []).map(source => source.toLowerCase()));
  const proof = packet.storedSpotlightScope;
  const possibleCrowdStrike = sources.has("crowdstrike") || proof || /^[a-f0-9]{32}$/i.test(packet.tenantId ?? "");
  if (!possibleCrowdStrike) return;
  if (!proof || proof.companyId !== packet.appCompanyId || packet.tenantId !== proof.cid || sources.size !== 1 || !sources.has("crowdstrike")) return stale();
  const hosts = new Set(packet.hostScope ?? []);
  if (!hosts.size || !packet.deviceCves?.length) return stale();
  for (const value of hosts) {
    let pair: unknown;
    try { pair = JSON.parse(value); } catch { return stale(); }
    if (!Array.isArray(pair) || pair.length !== 2 || pair[0] !== proof.cid || typeof pair[1] !== "string" || !pair[1].trim()) return stale();
  }
  for (const device of packet.deviceCves) {
    if (device.cid !== proof.cid || !device.hostId || !hosts.has(JSON.stringify([device.cid, device.hostId]))) return stale();
  }
  if (new Set(packet.deviceCves.map(device => JSON.stringify([device.cid, device.hostId]))).size !== hosts.size) return stale();
  await recheckStoredSpotlightProof(proof);
}
