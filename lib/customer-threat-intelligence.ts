import { resolveCustomerScope } from "./customer-scope";
import { applicationDatabase } from "./persist";
import { listFindings } from "./store";
import { openCustomerFindings } from "./customer-cve-model";
import { DashboardError } from "./elastic-dashboard";

export async function customerThreatIntelligence(companyId:string) {
  const scope=await resolveCustomerScope(companyId),db=applicationDatabase();
  if(!db) throw new DashboardError("Threat intelligence storage is unavailable.",503);
  const cves=[...new Set(openCustomerFindings(scope.companyId,listFindings({companyId:scope.companyId})).map(row=>row.cve.toUpperCase()))];
  const client=await db.connect();
  try {
    await client.query("BEGIN READ ONLY");
    await client.query("SET LOCAL statement_timeout = '15s'");
    const tables=(await client.query("SELECT to_regclass('public.cve_enrichment') AS enrichment, to_regclass('public.finding_risk') AS risk")).rows[0];
    if(!tables.enrichment) {await client.query("COMMIT");return {companyId,available:false,rows:[],total:0};}
    const rows=(await client.query(`SELECT e.cve,e.cisa_kev,e.epss_probability,e.active_exploitation,
      e.active_exploitation_source,e.active_exploitation_detail,e.updated_at,COUNT(*) OVER()::int AS total
      FROM cve_enrichment e WHERE (e.cve=ANY($2::text[]) ${tables.risk ? `OR EXISTS(SELECT 1 FROM finding_risk r
        WHERE r.company_id=$1 AND r.cve=e.cve AND r.source_open=true AND r.verification_status <> 'verified_remediated')` : "OR $1::text IS NULL"})
      AND (e.cisa_kev OR e.active_exploitation OR e.epss_probability IS NOT NULL)
      ORDER BY e.cisa_kev DESC,e.active_exploitation DESC,e.epss_probability DESC NULLS LAST,e.cve LIMIT 50`,[companyId,cves])).rows;
    await client.query("COMMIT");
    return {companyId,available:true,rows,total:rows[0]?.total ?? 0};
  } catch(error) {await client.query("ROLLBACK").catch(()=>{});throw error;} finally {client.release();}
}
