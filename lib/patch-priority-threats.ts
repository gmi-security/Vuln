import type {PoolClient} from "pg";
import type {PriorityThreat} from "./patch-priority";

// Saved public CVE evidence only; no provider calls, DDL, or finding-table scan.
export async function readPriorityThreats(db:Pick<PoolClient,"query">):Promise<Map<string,PriorityThreat>> {
  if(!(await db.query("SELECT to_regclass('public.cve_enrichment') AS enrichment")).rows[0]?.enrichment)return new Map();
  const rows=(await db.query(`SELECT cve,cisa_kev,active_exploitation,epss_probability,updated_at
    FROM cve_enrichment ORDER BY cve LIMIT 100001`)).rows;
  if(rows.length>100000)throw Error("Priority threat evidence exceeds the bounded cache capacity");
  return new Map(rows.map(r=>[r.cve,{kev:typeof r.cisa_kev==="boolean"?r.cisa_kev:null,active:typeof r.active_exploitation==="boolean"?r.active_exploitation:null,
    epss:r.epss_probability!==null&&Number.isFinite(Number(r.epss_probability))?Number(r.epss_probability):null,updatedAt:r.updated_at?new Date(r.updated_at).toISOString():null}]));
}

// Caller already owns a read-only transaction; a cache failure must not abort its source reads.
export async function optionalPriorityThreats(db:Pick<PoolClient,"query">):Promise<{threats:Map<string,PriorityThreat>;notice?:string}> {
  await db.query("SAVEPOINT priority_threats");
  try {const threats=await readPriorityThreats(db);await db.query("RELEASE SAVEPOINT priority_threats");return {threats};}
  catch {await db.query("ROLLBACK TO SAVEPOINT priority_threats");await db.query("RELEASE SAVEPOINT priority_threats");
    return {threats:new Map(),notice:"Saved threat enrichment is unavailable. Source signals are shown; missing evidence is Unknown."};}
}
