import {isDeepStrictEqual} from 'node:util';
import {privateShadowDatabase} from './defender-platform-shadow.mjs';
import {readDefenderRefreshSource} from './defender-refresh-source.mjs';
const requireValue=(v,m)=>{if(!v)throw Error(m);};
const keys=['meta','companies:00',...Array.from({length:64},(_,i)=>`findings:${String(i).padStart(2,'0')}`),...Array.from({length:16},(_,i)=>`assets:${String(i).padStart(2,'0')}`)].sort();
// xmin detects committed row replacement even if updated_at was not changed.
// All buckets are fenced conservatively, including other customers' updates.
async function fence(client,companyId){
  const {rows:buckets}=await client.query('SELECT key,xmin::text version,tableoid::text relation FROM vuln_store WHERE key=ANY($1::text[]) ORDER BY key',[keys]);
  requireValue(isDeepStrictEqual(buckets.map(r=>r.key),keys),'Complete snapshot buckets required');
  const {rows:[source]}=await client.query(`SELECT c.current_run::text run,c.revision,c.xmin::text connection_version,r.xmin::text run_version,
    c.last_success_at::text observed,r.status,r.revision source_revision FROM defender_connections c
    JOIN defender_import_runs r ON r.id=c.current_run AND r.company_id=c.company_id WHERE c.company_id=$1`,[companyId]);
  requireValue(source?.status==='succeeded'&&source.revision===source.source_revision,'Complete matching source generation required');
  const {rows:[database]}=await client.query('SELECT oid::text id,datname name FROM pg_database WHERE datname=current_database()');
  return {version:1,companyId,database,buckets,source};
}
export async function readDefenderRefreshBaseline(client,companyId,{afterPinned,deadlineMs=180000}={}){
  requireValue(typeof companyId==='string'&&/^CO-[A-Za-z0-9-]+$/.test(companyId),'Explicit customer required');
  requireValue(Number.isInteger(deadlineMs)&&deadlineMs>0&&deadlineMs<=300000,'Invalid baseline deadline');
  await privateShadowDatabase(client,'source');const started=Date.now();let bytes=0;
  const check=()=>requireValue(Date.now()-started<deadlineMs,'Baseline read deadline exceeded');
  await client.query('BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY');
  try{
    await client.query("SET LOCAL statement_timeout='15s';SET LOCAL idle_in_transaction_session_timeout='60s'");
    const baselineFence=await fence(client,companyId);await afterPinned?.();
    const {rows:[meta]}=await client.query(`SELECT data ?| ARRAY['findings','assets','companies'] overrides,
      data->'meta'->'defenderGenerations'->>$1 run,data->'compensatingControls' controls,updated_at FROM vuln_store WHERE key='meta'`,[companyId]);
    requireValue(meta&&!meta.overrides,'Unsupported snapshot overrides');
    requireValue(Array.isArray(meta.controls),'Explicit saved compensating controls required');
    const controls=meta.controls.map(row=>{requireValue(Array.isArray(row)&&row.length===2&&row[0]===row[1]?.id,'Invalid saved control');return row[1];}).filter(c=>c.companyId===companyId);
    const {rows:companies}=await client.query(`SELECT entry->1 company FROM vuln_store,LATERAL jsonb_array_elements(data) entry WHERE key='companies:00' AND entry->>0=$1`,[companyId]);
    requireValue(companies.length===1&&companies[0].company.id===companyId&&!companies[0].company.isDemo,'Known non-demo customer required');
    async function collection(prefix,max){
      const output=[];
      for(const key of keys.filter(k=>k.startsWith(prefix+':'))){
        check();
        const {rows:[shape]}=await client.query('SELECT jsonb_typeof(data) type FROM vuln_store WHERE key=$1',[key]);requireValue(shape.type==='array','Invalid snapshot bucket shape');
        const {rows:[size]}=await client.query(`SELECT count(*)::int n,coalesce(sum(octet_length((entry->1)::text)),0)::text bytes,
          bool_and(jsonb_typeof(entry)='array' AND jsonb_array_length(entry)=2 AND entry->>0=entry->1->>'id') valid
          FROM vuln_store,LATERAL jsonb_array_elements(data) entry WHERE key=$1 AND entry->1->>'companyId'=$2`,[key,companyId]);
        bytes+=Number(size.bytes);requireValue((size.n===0||size.valid===true)&&size.n<=20000&&output.length+size.n<=max&&bytes<=768*1024*1024,'Invalid or oversized customer baseline');
        const {rows}=await client.query(`SELECT entry->1 record FROM vuln_store,LATERAL jsonb_array_elements(data) WITH ORDINALITY AS entries(entry,n)
          WHERE key=$1 AND entry->1->>'companyId'=$2 ORDER BY n`,[key,companyId]);
        output.push(...rows.map(r=>r.record));
      }
      return output;
    }
    const findings=await collection('findings',500000),assets=await collection('assets',100000);
    const source=await readDefenderRefreshSource(client,companyId,{inTransaction:true,deadlineMs:Math.max(1,deadlineMs-(Date.now()-started))});check();
    await client.query('COMMIT');
    return {company:companies[0].company,baseline:{runId:meta.run??null,savedAt:new Date(meta.updated_at).toISOString(),findings,assets},source,controls,baselineFence};
  }catch(error){await client.query('ROLLBACK').catch(()=>{});throw error;}
}
export async function checkDefenderRefreshBaseline(client,expected){
  requireValue(expected?.version===1&&typeof expected.companyId==='string','Explicit baseline fence required');
  await privateShadowDatabase(client,'source');await client.query('BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY');
  try{
    await client.query("SET LOCAL statement_timeout='15s'");
    const current=await fence(client,expected.companyId);await client.query('COMMIT');
    return {unchanged:isDeepStrictEqual(current,expected),scope:'persisted-state-only'};
  }catch(error){await client.query('ROLLBACK').catch(()=>{});throw error;}
}
