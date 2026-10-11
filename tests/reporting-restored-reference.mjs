// Independent legacy-model reference for retained-data parity checks.
import {executiveHarness} from './executive-report-harness.mjs';
export async function originalExecutive(source,companyId,capturedAt){
 await source.query('BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY');
 try{
  const company=(await source.query("SELECT e->1 company FROM vuln_store,LATERAL jsonb_array_elements(data) e WHERE key='companies:00' AND e->>0=$1",[companyId])).rows[0].company;
  const meta=(await source.query("SELECT data FROM vuln_store WHERE key='meta'")).rows[0].data;
  const h=await executiveHarness(Date.parse(capturedAt));h.threat.restoreReportingKevCatalog(meta.reportingKevCatalog);
  const state={companies:new Map([[company.id,company]]),findings:new Map(),assets:new Map(),scans:new Map(),folders:new Map(),
   identityAliases:new Map(),compensatingControls:new Map(),meta:{},seeded:true,counter:1000,
   settings:{sla:meta.settings.sla,autoScanNewAssets:false,schedule:{autoSyncEnabled:false,alertsEnabled:false,monthlyReportsEnabled:false}}};
  const fields=['id','companyId','connector','cve','title','asset','category','status','severity','realRisk','cvss','cvssV2','cvssV3',
   'epss','firstSeen','resolvedAt','kev','ransomware','exploitAvailable','assetExposure','assetCriticality'];
  for(const [kind,n] of [['findings',64],['scans',8],['assets',16]])for(let i=0;i<n;i++){
   const projection=kind==='findings'?`jsonb_build_object(${fields.flatMap(k=>[`'${k}'`,`f->'${k}'`]).join(',')})`:'f';
   const {rows}=await source.query(`SELECT ${projection} record FROM vuln_store,LATERAL jsonb_array_elements(data) WITH ORDINALITY x(e,n),
    LATERAL(SELECT e->1 f) y WHERE key=$1 AND f->>'companyId'=$2 ORDER BY n`,[`${kind}:${String(i).padStart(2,'0')}`,companyId]);
   for(const {record} of rows)state[kind].set(record.id,record);
  }
  h.setState(state);const report=JSON.parse(JSON.stringify(h.legacy.legacyExecutiveReport(h.store,state,companyId)));
  const trend=(await source.query("SELECT ts,data FROM vuln_metrics_history WHERE company_id=$1 AND ts >= $2::timestamptz-interval '180 days' ORDER BY ts,id",[companyId,capturedAt])).rows.map(r=>({ts:r.ts.toISOString(),companyId,...r.data}));
  await source.query('COMMIT');return {...report,trend};
 }catch(error){await source.query('ROLLBACK');throw error;}
}
export async function originalSections(source,reference,companyId,capturedAt){
 await source.query('BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY');
 try{
  const c=(await source.query("SELECT e->1 company FROM vuln_store,LATERAL jsonb_array_elements(data) e WHERE key='companies:00' AND e->>0=$1",[companyId])).rows[0].company;
  const input={findings:[],scans:[],assets:[],history:[]};
  for(const [kind,n] of [['findings',64],['scans',8],['assets',16]])for(let i=0;i<n;i++){
   // Independently project only fields consumed by the unchanged report.
   const select=kind==='findings'?`jsonb_build_object('id',f->'id','companyId',f->'companyId','cve',f->'cve','title',f->'title',
    'asset',f->'asset','status',f->'status','severity',f->'severity','realRisk',f->'realRisk','cvss',f->'cvss',
    'connector',f->'connector','seenBy',f->'seenBy','lastSeen',f->'lastSeen','assetSource',f->'assetSource',
    'kev',f->'kev','exploitAvailable',f->'exploitAvailable','enrichments',f->'enrichments')`:'f';
   const {rows}=await source.query(`SELECT ${select} record FROM vuln_store,LATERAL jsonb_array_elements(data) WITH ORDINALITY x(e,n),
    LATERAL(SELECT e->1 f) y WHERE key=$1 AND f->>'companyId'=$2 ORDER BY n`,[`${kind}:${String(i).padStart(2,'0')}`,companyId]);
   input[kind].push(...rows.map(r=>r.record));
  }
  input.history=(await source.query("SELECT ts,data FROM vuln_metrics_history WHERE company_id=$1 AND ts >= $2::timestamptz-interval '180 days' ORDER BY ts,id",[companyId,capturedAt])).rows.map(r=>({ts:r.ts.toISOString(),data:r.data}));
  const contributors=[...new Set(input.findings.map(f=>f.connector))].sort();
  input.findings.sort((a,b)=>b.realRisk-a.realRisk||b.cvss-a.cvss);
  input.scans.sort((a,b)=>b.createdAt>a.createdAt?1:-1);input.assets.sort((a,b)=>a.identifier.localeCompare(b.identifier));
  const model=reference({id:c.id,name:c.name},input.findings,input.scans,input.assets,input.history);
  await source.query('COMMIT');return {model,contributors,records:input.findings.length};
 }catch(error){await source.query('ROLLBACK');throw error;}
}
