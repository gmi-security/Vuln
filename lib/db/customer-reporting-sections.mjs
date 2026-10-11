// Saved platform records -> bounded report sections. This is NOT raw-source
// aggregation or source authority activation. The optional executive bundle
// shares this committed input, policy, time and atomic publication.
import {createHash,randomUUID} from 'node:crypto';
import {readPlatformAuthority,platformMetadata} from './platform-authority.mjs';
import {platformCollections} from './platform-records.mjs';
const requireValue=(ok,message)=>{if(!ok)throw Error(message);};
const MAX_BYTES=2*1024*1024;
const canonical=value=>Array.isArray(value)?value.map(canonical):value&&typeof value==='object'?
 Object.fromEntries(Object.keys(value).sort().map(key=>[key,canonical(value[key])])):value;
const modelHash=model=>createHash('sha256').update(JSON.stringify(canonical(model))).digest('hex');
import {reportingKeys as keys,reportingFields as fields,readReportingInputRevision} from './customer-reporting-revisions.mjs';
import {readReportingSourceReview,checkReportingRecordSources} from './customer-reporting-review.mjs';
const projection=kind=>`jsonb_strip_nulls(jsonb_build_object(${fields[kind].flatMap(k=>[`'${k}'`,`f->'${k}'`]).join(',')}))`;
const checkCompany=id=>requireValue(typeof id==='string'&&id.length>0&&id.length<=100,'Explicit reporting customer required');
export async function assertReportingStorage(client,target,mode){
 if(mode!==undefined&&mode!=="published")throw Error("Unknown reporting storage mode");
 if(mode==="published"){
  const names=target?["customer_reporting_sections","customer_reporting_jobs"]:["customer_reporting_inputs","customer_reporting_publication","customer_source_selections","customer_connector_bindings","customer_connector_drafts"];
  const {rows:[g]}=await client.query("SELECT current_database() db, bool_and(to_regclass('public.'||name) IS NOT NULL) ready FROM unnest($1::text[]) name",[names]);
  requireValue(g.ready,"Explicit reporting migrations required");return g.db;
 }
 const {rows:[g]}=await client.query("SELECT current_database() db,current_setting('data_directory') dir,current_setting('listen_addresses') listen");
 requireValue(g.dir.startsWith('/home/codex/vuln-recovery/')&&!g.listen&&
  (target?/^vuln2_reporting_test_[a-f0-9]+$/.test(g.db):g.db==='recovery_application'||/^vuln2_reporting_source_test_[a-f0-9]+$/.test(g.db)),
  'Private reporting verification database required');
 return g.db;
}
async function manifest(client,companyId,asOf,mode){
 const authority=await readPlatformAuthority(client);
 const metadata=authority?.mode==='sql'?await platformMetadata(client,authority):null;
 const context=metadata?{sla:metadata.settings?.sla,catalog:metadata.reportingKevCatalog}:
  (await client.query("SELECT data->'settings'->'sla' sla,data->'reportingKevCatalog' catalog FROM vuln_store WHERE key='meta'")).rows[0];
 const policy={sla:context?.sla??null,catalog:context?.catalog??null};
 if(mode==="published"){
  const input=await readReportingInputRevision(client,companyId),review=await readReportingSourceReview(client,companyId);
  const history=await historyManifest(client,companyId,asOf);
  return {fingerprint:modelHash({version:2,input,review:review.pin,history,policy}),history,review,input,policy};
 }
 const {rows}=await client.query('SELECT key,xmin::text AS revision FROM vuln_store WHERE key=ANY($1::text[]) ORDER BY key',[keys]);
 requireValue(rows.length===keys.length&&rows.every((r,i)=>r.key===keys[i]),'Complete reporting snapshot required');
 const history=await historyManifest(client,companyId,asOf);
 const {rows:[identity]}=await client.query("SELECT current_database() db,'vuln_store'::regclass::oid::text relation");
 return {fingerprint:createHash('sha256').update(JSON.stringify({version:2,identity,rows,history,policy})).digest('hex'),history,policy};
}
async function historyManifest(client,companyId,asOf){
 const {rows:history}=await client.query(`SELECT id::text,xmin::text AS revision,ts::text FROM vuln_metrics_history
  WHERE company_id=$1 AND ts >= $2::timestamptz - interval '180 days' ORDER BY ts,id LIMIT 10001`,[companyId,asOf]);
 requireValue(history.length<=10000,'Reporting history limit exceeded');
 return history;
}
async function company(client,id){
 if((await readPlatformAuthority(client))?.mode==='sql'){
  const {rows}=await client.query("SELECT id,payload->>'name' name,payload->>'industry' industry,payload->'isDemo' demo FROM app_companies WHERE id=$1 AND payload->>'id'=$1",[id]);
  requireValue(rows.length===1&&(rows[0].demo===false||rows[0].demo===null)&&typeof rows[0].name==='string','Known non-demo reporting customer required');
  return {id:rows[0].id,name:rows[0].name,industry:rows[0].industry};
 }
 const {rows:[meta]}=await client.query("SELECT data ?| ARRAY['companies','findings','assets','scans'] AS overrides FROM vuln_store WHERE key='meta'");
 requireValue(meta&&!meta.overrides,'Unsupported reporting snapshot overrides');
 const {rows}=await client.query(`SELECT c->1->>'id' id,c->1->>'name' name,c->1->>'industry' industry,c->1->'isDemo' demo FROM vuln_store,
  LATERAL jsonb_array_elements(data) c WHERE key='companies:00' AND c->>0=$1 AND c->1->>'id'=$1`,[id]);
 requireValue(rows.length===1&&(rows[0].demo===false||rows[0].demo===null)&&typeof rows[0].name==='string','Known non-demo reporting customer required');
 return {id:rows[0].id,name:rows[0].name,industry:rows[0].industry};
}
async function traverse(client,id,kind,accept,deadline,checkpoint,buckets=keys){
 const sqlAuthority=(await readPlatformAuthority(client))?.mode==='sql';
 for(const key of buckets.filter(k=>k.startsWith(kind+':'))){
  await checkpoint?.();
  requireValue(Date.now()<deadline,'Reporting build deadline exceeded');
  if(sqlAuthority){
   const config=platformCollections[kind];requireValue(config,'Invalid reporting collection');
   let order=-1,afterId='';const b=Number(key.split(':')[1]);
   for(;;){
    const {rows}=await client.query(`SELECT id,store_order,${projection(kind)} record FROM ${config.table},
     LATERAL(SELECT payload f) x WHERE company_id=$1 AND store_bucket=$2 AND (store_order,id)>($3::double precision,$4::text)
     ORDER BY store_order,id LIMIT 500`,[id,b,order,afterId]);
    if(!rows.length)break;
    requireValue(Buffer.byteLength(JSON.stringify(rows))<=32*1024*1024,'Reporting projected page exceeds 32 MiB');
    for(const {record} of rows){if(kind==='scans')record.completedAt??=null;accept(record);}
    order=rows.at(-1).store_order;afterId=rows.at(-1).id;await checkpoint?.();
    requireValue(Date.now()<deadline,'Reporting build deadline exceeded');await new Promise(resolve=>setImmediate(resolve));
   }
   continue;
  }
  const {rows:[shape]}=await client.query(`SELECT jsonb_typeof(data) type FROM vuln_store WHERE key=$1`,[key]);
  requireValue(shape?.type==='array','Invalid reporting bucket');
  const {rows:[valid]}=await client.query(`SELECT count(*)::int n,count(DISTINCT e->>0)::int unique_ids,
   COALESCE(jsonb_agg(e->>0),'[]'::jsonb) ids,bool_and(COALESCE(CASE WHEN jsonb_typeof(e)='array' THEN
   jsonb_array_length(e)=2 AND jsonb_typeof(e->1)='object' AND e->>0=e->1->>'id'
    AND jsonb_typeof(e->1->'companyId')='string' ELSE false END,false)) valid
   FROM vuln_store,LATERAL jsonb_array_elements(data) e WHERE key=$1`,[key]);
  requireValue(valid.n<=50000&&valid.unique_ids===valid.n&&(valid.n===0||valid.valid),'Invalid or oversized reporting bucket');
  const bucketCount=kind==='findings'?64:kind==='scans'?8:16,bucketIndex=Number(key.split(':')[1]);
  requireValue(valid.ids.every(id=>createHash('sha1').update(id).digest().readUInt32BE(0)%bucketCount===bucketIndex),
   'Reporting identity stored in the wrong bucket');
  const sql=`SELECT ${projection(kind)} record FROM vuln_store,LATERAL jsonb_array_elements(data) WITH ORDINALITY x(e,n),
   LATERAL(SELECT e->1 f) y WHERE key=$1 AND f->>'companyId'=$2 ORDER BY n`;
  const {rows:[size]}=await client.query(`SELECT COALESCE(sum(octet_length(record::text)),0)::text bytes FROM (${sql}) projected`,[key,id]);
  requireValue(Number(size.bytes)<=32*1024*1024,'Reporting projected bucket exceeds 32 MiB');
  const {rows}=await client.query(sql,[key,id]);
  for(const {record} of rows){
   // PostgreSQL strip_nulls keeps optional fields absent, but these public
   // scan fields are explicitly nullable in the existing model.
   if(kind==='scans')record.completedAt??=null;
   accept(record);
  }
  await new Promise(resolve=>setImmediate(resolve));
 }
}
export async function buildCustomerReportingSections(source,target,companyId,createAccumulator,{beforeCommit,checkpoint,expectedFingerprint,deadlineMs=300000,mode,requireExecutive=false}={}){
 checkCompany(companyId);requireValue(typeof createAccumulator==='function','Reporting accumulator required');
 requireValue(Number.isInteger(deadlineMs)&&deadlineMs>0&&deadlineMs<=300000,'Invalid reporting build deadline');
 const sourceDb=await assertReportingStorage(source,false,mode),targetDb=await assertReportingStorage(target,true,mode);
 requireValue(mode==="published"||sourceDb!==targetDb,'Separate reporting target required');
 requireValue(source!==target,'Separate reporting connections required');
 const started=Date.now(),deadline=started+deadlineMs;let sourceOpen=false,targetOpen=false;
 try{
  await target.query('BEGIN');targetOpen=true;
  await target.query("SET LOCAL statement_timeout='15s';SET LOCAL search_path=public;SET LOCAL idle_in_transaction_session_timeout='330s';SET LOCAL lock_timeout='2s'");
  const {rows:[lock]}=await target.query('SELECT pg_try_advisory_xact_lock(hashtextextended($1,804259)) acquired',[companyId]);
  requireValue(lock.acquired,'Reporting customer build busy');
  await source.query('BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY');sourceOpen=true;
  await source.query("SET LOCAL statement_timeout='15s';SET LOCAL search_path=public;SET LOCAL idle_in_transaction_session_timeout='30s'");
  const asOf=(await source.query('SELECT clock_timestamp() AS value')).rows[0].value.toISOString();
  const owner=await company(source,companyId),proof=await manifest(source,companyId,asOf,mode);
  if(expectedFingerprint!==undefined&&proof.fingerprint!==expectedFingerprint)
   throw Object.assign(Error('Reporting source changed before build'),{code:'report-source-changed'});
  const acc=createAccumulator(owner,{now:Date.parse(asOf),policy:proof.policy});let records=0;
  for(const kind of ['scans','findings','assets'])await traverse(source,companyId,kind,record=>{
   if(proof.review)checkReportingRecordSources(proof.review,kind,record);
   if(kind==='findings'){records++;requireValue(records<=2000000,'Reporting finding limit exceeded');acc.finding(record);}
   else if(kind==='scans')acc.scan(record);else acc.asset(record);
  },deadline,checkpoint,proof.input?.buckets);
  const {rows:history}=await source.query(`SELECT ts,CASE WHEN octet_length(data::text)<=16384
    THEN data ELSE 'null'::jsonb END data,octet_length(data::text) bytes FROM vuln_metrics_history WHERE company_id=$1
    AND ts >= $2::timestamptz - interval '180 days' ORDER BY ts,id LIMIT 10001`,[companyId,asOf]);
  requireValue(history.length===proof.history.length&&history.every(r=>r.bytes<=16384),'Reporting history count or size mismatch');
  const output=acc.finish(history.map(r=>({ts:r.ts.toISOString(),data:r.data}))),json=JSON.stringify(output.model);
  requireValue(output.records===records&&Buffer.byteLength(json)<=MAX_BYTES,'Reporting result exceeds count or size bounds');
  const executive=output.executive===undefined?null:JSON.stringify(output.executive);
  requireValue(!requireExecutive||executive!==null,'Executive reporting accumulator required');
  if(executive!==null)requireValue(output.executive.company?.id===companyId&&Buffer.byteLength(executive)<=MAX_BYTES&&Number.isFinite(output.validUntil),'Invalid executive report bundle');
  const historyExpiry=history.length?new Date(history[0].ts).getTime()+180*86400000:Infinity;
  const expiresAt=new Date(Math.min(Date.parse(asOf)+15*60000,historyExpiry,output.validUntil??Infinity)).toISOString();
  requireValue(Date.parse(expiresAt)>Date.parse(asOf),'Reporting history window expired during build');
  const snapshotId=randomUUID();
  await target.query(`INSERT INTO customer_reporting_sections(company_id,format_version,snapshot_id,source_fingerprint,captured_at,expires_at,finding_count,model,model_hash)
   VALUES($1,1,$2,$3,$4,$5,$6,$7,$8) ON CONFLICT(company_id) DO UPDATE SET format_version=1,snapshot_id=EXCLUDED.snapshot_id,
   source_fingerprint=EXCLUDED.source_fingerprint,captured_at=EXCLUDED.captured_at,expires_at=EXCLUDED.expires_at,
   finding_count=EXCLUDED.finding_count,model=EXCLUDED.model,model_hash=EXCLUDED.model_hash,built_at=now()`,[companyId,snapshotId,proof.fingerprint,asOf,expiresAt,records,json,modelHash(JSON.parse(json))]);
  // Missing executive columns fail the whole transaction. No page/worker DDL.
  if(executive!==null)await target.query('UPDATE customer_reporting_sections SET executive=$2,executive_hash=$3 WHERE company_id=$1',
   [companyId,executive,modelHash(JSON.parse(executive))]);
  else {
   // A sections-only builder must never leave an executive result from another
   // generation attached. Compatible with the older sections-only schema.
   const {rows:[columns]}=await target.query("SELECT EXISTS(SELECT 1 FROM information_schema.columns WHERE table_schema='public' AND table_name='customer_reporting_sections' AND column_name='executive') ready");
   if(columns.ready)await target.query('UPDATE customer_reporting_sections SET executive=NULL,executive_hash=NULL WHERE company_id=$1',[companyId]);
  }
  await checkpoint?.();await beforeCommit?.(target);requireValue(Date.now()<deadline,'Reporting build deadline exceeded');
  await source.query('COMMIT');sourceOpen=false;await target.query('COMMIT');targetOpen=false;
  return {companyId,snapshotId,records,bucketsRead:(proof.input?.buckets??keys).filter(k=>/^(findings|scans|assets):/.test(k)).length,bytes:Buffer.byteLength(json),buildMs:Date.now()-started};
 }catch(error){if(sourceOpen)await source.query('ROLLBACK').catch(()=>{});if(targetOpen)await target.query('ROLLBACK').catch(()=>{});throw error;}
}
export async function inspectCustomerReportingInput(source,companyId,{mode}={}){
 checkCompany(companyId);await assertReportingStorage(source,false,mode);let begun=false;
 try{
  await source.query('BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY');begun=true;
  await source.query("SET LOCAL statement_timeout='5s';SET LOCAL search_path=public;SET LOCAL idle_in_transaction_session_timeout='15s'");
  await company(source,companyId);
  const asOf=(await source.query('SELECT clock_timestamp() AS value')).rows[0].value.toISOString();
  const result=await manifest(source,companyId,asOf,mode);
  await source.query('COMMIT');begun=false;return {fingerprint:result.fingerprint};
 }catch(error){if(begun)await source.query('ROLLBACK').catch(()=>{});throw error;}
}
/**
 * @param {any} source
 * @param {any} target
 * @param {string} companyId
 * @param {{mode?:string,expectedReviewRevision?:number,requireExecutive?:boolean}} [options]
 */
export async function readCustomerReportingSections(source,target,companyId,{mode,expectedReviewRevision,requireExecutive=false}={}){
 checkCompany(companyId);
 // Production use requires explicit migration, published revisions and opt-in routing.
 await assertReportingStorage(source,false,mode);await assertReportingStorage(target,true,mode);
 requireValue(source!==target,'Separate reporting connections required');
 let begun=false,targetBegun=false;
 try{
  await source.query('BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY');begun=true;
  await source.query("SET LOCAL statement_timeout='5s';SET LOCAL search_path=public;SET LOCAL idle_in_transaction_session_timeout='15s'");
  await target.query('BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY');targetBegun=true;
  await target.query("SET LOCAL statement_timeout='5s';SET LOCAL lock_timeout='2s';SET LOCAL search_path=public;SET LOCAL idle_in_transaction_session_timeout='15s'");
  const owner=await company(source,companyId);
  // Return only small derived output. A broken or oversized stored object must
  // never be loaded into a page response and represented as a partial result.
  const {rows:[saved]}=await target.query(`SELECT format_version,snapshot_id,source_fingerprint,model_hash,captured_at,expires_at,finding_count,built_at,
    octet_length(model::text) bytes,CASE WHEN octet_length(model::text)<=$2 THEN model END model,
    CASE WHEN $3 AND octet_length((to_jsonb(r)->'executive')::text)<=$2 THEN to_jsonb(r)->'executive' END executive,
    CASE WHEN $3 THEN to_jsonb(r)->>'executive_hash' END executive_hash
    FROM customer_reporting_sections r WHERE company_id=$1`,[companyId,MAX_BYTES,requireExecutive]);
  /** @type {{state:string,companyId:string,scope?:string,snapshotId?:string,capturedAt?:string,builtAt?:string,records?:number,model?:import('../reporting-customer-model').CustomerReportingModel,executive?:import('../executive-report').ExecReport}} */
  let response={state:'not-ready',companyId};
  if(saved){
   requireValue(saved.format_version===1&&saved.model?.company?.id===companyId&&typeof saved.model.company.name==='string'&&
    saved.bytes<=MAX_BYTES&&Number.isInteger(saved.finding_count)&&saved.finding_count>=0&&modelHash(saved.model)===saved.model_hash,'Invalid saved reporting sections');
   const proof=await manifest(source,companyId,saved.captured_at.toISOString(),mode);
   requireValue(mode!=="published"||proof.review.revision===expectedReviewRevision,"Customer source review changed during reporting read");
   const now=Date.now(),captured=saved.captured_at.getTime();
   if(requireExecutive&&saved.executive)requireValue(saved.executive.company?.id===companyId&&modelHash(saved.executive)===saved.executive_hash,'Invalid saved executive report');
   if(proof.fingerprint!==saved.source_fingerprint||saved.model.company.name!==owner.name||saved.expires_at.getTime()<=now||captured>now+60000||requireExecutive&&!saved.executive)
    response={state:'stale',companyId};
   else response={state:'available',companyId,scope:'saved-platform-report-sections',snapshotId:saved.snapshot_id,
    capturedAt:saved.captured_at.toISOString(),builtAt:saved.built_at.toISOString(),records:saved.finding_count,model:saved.model,
    ...(requireExecutive?{executive:saved.executive}:{})};
  }
  await source.query('COMMIT');begun=false;await target.query('COMMIT');targetBegun=false;return response;
 }catch(error){if(begun)await source.query('ROLLBACK').catch(()=>{});if(targetBegun)await target.query('ROLLBACK').catch(()=>{});throw error;}
}
