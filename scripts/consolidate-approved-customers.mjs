// Explicit private-clone rehearsal only. No dotenv or DATABASE_URL fallback.
// See docs/customer-consolidation-runbook.md before using this command.
import {readFile} from 'node:fs/promises';
import {createHash,randomUUID} from 'node:crypto';
import {pathToFileURL} from 'node:url';
import pg from 'pg';
import {platformBucketKeys} from '../lib/db/platform-store.mjs';
import {platformJson} from '../lib/db/platform-records.mjs';
import {readPlatformAuthority,bindPlatformWriter} from '../lib/db/platform-authority.mjs';
import {planCustomerConsolidation} from '../lib/db/customer-consolidation.mjs';

const fail=message=>{throw Error(message);};
const approved=[
 {sourceId:'CO-9150',sourceName:'GMI Scans',destinationId:'CO-229336',destinationName:'Global Market Innovators, Inc.'},
 {sourceId:'CO-9153',sourceName:'Valor Global Scans',destinationId:'CO-229438',destinationName:'Valor Global, LLC'},
];
const cloneTarget={database:'recovery_merge',port:55483,
 socket:'/home/codex/vuln-recovery/merge-rehearsal-26PA6Y/restore-vR3gUb/socket'};
const same=(a,b)=>JSON.stringify(a)===JSON.stringify(b);
const assert=(condition,message)=>{if(!condition)fail(message);};
function argumentsFor(argv){
 const [mode,...rest]=argv;
 assert(['--inspect','--dry-run','--commit'].includes(mode),'Choose --inspect, --dry-run or --commit.');
 const args={};for(let i=0;i<rest.length;i+=2){
  assert(rest[i]?.startsWith('--')&&rest[i+1]&&!args[rest[i]],'Invalid or duplicate argument.');args[rest[i]]=rest[i+1];
 }
 const allowed=['--socket','--database','--port','--user','--manifest','--expect-plan-hash'];
 assert(Object.keys(args).every(key=>allowed.includes(key)),'Unknown argument.');
 assert(args['--socket']===cloneTarget.socket&&args['--database']===cloneTarget.database&&
  args['--port']===String(cloneTarget.port),'Target must be the named private recovery_merge clone.');
 assert(typeof args['--user']==='string'&&/^[A-Za-z_][A-Za-z0-9_]{0,62}$/.test(args['--user']),'Explicit database user required.');
 if(mode!=='--inspect')assert(args['--manifest'],'Manifest required.');
 if(mode==='--commit')assert(args['--expect-plan-hash']?.match(/^[a-f0-9]{64}$/),'Reviewed plan hash required for commit.');
 return {mode,args};
}
const digest=snapshot=>{
 const hash=createHash('sha256');for(const [key,value] of [...snapshot].sort(([a],[b])=>a.localeCompare(b))){
  hash.update(key);hash.update('\0');hash.update(platformJson(value));hash.update('\n');
 }return hash.digest('hex');
};
const rows=(snapshot,kind)=>[...snapshot].filter(([key])=>key.startsWith(`${kind}:`)).flatMap(([,values])=>values);
function coreCounts(snapshot){
 const result={};for(const pair of approved){
  const counts={};for(const kind of ['folders','scans','findings','assets'])counts[kind]=rows(snapshot,kind).filter(([,v])=>v.companyId===pair.sourceId).length;
  const destination={};for(const kind of ['folders','scans','findings','assets'])destination[kind]=rows(snapshot,kind).filter(([,v])=>v.companyId===pair.destinationId).length;
  result[pair.sourceId]={source:counts,destination};
 }return result;
}
function internalFolderEvidence(snapshot){
 const expected=[{folderId:'FLD-9152',companyId:'CO-9150',scans:71},
  {folderId:'FLD-9155',companyId:'CO-9153',scans:67}];
 const folders=new Map(rows(snapshot,'folders'));
 return expected.map(item=>({folderId:item.folderId,companyId:folders.get(item.folderId)?.companyId??null,
  scans:rows(snapshot,'scans').filter(([,scan])=>scan.folderId===item.folderId).length}));
}
function verifiedExternalIdentities(verification){
 if(!Array.isArray(verification)||verification.length!==2)return false;
 return approved.every(pair=>{
  const row=verification.find(value=>value?.destinationId===pair.destinationId);
  const cw=row?.connectwise,nessus=row?.nessus;
  return Number.isSafeInteger(cw?.numericId)&&cw.numericId>0&&cw.name===pair.destinationName&&
   cw.observedVia==='GET /company/companies'&&/^[a-f0-9]{64}$/.test(cw.evidenceSha256)&&
   Number.isSafeInteger(nessus?.numericFolderId)&&nessus.numericFolderId>0&&
   nessus.name===pair.sourceName&&nessus.observedVia==='GET /folders'&&
   /^[a-f0-9]{64}$/.test(nessus.evidenceSha256);
 })&&new Set(verification.map(row=>row.nessus.numericFolderId)).size===2&&
  new Set(verification.map(row=>row.connectwise.numericId)).size===2;
}
function validateManifest(mode,manifest){
 assert(manifest?.version===1&&same(manifest.mappings,approved)&&
  manifest.expected&&typeof manifest.expected==='object'&&!Array.isArray(manifest.expected),
  'Manifest mappings or expected snapshot are invalid.');
 if(mode==='--commit')assert(verifiedExternalIdentities(manifest.externalVerification),
  'Independent ConnectWise company and Nessus folder ID evidence is required before commit.');
}
async function ancillary(client){
 for(const name of ['vuln_metrics_history','patch_group_ticket_requests','patch_group_ticket_audit'])
  assert((await client.query('SELECT to_regclass($1)::text relation',[`public.${name}`])).rows[0]?.relation,`Missing ${name} table.`);
 const metrics={};for(const pair of approved){
  metrics[pair.sourceId]=Number((await client.query('SELECT count(*)::text n FROM vuln_metrics_history WHERE company_id=$1',[pair.sourceId])).rows[0].n);
  metrics[pair.destinationId]=Number((await client.query('SELECT count(*)::text n FROM vuln_metrics_history WHERE company_id=$1',[pair.destinationId])).rows[0].n);
 }
 const drafts=Number((await client.query(`SELECT count(*)::text n FROM patch_group_ticket_requests
  WHERE tenant_id='CO-9150' AND packet->>'appCompanyId'='CO-9150' AND packet->>'source'='stored-findings'
  AND state='prepared' AND review_state='pending' AND ticket_id IS NULL`)).rows[0].n);
 const sourceDrafts=Number((await client.query(`SELECT count(*)::text n FROM patch_group_ticket_requests
  WHERE tenant_id IN ('CO-9150','CO-9153') OR packet->>'appCompanyId' IN ('CO-9150','CO-9153')`)).rows[0].n);
 const manualOnlyDrafts=Number((await client.query(`SELECT count(*)::text n FROM patch_group_ticket_requests
  WHERE tenant_id='CO-9150' AND packet->>'appCompanyId'='CO-9150' AND packet->>'source'='stored-findings'
  AND state='prepared' AND review_state='pending' AND ticket_id IS NULL
  AND packet->>'manualOnly'='true'`)).rows[0].n);
 const metricRows=(await client.query(`SELECT id::text,ts::text,company_id,data FROM vuln_metrics_history
  WHERE company_id=ANY($1::text[]) ORDER BY id`,
  [approved.flatMap(pair=>[pair.sourceId,pair.destinationId])])).rows;
 const metricsSha256=createHash('sha256').update(platformJson(metricRows)).digest('hex');
 return {metrics,metricsSha256,drafts,sourceDrafts,manualOnlyDrafts};
}
async function loadSnapshot(client){
 const records=(await client.query('SELECT key,data FROM public.vuln_store ORDER BY key')).rows;
 assert(same(records.map(r=>r.key),[...platformBucketKeys,'meta'].sort()),'Legacy store key set or schema differs.');
 const snapshot=new Map(records.map(({key,data})=>[key,data]));
 for(const [key,value] of snapshot)assert(key==='meta'?value&&typeof value==='object'&&!Array.isArray(value):Array.isArray(value),`Invalid ${key} bucket.`);
 return snapshot;
}
async function unknownReferences(client){
 // Historical audit and frozen backup tables are retained as original evidence.
 const excluded=new Set(['vuln_store','vuln_snapshot','vuln_metrics_history','patch_group_ticket_requests',
  'patch_group_ticket_audit','customer_consolidation_runs','app_companies','app_folders','app_scans',
  'app_findings','app_assets','app_store_metadata','app_store_authority','app_store_commits']);
 const tables=(await client.query(`SELECT DISTINCT table_name FROM information_schema.columns
  WHERE table_schema='public' AND data_type IN ('text','character varying','json','jsonb') ORDER BY table_name`)).rows;
 const hits=[];
 for(const {table_name:table} of tables){
  if(excluded.has(table))continue;
  const quote=value=>'"'+value.replaceAll('"','""')+'"';
  const count=Number((await client.query(`SELECT count(*)::text n FROM public.${quote(table)} AS t
   WHERE row_to_json(t)::text LIKE ANY($1::text[])`,
   [approved.map(pair=>`%${pair.sourceId}%`)])).rows[0].n);
  if(count)hits.push({table,count});
 }
 return hits;
}
export {argumentsFor,coreCounts,digest,verifiedExternalIdentities,internalFolderEvidence,validateManifest};

if(process.argv[1]&&import.meta.url===pathToFileURL(process.argv[1]).href){
 const {mode,args}=argumentsFor(process.argv.slice(2));
 const manifest=mode==='--inspect'?null:JSON.parse(await readFile(args['--manifest'],'utf8'));
 if(manifest)validateManifest(mode,manifest);
 const client=new pg.Client({host:args['--socket'],database:args['--database'],port:Number(args['--port']),
  user:args['--user'],ssl:false,application_name:'vuln2-private-customer-consolidation',connectionTimeoutMillis:15000});
 let transaction=false;
 try{
  await client.connect();await client.query('BEGIN ISOLATION LEVEL SERIALIZABLE');transaction=true;
  await client.query("SET LOCAL search_path=public;SET LOCAL lock_timeout='5s';SET LOCAL idle_in_transaction_session_timeout='1800s'");
  await client.query('SELECT pg_advisory_xact_lock(804209)');
  const identity=(await client.query(`SELECT current_database() database,current_setting('server_version_num') version,
   current_setting('unix_socket_directories') sockets,inet_server_addr() server_address`)).rows[0];
  assert(identity.database===cloneTarget.database&&identity.server_address===null&&
   identity.sockets.split(',').map(v=>v.trim()).includes(cloneTarget.socket),'Connected to an unexpected database server.');
  const peers=Number((await client.query(`SELECT count(*)::text n FROM pg_stat_activity
   WHERE datname=current_database() AND pid<>pg_backend_pid()`)).rows[0].n);
  assert(peers===0,'Other database sessions remain; stop all writers and retry.');
  const authority=await readPlatformAuthority(client,{lock:true});
  if(mode!=='--inspect')assert(authority?.mode==='legacy'&&authority.enforced===true,
   'Expected fenced legacy authority on the isolated clone.');
  await client.query('LOCK TABLE public.vuln_store IN SHARE ROW EXCLUSIVE MODE');
  await client.query('LOCK TABLE public.vuln_metrics_history, public.patch_group_ticket_requests IN SHARE ROW EXCLUSIVE MODE');
  const snapshot=await loadSnapshot(client),beforeHash=digest(snapshot),counts=coreCounts(snapshot),extra=await ancillary(client);
  const aliases=snapshot.get('meta')?.identityAliases??[];
  const aliasesToMove=aliases.filter(([from])=>approved.some(pair=>from.startsWith(`${pair.sourceId}::`))).length;
  const observed={identity:{database:identity.database,version:identity.version},authority,
   snapshotSha256:beforeHash,counts,metrics:extra.metrics,metricsSha256:extra.metricsSha256,
   drafts:extra.drafts,sourceDrafts:extra.sourceDrafts,
   manualOnlyDrafts:extra.manualOnlyDrafts,
   aliasesToMove,internalFolders:internalFolderEvidence(snapshot)};
  if(mode==='--inspect'){
   console.log(JSON.stringify({mode:'inspect',observed}));await client.query('ROLLBACK');transaction=false;
  }else{
   assert(same(manifest.expected,observed),'Observed snapshot, schema, counts, or authority drifted from manifest.');
   assert(extra.drafts===39353&&extra.sourceDrafts===39353&&aliasesToMove===55,
    'Historical draft or alias reconciliation baseline changed.');
   assert(counts['CO-9150'].source.findings+counts['CO-9153'].source.findings===106256&&
    counts['CO-9150'].source.scans+counts['CO-9153'].source.scans===206,
    'Finding or scan reconciliation baseline changed.');
   assert(counts['CO-9150'].source.findings===102695&&counts['CO-9153'].source.findings===3561&&
    counts['CO-9150'].source.scans===118&&counts['CO-9153'].source.scans===88,
    'Per-customer finding or scan baseline changed.');
   assert(same(observed.internalFolders,[{folderId:'FLD-9152',companyId:'CO-9150',scans:71},
    {folderId:'FLD-9155',companyId:'CO-9153',scans:67}]),'Internal Nessus folder ownership changed.');
   assert(Object.values(extra.metrics).reduce((a,b)=>a+b,0)===104,'Historical metrics baseline changed.');
   const plan=planCustomerConsolidation(snapshot,approved),afterHash=digest(plan.buckets);
   assert(plan.report.assetCollisions===93,'Overlapping asset count changed.');
   const folderCollisions=plan.lineage.folders.filter(row=>row.source.id!==row.destinationId);
   assert(folderCollisions.length===2&&folderCollisions.every(row=>row.source.name.trim().toLowerCase()==='general')&&
    approved.every(pair=>folderCollisions.some(row=>row.source.companyId===pair.sourceId)),
    'The two reviewed General folder collisions changed.');
   const unknown=await unknownReferences(client);
   assert(unknown.length===0,`Unreviewed SQL customer references: ${JSON.stringify(unknown)}`);
   const planHash=createHash('sha256').update(platformJson({beforeHash,afterHash,counts,
    lineage:plan.lineage,metrics:extra.metrics,metricsSha256:extra.metricsSha256,drafts:extra.drafts,
    externalVerification:manifest.externalVerification??null})).digest('hex');
   if(mode==='--commit')assert(planHash===args['--expect-plan-hash'],'Plan hash differs from operator-reviewed plan.');
   const report={mode:mode==='--commit'?'committed':'dry-run',before:observed,
    after:{snapshotSha256:afterHash,counts:coreCounts(plan.buckets),metrics:extra.metrics,
     metricsSha256:extra.metricsSha256,draftsQuarantined:extra.drafts,draftAuditRowsAdded:extra.drafts},
    planHash,externalIdentitiesVerified:verifiedExternalIdentities(manifest.externalVerification),
    assetCollisions:plan.report.assetCollisions,folderMappings:plan.lineage.folders,
    sourceAssetsArchived:plan.lineage.assets.length,orphans:plan.report.orphans};
   if(mode==='--dry-run'){
    console.log(JSON.stringify(report));await client.query('ROLLBACK');transaction=false;
   }else{
    await bindPlatformWriter(client,authority);
    await client.query(`CREATE TABLE IF NOT EXISTS customer_consolidation_runs (
     id text PRIMARY KEY, before_hash text NOT NULL, after_hash text NOT NULL,
     plan_hash text NOT NULL, lineage jsonb NOT NULL, report jsonb NOT NULL,
     created_at timestamptz NOT NULL DEFAULT clock_timestamp())`);
    assert(!(await client.query("SELECT 1 FROM customer_consolidation_runs WHERE id='gmi-valor-v1'")).rowCount,
     'Customer consolidation was already applied.');
    await client.query(`INSERT INTO customer_consolidation_runs(id,before_hash,after_hash,plan_hash,lineage,report)
      VALUES('gmi-valor-v1',$1,$2,$3,$4,$5)`,
     [beforeHash,afterHash,planHash,JSON.stringify(plan.lineage),JSON.stringify(report)]);
    for(const [key,data] of plan.buckets){
     if(platformJson(snapshot.get(key))===platformJson(data))continue;
     const result=await client.query('UPDATE vuln_store SET data=$2,updated_at=clock_timestamp() WHERE key=$1',[key,JSON.stringify(data)]);
     assert(result.rowCount===1,`Store bucket ${key} disappeared.`);
    }
    const held=await client.query(`UPDATE patch_group_ticket_requests
      SET packet=jsonb_set(packet,'{manualOnly}','true'::jsonb,true),updated_at=clock_timestamp()
      WHERE tenant_id='CO-9150' AND packet->>'appCompanyId'='CO-9150' AND packet->>'source'='stored-findings'
       AND state='prepared' AND review_state='pending' AND ticket_id IS NULL`);
    assert(held.rowCount===39353,'Draft quarantine count drifted.');
    const audited=await client.query(`INSERT INTO patch_group_ticket_audit(request_id,actor,action)
      SELECT id,'customer-consolidation','group.manual-only' FROM patch_group_ticket_requests
      WHERE tenant_id='CO-9150' AND packet->>'appCompanyId'='CO-9150' AND packet->>'source'='stored-findings'
       AND state='prepared' AND review_state='pending' AND ticket_id IS NULL AND packet->>'manualOnly'='true'`);
    assert(audited.rowCount===39353,'Draft quarantine audit count drifted.');
    const stored=await loadSnapshot(client);
    assert(digest(stored)===afterHash,'Stored snapshot verification failed.');
    const post=await ancillary(client);
    assert(post.drafts===39353&&post.manualOnlyDrafts===39353&&same(post.metrics,extra.metrics)&&
     post.metricsSha256===extra.metricsSha256,
     'Ticket hold or metrics provenance changed.');
    const nextAuthority=(await client.query(`UPDATE app_store_authority SET revision=revision+1,updated_at=clock_timestamp()
      WHERE id=1 RETURNING epoch::text,revision::text`)).rows[0];
    await client.query(`INSERT INTO app_store_commits(id,epoch,revision,operation,actor,counts)
      VALUES($1,$2,$3,'save','private-customer-consolidation',$4)`,
     [randomUUID(),nextAuthority.epoch,nextAuthority.revision,JSON.stringify({customers:2,scans:206,findings:106256,assetCollisions:93,draftsQuarantined:39353})]);
    await client.query('COMMIT');transaction=false;console.log(JSON.stringify(report));
   }
  }
 }finally{if(transaction)await client.query('ROLLBACK').catch(()=>{});await client.end();}
}
