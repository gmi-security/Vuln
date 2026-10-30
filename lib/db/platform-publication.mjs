import {createHash,randomUUID} from 'node:crypto';
import {bindPlatformWriter,readPlatformAuthority,samePlatformAuthority} from './platform-authority.mjs';
import {platformCollections,platformColumnTypes,platformRecord,upsertPlatformRecords,validFindingGeneration} from './platform-records.mjs';
import {collectSqlReportingTargets,computeSqlReportingChanges} from './customer-reporting-revisions.mjs';
import {trackPublicationClient} from './publication-client.mjs';

const check=(ok,message)=>{if(!ok)throw Error(message);};
const pause=()=>new Promise(resolve=>setImmediate(resolve));
const columns=Object.keys(platformRecord('findings',['shape',{id:'shape'}],0));
const compare=(a,b)=>a<b?-1:a>b?1:0;
const digest=values=>{const h=createHash('sha256');for(const value of values)h.update(JSON.stringify(value)+'\n');return h.digest('hex');};
const LOCK=804280;

// Called under the publication lock, before allocating the next generation.
// Retain the active data and this exact resumable plan only. Deletion advances
// in short transactions; a crash simply leaves another bounded batch to clean.
async function reclaimObsolete(client,plan,keep,guard,checkpoint){
 const obsolete=(await client.query(`SELECT p.id FROM app_finding_publications p WHERE p.id<>$1 AND p.id<>$2
  AND (p.phase<>'discarded' OR EXISTS(SELECT 1 FROM app_finding_versions f WHERE f.generation=p.id))`,[plan.findingGeneration,keep])).rows;
 for(const {id}of obsolete){
  for(;;){
   const n=await transaction(client,plan.authority,async()=>{
    guard();check(await readFindingGeneration(client)===plan.findingGeneration,'Active finding generation changed');
    await client.query("UPDATE app_finding_publications SET phase='discarded',plan_hash=NULL,updated_at=clock_timestamp() WHERE id=$1",[id]);
    return (await client.query(`DELETE FROM app_finding_versions WHERE generation=$1 AND id IN
     (SELECT id FROM app_finding_versions WHERE generation=$1 ORDER BY id LIMIT 10000)`,[id])).rowCount;
   });
   await checkpoint({phase:'cleanup',id,deleted:n});await pause();
   if(n<10000)break;
  }
 }
}

export async function readFindingGeneration(client){
 if(!(await client.query("SELECT to_regclass('public.app_finding_head')::text relation")).rows[0]?.relation)return null;
 const generation=(await client.query('SELECT generation::text FROM app_finding_head WHERE id=1')).rows[0]?.generation;
 check(validFindingGeneration(generation),'Invalid active finding generation');return generation;
}
export function publicationIdentity(plan){
 check(validFindingGeneration(plan.findingGeneration),'Finding generation schema is required for large publication');
 const writes=[...(plan.writes.get('findings')??[])].sort((a,b)=>compare(a.id,b.id));
 const deleted=[...(plan.deletes.get('findings')??[])].sort(compare);
 const planHash=digest((function*(){yield plan.authority;yield plan.findingGeneration;for(const r of writes)yield [r.id,r.record_hash,r.store_order,r.store_bucket];yield deleted;})());
 const reportHash=digest([planHash,plan.metaHash,plan.changedKeys,...[...plan.writes].filter(([kind])=>kind!=='findings').map(([kind,rows])=>
  [kind,rows.map(r=>[r.id,r.record_hash,r.store_order,r.store_bucket]).sort((a,b)=>compare(a[0],b[0])),plan.deletes.get(kind)])]);
 return {writes,deleted,planHash,reportHash};
}
async function transaction(client,expected,fn){
 await client.query("BEGIN; SET LOCAL statement_timeout='60s'; SET LOCAL lock_timeout='5s'; SET LOCAL idle_in_transaction_session_timeout='90s'");
 try{await bindPlatformWriter(client,expected);const value=await fn();await client.query('COMMIT');return value;}
 catch(error){await client.query('ROLLBACK').catch(()=>{});throw error;}
}
const fields=kind=>Object.keys(platformRecord(kind,['shape',{id:'shape'}],0));
// Only read queries enter this wrapper. Non-finding changes are frozen SQL
// overlays; the original generation remains untouched until the final commit.
export function publicationPreview(client,plan,generation){
 check(generation==null||validFindingGeneration(generation),'Invalid preview generation');
 return {query:async(sql,params=[])=>{
  check(/^SELECT\b/.test(sql),'Publication preview accepts reads only');
  for(const [kind,config]of Object.entries(platformCollections)){
   const needle=new RegExp(`\\bFROM ${config.table}\\b`,'g');if(!needle.test(sql))continue;
   if(kind==='findings'&&generation)return client.query(sql.replace(needle,`FROM (SELECT ${columns.join(',')} FROM app_finding_versions WHERE generation=$${params.length+1}::uuid) AS publication_findings`),[...params,generation]);
   const writes=plan.writes.get(kind)??[],deleted=plan.deletes.get(kind)??[];
   if(!writes.length&&!deleted.length)continue;
   const names=fields(kind),removed=[...writes.map(r=>r.id),...deleted],a=params.length+1,b=a+1;
   const cte=`WITH publication_rows AS (SELECT ${names.join(',')} FROM ${config.table} WHERE NOT(id=ANY($${a}::text[])) UNION ALL SELECT ${names.join(',')} FROM jsonb_to_recordset($${b}::jsonb) AS replacement(${names.map(k=>`${k} ${platformColumnTypes[k]}`).join(',')})) `;
   return client.query(cte+sql.replace(needle,'FROM publication_rows'),[...params,removed,JSON.stringify(writes)]);
  }
  return client.query(sql,params);
 }};
}
export async function preparePlatformReporting(pool,plan){
 const client=await pool.connect(),owner=trackPublicationClient(client);let broken;
 try{
  await client.query("BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY; SET LOCAL statement_timeout='60s'; SET LOCAL idle_in_transaction_session_timeout='90s'");
  if(!samePlatformAuthority(await readPlatformAuthority(client),plan.authority))throw Object.assign(Error('Platform authority changed; reload before reporting'),{code:'platform-writer-stale'});
  const targets=await collectSqlReportingTargets(client,plan);
  const digests=await computeSqlReportingChanges(publicationPreview(client,plan),plan.changedKeys,targets,plan);
  await client.query('COMMIT');return digests;
 }catch(error){broken=owner.firstError()??error;throw broken;}
 finally{owner.release(broken);}
}

/** Private batches commit independently. Only publishFindingGeneration changes visible data.
 * @param {any} pool
 * @param {any} plan
 * @param {{guard?:()=>void,checkpoint?:(progress:any)=>any}} options
 */
export async function prepareFindingPublication(pool,plan,{guard=()=>{},checkpoint=()=>{}}={}){
 const identity=publicationIdentity(plan),{writes,deleted,planHash,reportHash}=identity;
 const client=await pool.connect(),owner=trackPublicationClient(client);let locked=false,broken;
 try{
  locked=(await client.query('SELECT pg_try_advisory_lock($1) acquired',[LOCK])).rows[0]?.acquired;
  if(!locked)throw Object.assign(Error('Another finding publication is running'),{code:'55P03'});
  await client.query("SET statement_timeout='60s'; SET lock_timeout='5s'");
  let row=await transaction(client,plan.authority,async()=>{
   guard();check(await readFindingGeneration(client)===plan.findingGeneration,'Active finding generation changed');
   await client.query(`INSERT INTO app_finding_publications(id,base_generation,base_epoch,base_revision,plan_hash,report_plan_hash,phase)
    VALUES($1,$2,$3,$4,$5,$6,'writing') ON CONFLICT(plan_hash) DO NOTHING`,
    [randomUUID(),plan.findingGeneration,plan.authority.epoch,plan.authority.revision,planHash,reportHash]);
   return (await client.query('SELECT * FROM app_finding_publications WHERE plan_hash=$1',[planHash])).rows[0];
  });
  check(row&&row.base_generation===plan.findingGeneration&&String(row.base_epoch)===plan.authority.epoch&&String(row.base_revision)===plan.authority.revision,'Publication checkpoint has a different base');
  check(!['published','discarded'].includes(row.phase),'Publication is no longer pending');
  await reclaimObsolete(client,plan,row.id,guard,checkpoint);
  const update=async(sql,params=[])=>transaction(client,plan.authority,async()=>{
   guard();const r=await client.query(sql,params);return r.rows[0];
  });
  const step=async(phase,fn)=>{
   row=await transaction(client,plan.authority,async()=>{guard();return fn();});
   await checkpoint({phase,id:row.id,writeOffset:row.write_offset,copyAfter:row.copy_after});await pause();
  };
  check(row.write_offset<=writes.length&&row.delete_offset<=deleted.length,'Publication checkpoint exceeds the frozen plan');
  check(row.phase==='writing'||row.write_offset===writes.length,'Incomplete upload checkpoint');
  check(['writing','copying','deleting'].includes(row.phase)||row.delete_offset===deleted.length,'Incomplete deletion checkpoint');
  while(row.phase==='writing'){
   const end=Math.min(row.write_offset+500,writes.length),batch=writes.slice(row.write_offset,end);
   await step('writing',async()=>{
    await upsertPlatformRecords(client,'findings',batch,{generation:row.id});
    return (await client.query(`UPDATE app_finding_publications SET write_offset=$2,phase=$3,updated_at=clock_timestamp() WHERE id=$1 RETURNING *`,[row.id,end,end===writes.length?'copying':'writing'])).rows[0];
   });
  }
  while(row.phase==='copying'){
   await step('copying',async()=>{
    const copied=(await client.query(`WITH page AS MATERIALIZED (
      SELECT ${columns.join(',')} FROM app_finding_versions WHERE generation=$1 AND ($2::text IS NULL OR id>$2) ORDER BY id LIMIT 2000
     ), inserted AS (INSERT INTO app_finding_versions(generation,${columns.join(',')})
      SELECT $3::uuid,${columns.join(',')} FROM page ON CONFLICT(generation,id) DO NOTHING RETURNING id)
     SELECT (SELECT max(id) FROM page) last,(SELECT count(*)::int FROM page) count`,[row.base_generation,row.copy_after,row.id])).rows[0];
    return (await client.query(`UPDATE app_finding_publications SET copy_after=COALESCE($2,copy_after),phase=$3,updated_at=clock_timestamp() WHERE id=$1 RETURNING *`,
     [row.id,copied.last,copied.count<2000?'deleting':'copying'])).rows[0];
   });
  }
  while(row.phase==='deleting'){
   const end=Math.min(row.delete_offset+500,deleted.length);
   await step('deleting',async()=>{
    if(end>row.delete_offset)await client.query('DELETE FROM app_finding_versions WHERE generation=$1 AND id=ANY($2::text[])',[row.id,deleted.slice(row.delete_offset,end)]);
    return (await client.query(`UPDATE app_finding_publications SET delete_offset=$2,phase=$3,updated_at=clock_timestamp() WHERE id=$1 RETURNING *`,[row.id,end,end===deleted.length?'reporting':'deleting'])).rows[0];
   });
  }
  if(row.report_plan_hash!==reportHash){
   row=await update(`UPDATE app_finding_publications SET report_plan_hash=$2,phase='reporting',report_progress='{}',report_digests=NULL WHERE id=$1 RETURNING *`,[row.id,reportHash]);
  }
  if(row.phase==='reporting'){
   const count=Number((await client.query('SELECT count(*)::text n FROM app_finding_versions WHERE generation=$1',[row.id])).rows[0].n);
   check(count===plan.index.get('findings').size,'Staged finding count differs from the frozen generation');
   // Ownership changes must include the old customer, before previewing replacements.
   const targets=await collectSqlReportingTargets(client,plan);
   const reports=await computeSqlReportingChanges(publicationPreview(client,plan,row.id),plan.changedKeys,targets,plan,{
    completed:row.report_progress,
    checkpoint:async(key,pieces)=>{
     row=await update(`UPDATE app_finding_publications SET report_progress=jsonb_set(report_progress,ARRAY[$2::text],$3::jsonb),updated_at=clock_timestamp() WHERE id=$1 RETURNING *`,[row.id,key,JSON.stringify(pieces)]);
     await checkpoint({phase:'reporting',id:row.id,bucket:key});
    },
   });
   row=await update(`UPDATE app_finding_publications SET phase='ready',record_count=$2,report_digests=$3,updated_at=clock_timestamp() WHERE id=$1 RETURNING *`,[row.id,count,JSON.stringify(reports)]);
  }
  check(row.phase==='ready'&&row.report_plan_hash===reportHash&&Array.isArray(row.report_digests),'Publication is incomplete');
  return {...row,record_count:Number(row.record_count)};
 }catch(error){broken=owner.firstError()??error;throw broken;}
 finally{
  if(locked)await client.query('SELECT pg_advisory_unlock($1)',[LOCK]).catch(()=>{});
  if(!broken)await client.query('RESET statement_timeout; RESET lock_timeout').catch(error=>{broken=error;});
  owner.release(broken);
 }
}
export async function publishFindingGeneration(client,plan,publication){
 const {planHash,reportHash}=publicationIdentity(plan);
 const row=(await client.query('SELECT * FROM app_finding_publications WHERE id=$1 FOR UPDATE',[publication.id])).rows[0];
 check(row?.phase==='ready'&&row.plan_hash===planHash&&row.report_plan_hash===reportHash&&Number(row.record_count)===plan.index.get('findings').size&&
  JSON.stringify(row.report_digests)===JSON.stringify(publication.report_digests),'Finding publication is incomplete or changed');
 check(await readFindingGeneration(client)===plan.findingGeneration,'Active finding generation changed');
 await client.query('UPDATE app_finding_head SET generation=$1 WHERE id=1',[row.id]);
 await client.query("UPDATE app_finding_publications SET phase='published',updated_at=clock_timestamp() WHERE id=$1",[row.id]);
 return row.id;
}
