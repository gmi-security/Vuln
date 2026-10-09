// Disposable publication prototype. No active application pointer or production caller.
import {shadowReadRequest,validShadowSummary,readDefenderShadow} from './defender-shadow-reads.mjs';
import {readDefenderShadowCve} from './defender-shadow-cve.mjs';
const fail=(message,status=409)=>{throw Object.assign(new Error(message),{status});};
const validCompany=id=>typeof id==='string'&&/^CO-[A-Za-z0-9-]{1,120}$/.test(id);
export function shadowPublicationRequest(request){
  const {companyId,projectionId}=shadowReadRequest({companyId:request.companyId,projectionId:request.projectionId});
  const {expectedRevision,actor,reason}=request;
  if(!Number.isSafeInteger(expectedRevision)||expectedRevision<0||expectedRevision>=Number.MAX_SAFE_INTEGER||
    typeof actor!=='string'||!actor.trim()||actor.length>120||typeof reason!=='string'||!reason.trim()||reason.length>500)fail('Explicit publication revision, actor and reason required',400);
  return {companyId,projectionId,expectedRevision,actor,reason};
}
async function privateTarget(client){
  const {rows:[g]}=await client.query("SELECT current_database() db,current_setting('data_directory') dir,current_setting('listen_addresses') listen");
  if(!/^vuln2_shadow_test_[a-f0-9]+$/.test(g.db)||!g.dir.startsWith('/home/codex/vuln-recovery/')||g.listen)fail('Disposable shadow target required');
}
function revision(value){const n=Number(value);if(!Number.isSafeInteger(n)||n<1)fail('Invalid publication revision');return n;}
function complete(row){
  if(row?.state!=='verified'||row.reads_sealed!==true||row.model_version!==2||row.read_version!==1||row.finding_count!==row.saved_count||
    !validShadowSummary(row.summary,row.finding_count))fail('Complete verified generation and saved reads required');
}
const verified=`SELECT g.state,g.reads_sealed,g.model_version,g.finding_count,s.read_version,s.finding_count saved_count,s.summary
  FROM defender_shadow_generations g LEFT JOIN defender_shadow_read_summary s USING(company_id,projection_id)
  WHERE g.company_id=$1 AND g.projection_id=$2`;

export async function publishDefenderShadow(client,request,{beforeCommit}={}){
  const r=shadowPublicationRequest(request);await privateTarget(client);
  await client.query('BEGIN');
  try{
    await client.query("SET LOCAL statement_timeout='5s';SET LOCAL lock_timeout='2s';SET LOCAL idle_in_transaction_session_timeout='15s'");
    await client.query('SELECT pg_advisory_xact_lock(hashtextextended($1,804251))',[r.companyId]);
    const {rows:[current]}=await client.query('SELECT projection_id,revision FROM defender_shadow_publications WHERE company_id=$1 FOR UPDATE',[r.companyId]);
    const previous=current?revision(current.revision):0;
    if(previous!==r.expectedRevision)fail('Publication changed; read the current revision before retrying');
    complete((await client.query(verified,[r.companyId,r.projectionId])).rows[0]);
    if(current?.projection_id===r.projectionId){await client.query('COMMIT');return {companyId:r.companyId,projectionId:r.projectionId,revision:previous,changed:false};}
    const values=[r.companyId,r.projectionId,previous+1,r.actor,r.reason];
    const sql=current?`UPDATE defender_shadow_publications SET projection_id=$2,revision=$3,actor=$4,reason=$5 WHERE company_id=$1 RETURNING published_at`:
      `INSERT INTO defender_shadow_publications(company_id,projection_id,revision,actor,reason) VALUES($1,$2,$3,$4,$5) RETURNING published_at`;
    const {rows:[published]}=await client.query(sql,values);
    await beforeCommit?.();await client.query('COMMIT');
    return {companyId:r.companyId,projectionId:r.projectionId,revision:previous+1,publishedAt:published.published_at,changed:true};
  }catch(error){await client.query('ROLLBACK').catch(()=>{});throw error;}
}

export async function readDefenderPublication(client,companyId){
  if(!validCompany(companyId))fail('Explicit publication customer required',400);
  await client.query('BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY');
  try{
    await client.query("SET LOCAL statement_timeout='5s';SET LOCAL idle_in_transaction_session_timeout='15s'");
    const {rows:[row]}=await client.query(`SELECT p.projection_id,p.revision,p.published_at,g.state,g.reads_sealed,g.model_version,g.finding_count,
      s.read_version,s.finding_count saved_count,s.summary FROM defender_shadow_publications p
      JOIN defender_shadow_generations g USING(company_id,projection_id)
      LEFT JOIN defender_shadow_read_summary s USING(company_id,projection_id) WHERE p.company_id=$1`,[companyId]);
    if(!row){await client.query('COMMIT');return {state:'unpublished',companyId,scope:'published-defender-cohort'};}
    complete(row);const value={state:'published',companyId,projectionId:row.projection_id,revision:revision(row.revision),publishedAt:row.published_at};
    await client.query('COMMIT');return value;
  }catch(error){await client.query('ROLLBACK').catch(()=>{});throw error;}
}

async function publishedRead(client,request,read){
  if(Object.hasOwn(request,'projectionId'))fail('Published reads select the customer generation',400);
  const selected=await readDefenderPublication(client,request.companyId);
  if(selected.state==='unpublished')return selected;
  // Old verified generations cannot change or be removed: a switch between
  // selection and detail read still returns one complete, consistently identified generation.
  const data=await read(client,{...request,projectionId:selected.projectionId});
  return {...data,publication:{revision:selected.revision,publishedAt:selected.publishedAt}};
}
export const readPublishedDefenderShadow=(client,request)=>publishedRead(client,request,readDefenderShadow);
export const readPublishedDefenderShadowCve=(client,request)=>publishedRead(client,request,readDefenderShadowCve);
