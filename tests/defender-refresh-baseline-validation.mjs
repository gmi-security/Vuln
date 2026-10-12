import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {readDefenderRefreshBaseline,checkDefenderRefreshBaseline} from '../lib/db/defender-refresh-baseline.mjs';
import {buildDefenderRefresh} from '../lib/db/defender-refresh-coordinator.mjs';
import {publishDefenderShadow,readDefenderPublication} from '../lib/db/defender-shadow-publication.mjs';
import {reconstructShadowSql} from '../lib/db/defender-platform-shadow.mjs';
export async function saveRefreshBaseline(client,s,when){
  await client.query('CREATE TABLE IF NOT EXISTS vuln_store(key text PRIMARY KEY,data jsonb NOT NULL,updated_at timestamptz NOT NULL)');
  const rows=[['meta',{meta:s.meta,compensatingControls:[...s.compensatingControls]}],['companies:00',[...s.companies]]];
  for(const [name,count] of [['findings',64],['assets',16]]){
    const buckets=Array.from({length:count},()=>[]);
    for(const [id,value] of s[name])buckets[createHash('sha1').update(id).digest().readUInt32BE(0)%count].push([id,value]);
    for(let i=0;i<count;i++)rows.push([`${name}:${String(i).padStart(2,'0')}`,buckets[i]]);
  }
  await client.query('BEGIN');try{for(const [key,data] of rows)await client.query('INSERT INTO vuln_store VALUES($1,$2,$3) ON CONFLICT(key) DO UPDATE SET data=EXCLUDED.data,updated_at=EXCLUDED.updated_at',[key,JSON.stringify(data),when]);await client.query('COMMIT');}
  catch(e){await client.query('ROLLBACK');throw e;}
}
export async function verifyRefreshBaseline({source,target,writer,baseline,when,company,run,modules,pass}){
  const {prepareDefenderRefreshCandidate:prepare}=modules.candidate,{captureDefenderRefreshAssessment:capture}=modules.assessment;
  await saveRefreshBaseline(source,baseline,when);
  const captured=await readDefenderRefreshBaseline(source,company.id);assert.equal(captured.source.snapshot.runId,run);
  assert.deepEqual(captured.baseline.findings,JSON.parse(JSON.stringify([...baseline.findings.values()])));assert.equal(captured.baselineFence.buckets.length,82);
  assert.equal((await checkDefenderRefreshBaseline(source,captured.baselineFence)).unchanged,true);
  // Change persisted workflow while retaining the exact saved timestamp.
  const key=captured.baselineFence.buckets.find(r=>r.key.startsWith('findings:'));
  await writer.query('UPDATE vuln_store SET data=data WHERE key=$1',[key.key]);assert.equal((await checkDefenderRefreshBaseline(source,captured.baselineFence)).unchanged,false);
  const pinned=await readDefenderRefreshBaseline(source,company.id,{afterPinned:async()=>writer.query("UPDATE defender_connections SET revision=2 WHERE company_id=$1",[company.id])});
  assert.equal(pinned.source.revision,1);await assert.rejects(()=>checkDefenderRefreshBaseline(source,pinned.baselineFence),/matching source/);
  await writer.query('UPDATE defender_connections SET revision=1 WHERE company_id=$1',[company.id]);
  pass('baseline and source share one snapshot; committed bucket/source changes are detected even without timestamp changes');
  const before=(await target.query('SELECT count(*)::int n FROM defender_shadow_generations')).rows[0].n;
  const stale=await buildDefenderRefresh(source,target,company.id,{prepare,capture,afterPlan:async()=>writer.query("UPDATE vuln_store SET data=data WHERE key='meta'")});
  assert.equal(stale.state,'stale');assert.equal(stale.phase,'before-write');assert.equal((await target.query('SELECT count(*)::int n FROM defender_shadow_generations')).rows[0].n,before);
  const pointer=await readDefenderPublication(target,company.id);
  const post=await buildDefenderRefresh(source,target,company.id,{prepare,capture,afterBatch:async()=>writer.query("UPDATE vuln_store SET data=data WHERE key='assets:00'")});
  assert.equal(post.state,'stale');assert.equal(post.phase,'after-build');assert.equal(post.publicationAllowed,false);
  const result=await buildDefenderRefresh(source,target,company.id,{prepare,capture,afterPlan(candidate,input){
    const expected=prepare({...input,assessmentContext:candidate.assessmentContext},(f,inventory)=>modules.store.riskFields(baseline,{...f,inventory}));
    assert.deepEqual(candidate.records,expected.records);
  }});assert.equal(result.state,'comparison-only');assert.equal(result.publicationAllowed,false);
  const copied=(await target.query(reconstructShadowSql,[company.id,result.projectionId])).rows;assert.equal(copied.length,baseline.findings.size);
  for(const id of [post.projectionId,result.projectionId])await assert.rejects(()=>publishDefenderShadow(target,{companyId:company.id,projectionId:id,expectedRevision:pointer.revision??0,actor:'fixture',reason:'blocked refresh'}),/comparison-only/);
  await assert.rejects(()=>target.query('UPDATE defender_shadow_publications SET projection_id=$2,revision=revision+1 WHERE company_id=$1',[company.id,result.projectionId]),/comparison-only/);
  assert.deepEqual(await readDefenderPublication(target,company.id),pointer);
  pass('coordinator stops on saved-state changes and SQL blocks publication of both stale and unchanged refresh candidates');
}
