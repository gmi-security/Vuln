import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import {randomUUID} from 'node:crypto';
import {setTimeout as delay} from 'node:timers/promises';
import {buildDefenderPlatformShadow as build} from '../lib/db/defender-platform-shadow.mjs';
import {buildDefenderShadowReads,readDefenderShadow} from '../lib/db/defender-shadow-reads.mjs';
import {publishDefenderShadow as publish,readDefenderPublication as selected,readPublishedDefenderShadow as read,readPublishedDefenderShadowCve as cveRead} from '../lib/db/defender-shadow-publication.mjs';
const rejected=e=>e.code==='55000';

export async function verifyPublication(source,target,observer,writer,first){
  await target.query(await readFile('docs/sql/defender-shadow-publication.sql','utf8'));
  const companyId='CO-A',cve='CVE-2026-1234';let checks=0;
  const observerPid=(await observer.query('SELECT pg_backend_pid() pid')).rows[0].pid;
  const waitBlocked=async inspector=>{for(let i=0;i<50;i++){
    if((await inspector.query('SELECT cardinality(pg_blocking_pids($1))>0 blocked',[observerPid])).rows[0].blocked)return;
    await delay(10);
  }assert.fail('Expected a blocked competing transaction');};
  const setRows=rows=>source.query("UPDATE vuln_store SET data=$1 WHERE key='findings:00'",[JSON.stringify(rows.map(f=>[f.id,f]))]);
  const fixtures=Array.from({length:501},(_,i)=>({...first,id:`PUB-${i}`,status:'Open',asset:`asset-${i}`,cve,
    defender:{...first.defender,deviceId:`device-${i}`}}));
  await setRows(fixtures);const a=await build(source,target,companyId);await buildDefenderShadowReads(target,companyId,a.projectionId);
  await setRows([{...fixtures[0],severity:'Critical',cvss:9.8,realRisk:90}]);const b=await build(source,target,companyId);await buildDefenderShadowReads(target,companyId,b.projectionId);
  const bare=await build(source,target,companyId);
  const params=[companyId,a.projectionId];
  for(const table of ['findings','workflow','assessments','evidence']){
    await assert.rejects(()=>target.query(`UPDATE defender_shadow_${table} SET finding_id=finding_id WHERE company_id=$1 AND projection_id=$2`,params),rejected);
    await assert.rejects(()=>target.query(`DELETE FROM defender_shadow_${table} WHERE company_id=$1 AND projection_id=$2`,params),rejected);
  }
  await assert.rejects(()=>target.query('INSERT INTO defender_shadow_workflow SELECT company_id,projection_id,\'additional\',status,assignee,first_seen,last_seen,resolved_at FROM defender_shadow_workflow WHERE company_id=$1 AND projection_id=$2 LIMIT 1',params),rejected);
  await assert.rejects(()=>target.query("UPDATE defender_shadow_generations SET state='building',verified_at=NULL WHERE company_id=$1 AND projection_id=$2",params),rejected);
  await assert.rejects(()=>target.query('DELETE FROM defender_shadow_generations WHERE company_id=$1 AND projection_id=$2',params),rejected);
  for(const table of ['read_summary','priority','cve_pages']){
    await assert.rejects(()=>target.query(`DELETE FROM defender_shadow_${table} WHERE company_id=$1 AND projection_id=$2`,params),rejected);
    await assert.rejects(()=>target.query(`UPDATE defender_shadow_${table} SET company_id=company_id WHERE company_id=$1 AND projection_id=$2`,params),rejected);
  }
  await assert.rejects(()=>target.query('TRUNCATE defender_shadow_findings CASCADE'),rejected);
  await assert.rejects(()=>target.query('TRUNCATE defender_shadow_priority'),rejected);checks++;

  const incomplete=randomUUID();
  await target.query("INSERT INTO defender_shadow_generations(company_id,projection_id,model_version,source_run,snapshot_saved_at,state) VALUES($1,$2,2,'fixture',now(),'building')",[companyId,incomplete]);
  await target.query('INSERT INTO defender_shadow_findings SELECT company_id,$3,finding_id,issue_key,asset_key,connector,legacy_order,detail FROM defender_shadow_findings WHERE company_id=$1 AND projection_id=$2 LIMIT 1',[...params,incomplete]);
  await assert.rejects(()=>target.query("UPDATE defender_shadow_generations SET state='verified',finding_count=1,verified_at=now() WHERE company_id=$1 AND projection_id=$2",[companyId,incomplete]),rejected);
  await target.query("UPDATE defender_shadow_generations SET state='failed' WHERE company_id=$1 AND projection_id=$2",[companyId,incomplete]);
  const scope=(generation,expectedRevision)=>({companyId,projectionId:generation,expectedRevision,actor:'fixture-operator',reason:'Reviewed fixture publication'});
  assert.equal((await selected(target,companyId)).state,'unpublished');
  for(const generation of [incomplete,bare.projectionId,randomUUID()])await assert.rejects(()=>publish(target,scope(generation,0)),e=>e.status===409);
  assert.equal((await selected(target,companyId)).state,'unpublished');
  await target.query('DELETE FROM defender_shadow_generations WHERE company_id=$1 AND projection_id=$2',[companyId,incomplete]);
  assert.equal((await target.query('SELECT count(*)::int n FROM defender_shadow_findings WHERE projection_id=$1',[incomplete])).rows[0].n,0);checks++;

  assert.equal((await publish(target,scope(a.projectionId,0))).revision,1);
  assert.equal((await publish(target,scope(a.projectionId,1))).changed,false);
  assert.equal((await read(target,{companyId})).summary.records,501);
  await assert.rejects(()=>publish(target,scope(b.projectionId,0)),e=>e.status===409);
  await assert.rejects(()=>publish(target,{...scope(a.projectionId,0),companyId:'CO-B'}),e=>e.status===409);
  assert.equal((await selected(target,'CO-B')).state,'unpublished');
  await assert.rejects(()=>publish(target,scope(b.projectionId,1),{async beforeCommit(){
    assert.equal((await read(observer,{companyId})).summary.records,501);
    assert.equal((await observer.query('SELECT count(*)::int n FROM defender_shadow_publication_events')).rows[0].n,1);
    throw Error('Injected publication failure');
  }}),/Injected publication failure/);
  assert.equal((await selected(target,companyId)).revision,1);checks++;

  await publish(target,scope(b.projectionId,1),{async beforeCommit(){assert.equal((await selected(observer,companyId)).projectionId,a.projectionId);}});
  assert.equal((await read(target,{companyId})).summary.records,1);
  assert.equal((await cveRead(target,{companyId,cve})).findingCount,1);
  const rollback=await publish(target,{...scope(a.projectionId,2),reason:'Explicit rollback to retained verified generation'});
  assert.equal(rollback.revision,3);assert.equal((await read(target,{companyId})).summary.records,501);checks++;

  // Switch after pointer selection but before data reconstruction. The old
  // retained generation must remain a valid complete read, never a mix.
  let switched=false;
  const interleaved={async query(sql,values){const result=await target.query(sql,values);
    if(sql==='COMMIT'&&!switched){switched=true;await publish(observer,scope(b.projectionId,3));}return result;}};
  const pinned=await cveRead(interleaved,{companyId,cve});
  assert.equal(pinned.findingCount,501);assert.equal(pinned.projectionId,a.projectionId);assert.equal(pinned.publication.revision,3);
  assert.equal((await cveRead(target,{companyId,cve})).findingCount,1);
  await publish(target,scope(a.projectionId,4));
  const firstPage=await read(target,{companyId,view:'findings',limit:2});assert.ok(firstPage.page.nextCursor);
  await publish(observer,scope(b.projectionId,5));
  await assert.rejects(()=>read(target,{companyId,view:'findings',limit:2,cursor:firstPage.page.nextCursor}),/cursor scope or position/i);checks++;

  // Concurrent requests with the same expected revision: one changes the
  // pointer; the delayed stale request cannot overwrite that decision.
  let unblock,staged;const ready=new Promise(resolve=>staged=resolve),hold=new Promise(resolve=>unblock=resolve);
  const one=publish(target,scope(a.projectionId,6),{async beforeCommit(){staged();await hold;}});
  await ready;const two=publish(observer,scope(a.projectionId,6)).then(()=>({success:true}),error=>({error}));
  try{await waitBlocked(writer);}finally{unblock();}await one;assert.equal((await two).error.status,409);assert.equal((await selected(target,companyId)).revision,7);checks++;

  // A child writer that is already in flight holds a shared generation lock.
  // Verification waits, then validates counts after that write has committed.
  const racing=randomUUID();await target.query("INSERT INTO defender_shadow_generations(company_id,projection_id,model_version,source_run,snapshot_saved_at,state) VALUES($1,$2,2,'race',now(),'building')",[companyId,racing]);
  await writer.query('BEGIN');await writer.query('INSERT INTO defender_shadow_findings SELECT company_id,$3,finding_id,issue_key,asset_key,connector,legacy_order,detail FROM defender_shadow_findings WHERE company_id=$1 AND projection_id=$2 LIMIT 1',[...params,racing]);
  const waiting=observer.query("UPDATE defender_shadow_generations SET state='verified',finding_count=0,verified_at=now() WHERE company_id=$1 AND projection_id=$2",[companyId,racing]).then(()=>({success:true}),error=>({error}));
  try{await waitBlocked(target);}finally{await writer.query('COMMIT');}assert.equal((await waiting).error.code,'55000');
  await target.query('DELETE FROM defender_shadow_generations WHERE company_id=$1 AND projection_id=$2',[companyId,racing]);checks++;

  await writer.query('BEGIN ISOLATION LEVEL REPEATABLE READ');
  await writer.query('SELECT * FROM defender_shadow_generations WHERE company_id=$1 AND projection_id=$2',[companyId,bare.projectionId]);
  await buildDefenderShadowReads(target,companyId,bare.projectionId);
  await assert.rejects(()=>writer.query(`INSERT INTO defender_shadow_cve_pages VALUES($1,$2,999,'CVE-1900-9999','High',1,1,8.1,42)`,[companyId,bare.projectionId]),e=>e.code==='40001');
  await writer.query('ROLLBACK');
  await assert.rejects(()=>target.query('UPDATE defender_shadow_generations SET reads_sealed=false WHERE company_id=$1 AND projection_id=$2',params),rejected);
  const stale=randomUUID();await target.query("INSERT INTO defender_shadow_generations(company_id,projection_id,model_version,source_run,snapshot_saved_at,state) VALUES($1,$2,2,'stale',now(),'building')",[companyId,stale]);
  await writer.query('BEGIN ISOLATION LEVEL REPEATABLE READ');
  await assert.rejects(()=>writer.query("UPDATE defender_shadow_generations SET state='verified',finding_count=0,verified_at=now() WHERE company_id=$1 AND projection_id=$2",[companyId,stale]),rejected);
  await writer.query('ROLLBACK');await target.query('DELETE FROM defender_shadow_generations WHERE company_id=$1 AND projection_id=$2',[companyId,stale]);checks++;

  const history=(await target.query('SELECT revision,from_projection,projection_id,actor,reason FROM defender_shadow_publication_events WHERE company_id=$1 ORDER BY revision',[companyId])).rows;
  assert.deepEqual(history.map(row=>Number(row.revision)),[1,2,3,4,5,6,7]);assert.equal(history[0].from_projection,null);
  for(let i=1;i<history.length;i++)assert.equal(history[i].from_projection,history[i-1].projection_id);
  assert.match(history[2].reason,/rollback/);
  await assert.rejects(()=>target.query('UPDATE defender_shadow_publication_events SET reason=reason'),rejected);
  await assert.rejects(()=>target.query('DELETE FROM defender_shadow_publication_events'),rejected);
  await assert.rejects(()=>target.query('INSERT INTO defender_shadow_publication_events SELECT company_id,revision+100,from_projection,projection_id,actor,reason,published_at FROM defender_shadow_publication_events LIMIT 1'),rejected);
  await assert.rejects(()=>target.query('DELETE FROM defender_shadow_publications'),rejected);
  await assert.rejects(()=>target.query('TRUNCATE defender_shadow_publication_events'),rejected);
  await assert.rejects(()=>target.query('UPDATE defender_shadow_publications SET revision=revision+2'),rejected);
  assert.equal((await readDefenderShadow(target,{companyId,projectionId:b.projectionId})).summary.records,1);checks++;
  return {scenarios:checks,verifiedGenerations:3,publishedRevision:7,historyEvents:history.length,retainedRollbackFindings:501};
}
