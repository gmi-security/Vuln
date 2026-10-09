// Offline paired measurement. Reads the private restore; writes only disposable databases.
import assert from 'node:assert/strict';
import {randomUUID} from 'node:crypto';
import {readFile,realpath,writeFile} from 'node:fs/promises';
import {setTimeout as delay} from 'node:timers/promises';
import pg from 'pg';
import {buildDefenderPlatformShadow as build} from '../lib/db/defender-platform-shadow.mjs';
import {buildDefenderShadowReads,readDefenderShadow} from '../lib/db/defender-shadow-reads.mjs';
import {publishDefenderShadow,readDefenderPublication,readPublishedDefenderShadow} from '../lib/db/defender-shadow-publication.mjs';
import {savedReference,verifyShadowReads} from './defender-shadow-read-validation.mjs';

const socket=await realpath(process.argv[2]||'.'),cwd=await realpath('.');
assert.ok(socket.startsWith('/home/codex/vuln-recovery/')&&socket.endsWith('/socket'));
assert.ok(cwd.startsWith('/home/codex/vuln-recovery/'));
const options={host:socket,port:55483,user:'codex',connectionTimeoutMillis:5000,statement_timeout:15000,query_timeout:20000};
const admin=new pg.Client({...options,database:'postgres'}),source=new pg.Client({...options,database:'recovery_application'});
const clients=[],created=[],report={scope:'private retained Defender cohort; not live capacity',measurements:[]};
const companyId='CO-230784';let phase='guard';
const emit=value=>console.log(JSON.stringify(value));
const timed=async action=>{const start=performance.now(),value=await action();return {ms:Math.round((performance.now()-start)*10)/10,value};};
async function sampled(client,action){
  const pid=(await client.query('SELECT pg_backend_pid() pid')).rows[0].pid;
  const waits={samples:0,lockSamples:0,blockedSamples:0};let active=true;
  const monitor=(async()=>{while(active){
    const {rows:[row]}=await admin.query('SELECT wait_event_type,cardinality(pg_blocking_pids(pid)) blockers FROM pg_stat_activity WHERE pid=$1',[pid]);
    waits.samples++;if(row?.wait_event_type==='Lock')waits.lockSamples++;if(row?.blockers>0)waits.blockedSamples++;
    await delay(100);
  }})();
  try{return {...await timed(action),waits};}finally{active=false;await monitor;}
}
async function storage(client){
  return (await client.query(`SELECT relname,pg_total_relation_size(oid)::text bytes FROM pg_class
    WHERE relnamespace='public'::regnamespace AND relkind='r' ORDER BY relname`)).rows.map(r=>({table:r.relname,bytes:Number(r.bytes)}));
}
try{
  await admin.connect();
  const {rows:[guard]}=await admin.query("SELECT current_setting('data_directory') dir,current_setting('listen_addresses') listen");
  assert.equal(await realpath(guard.dir),await realpath(`${socket}/../data`));assert.equal(guard.listen,'');
  await source.connect();source.on('error',()=>{});
  await source.query('SET default_transaction_read_only=on');
  for(const guarded of [false,true]){
    phase=guarded?'guarded-base':'baseline-base';
    const name=`vuln2_shadow_test_${randomUUID().replaceAll('-','')}`;
    await admin.query(`CREATE DATABASE ${name}`);created.push(name);
    const client=new pg.Client({...options,database:name});clients.push(client);client.on('error',()=>{});await client.connect();
    for(const file of ['defender-platform-shadow','defender-shadow-reads',...(guarded?['defender-shadow-publication']:[])]){
      await client.query(await readFile(`docs/sql/${file}.sql`,'utf8'));
    }
    const measurement={mode:guarded?'guarded':'baseline'};report.measurements.push(measurement);
    const base=await sampled(client,()=>build(source,client,companyId,{afterBatch({count,batches,elapsedMs}){
      if(batches%60===0)emit({phase,records:count,elapsedMs});
    }}));
    const result=base.value;assert.equal(result.count,288878);
    measurement.baseBuildMs=base.ms;measurement.baseWaits=base.waits;measurement.records=result.count;
    emit({phase,baseBuildMs:base.ms,records:result.count,waits:base.waits});
    const states=(await client.query('SELECT status,count(*)::int n FROM defender_shadow_workflow GROUP BY status ORDER BY status')).rows;
    assert.deepEqual(states,[{status:'Open',n:215891},{status:'Resolved',n:72987}]);
    const retained=(await client.query(`SELECT count(*)::int n FROM defender_shadow_evidence e JOIN defender_shadow_workflow w USING(company_id,projection_id,finding_id)
      WHERE w.status='Open' AND e.source_run<>$1 AND e.active`,[result.sourceRun])).rows[0].n;
    assert.equal(retained,2970);measurement.retainedOlderOpen=retained;
    const request={companyId,projectionId:result.projectionId};
    if(!guarded){
      phase='baseline-derived';const derived=await sampled(client,()=>buildDefenderShadowReads(client,companyId,result.projectionId));
      measurement.derivedBuildMs=derived.ms;measurement.derivedWaits=derived.waits;
      measurement.summaryReadMs=[];
      for(let i=0;i<5;i++)measurement.summaryReadMs.push((await timed(()=>readDefenderShadow(client,request))).ms);
    }else{
      assert.equal((await readDefenderPublication(client,companyId)).state,'unpublished');
      phase='reference';const reference=await savedReference(source,companyId);assert.equal(reference.length,288878);emit({phase,records:reference.length});
      phase='guarded-derived-and-exhaustive-parity';let reads=0;
      const verification=await sampled(client,()=>verifyShadowReads(client,result,reference,{
        async afterBuild(){
          const publication=await timed(()=>publishDefenderShadow(client,{...request,expectedRevision:0,actor:'offline-scale-validator',reason:'Verified full restored cohort comparison'}));
          assert.equal(publication.value.revision,1);measurement.publicationMs=publication.ms;
          emit({phase:'guarded-published',publicationMs:publication.ms});
        },
        async reader(connection,{projectionId,...r}){
          const response=await readPublishedDefenderShadow(connection,r);
          assert.equal(response.projectionId,projectionId);assert.equal(response.publication.revision,1);
          reads++;if(reads%1000===0)emit({phase:'published-traversal',pages:reads});return response;
        },
      }));
      const parity=verification.value;
      assert.equal(parity.open,215891);assert.equal(parity.cves,10229);
      measurement.derivedAndTraversalWaits=verification.waits;
      measurement.parity=parity;measurement.publishedReads=reads;
      measurement.derivedBuildMs=parity.buildMs;
      const selected=await readDefenderPublication(client,companyId);assert.equal(selected.revision,1);
      assert.equal((await client.query('SELECT count(*)::int n FROM defender_shadow_publication_events')).rows[0].n,1);
      await assert.rejects(()=>client.query('UPDATE defender_shadow_workflow SET status=status WHERE company_id=$1 AND projection_id=$2 AND finding_id=(SELECT finding_id FROM defender_shadow_workflow LIMIT 1)',[companyId,result.projectionId]),e=>e.code==='55000');
      assert.equal((await readPublishedDefenderShadow(client,{companyId})).summary.records,288878);
    }
    measurement.storage=await storage(client);measurement.tableIndexBytes=measurement.storage.reduce((n,r)=>n+r.bytes,0);
    measurement.processPeakRssMiB=Math.round(process.resourceUsage().maxRSS/1024);
    emit({phase:'measurement-complete',...measurement});
  }
  const [baseline,guarded]=report.measurements;
  report.observedBaseBuildChangePct=Math.round((guarded.baseBuildMs/baseline.baseBuildMs-1)*1000)/10;
  report.observedDerivedBuildChangePct=Math.round((guarded.derivedBuildMs/baseline.derivedBuildMs-1)*1000)/10;
  report.limits='One sequential pair; shared host/cache effects are not controlled. No competing production workload generated. Wait sampling may miss short waits. Memory includes independent reference validation.';
  await writeFile('shadow-publication-scale-result.json',JSON.stringify(report,null,2));
  emit({phase:'PASS',records:288878,open:215891,cves:10229,publishedReads:guarded.publishedReads,observedBaseBuildChangePct:report.observedBaseBuildChangePct});
}catch(error){
  console.error(JSON.stringify({phase,code:error.code??'VALIDATION_FAILED',auditPhase:error.auditPhase,
    location:error.stack?.split('\n').filter(line=>/^\s+at /.test(line)).slice(0,7)}));process.exitCode=1;
}finally{
  await source.end();for(const client of clients)await client.end();
  for(const name of created.reverse())await admin.query(`DROP DATABASE ${name}`);
  await admin.end();
}
