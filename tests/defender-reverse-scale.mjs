import assert from 'node:assert/strict';
import {randomUUID} from 'node:crypto';
import {readFile,writeFile,realpath} from 'node:fs/promises';
import {spawn} from 'node:child_process';
import pg from 'pg';
import {refreshModules} from './defender-refresh-fixture.mjs';
import {buildDefenderRefresh} from '../lib/db/defender-refresh-coordinator.mjs';
import {initializeWriterOwnership,readWriterOwnership,transitionWriterOwnership,completeVerifiedOwnership,defenderWriterKinds} from '../lib/db/defender-writer-ownership.mjs';
import {prepareOwnedReverseExport,verifyOwnedReverseRestore} from '../lib/db/defender-reverse-receipt.mjs';
import {editOwnedDefenderWorkflow} from '../lib/db/defender-workflow-edits.mjs';
import {publishDefenderShadow} from '../lib/db/defender-shadow-publication.mjs';
const socket=await realpath(process.argv[2]||'.');assert.ok(socket.startsWith('/home/codex/vuln-recovery/')&&socket.endsWith('/socket'));
const options={host:socket,port:55483,user:'codex',connectionTimeoutMillis:5000,statement_timeout:15000,query_timeout:20000};
const stage=process.argv[3],statePath='reverse-scale-state.json';
const context={companyId:'CO-230784',actor:'private scale fixture',reason:'offline reverse scale measurement'};
if(!stage){
  const admin=new pg.Client({...options,database:'postgres'}),name=`vuln2_shadow_test_${randomUUID().replaceAll('-','')}`;
  const report={scope:'retained recovery data; no production writes or restored-source writes',stages:[],passed:false};let created=false;
  try{
    await admin.connect();await admin.query(`CREATE DATABASE ${name}`);created=true;
    await writeFile(statePath,JSON.stringify({name,forwardId:randomUUID()}));
    for(const name of ['build','empty-export','verify','changed-export','reject-unrestored']){
      await new Promise((resolve,reject)=>{
        const child=spawn(process.execPath,['--max-old-space-size=2048','--require','./tests/shadow-cve-http-network.cjs','--experimental-vm-modules','tests/defender-reverse-scale.mjs',socket,name],{stdio:'inherit',env:process.env});
        const timer=setTimeout(()=>{child.kill('SIGKILL');},360000);
        child.once('error',reject);child.once('exit',(code,signal)=>{clearTimeout(timer);code===0?resolve():reject(Error(`Scale stage ${name} failed (${signal??code})`));});
      });
      report.stages.push(JSON.parse(await readFile(`reverse-scale-${name}.json`,'utf8')));
    }
    report.passed=true;
  }catch(error){report.error=error.message;process.exitCode=1;}
  finally{if(created)await admin.query(`DROP DATABASE ${name} WITH(FORCE)`);await admin.end();await writeFile('reverse-scale-result.json',JSON.stringify(report,null,2));console.log(JSON.stringify(report));}
}else{
  const state=JSON.parse(await readFile(statePath,'utf8'));assert.match(state.name,/^vuln2_shadow_test_[a-f0-9]+$/);
  const source=new pg.Client({...options,database:'recovery_application'}),target=new pg.Client({...options,database:state.name});
  const started=Date.now(),result={stage};
  const read=()=>readWriterOwnership(target,context.companyId);
  const change=async r=>transitionWriterOwnership(target,{...context,expectedRevision:(await read()).revision,...r});
  const register=(owner,processId)=>change({action:'register',owner,processId,inventoryVersion:1,writerKinds:defenderWriterKinds});
  async function reverse(){
    state.reverseId=randomUUID();await change({action:'begin',attemptId:state.reverseId});
    await change({action:'ack',attemptId:state.reverseId,processId:state.sqlProcess,pendingWrites:0,strictFlush:true,baselineDigest:state.baselineDigest});
    state.request={...context,attemptId:state.reverseId,expectedRevision:(await read()).revision};
  }
  try{
    await source.connect();await source.query('SET default_transaction_read_only=on');await target.connect();
    if(stage==='build'){
      for(const file of ['defender-platform-shadow','defender-shadow-reads','defender-shadow-publication','defender-shadow-refresh','defender-shadow-refresh-publication-block','defender-shadow-workflow-edits','defender-shadow-ownership','defender-shadow-reverse-receipts'])await target.query(await readFile(`docs/sql/${file}.sql`,'utf8'));
      const {candidate:{prepareDefenderRefreshCandidate:prepare},assessment:{captureDefenderRefreshAssessment:capture}}=await refreshModules();
      const built=await buildDefenderRefresh(source,target,context.companyId,{prepare,capture,withWorkflow:true,handoffAttemptId:state.forwardId,
        afterCollect(input){assert.equal(input.baseline.runId,input.source.snapshot.runId);console.log(JSON.stringify({stage,phase:'collected',findings:input.baseline.findings.length}));},
        afterBatch({batches,count}){if(batches%100===0)console.log(JSON.stringify({stage,phase:'writing',count}));}});
      assert.equal(built.state,'comparison-only');state.projectionId=built.projectionId;result.records=built.count;result.buildTimings=built.timings;
      state.baselineDigest=(await target.query('SELECT evidence FROM defender_shadow_refresh_candidates WHERE projection_id=$1',[built.projectionId])).rows[0].evidence.handoff.baselineDigest;
      state.findingId=(await target.query('SELECT finding_id FROM defender_shadow_findings WHERE projection_id=$1 ORDER BY legacy_order LIMIT 1',[built.projectionId])).rows[0].finding_id;
      await initializeWriterOwnership(target,context);const processId=randomUUID();await register('legacy',processId);await change({action:'begin',attemptId:state.forwardId});
      await change({action:'ack',attemptId:state.forwardId,processId,pendingWrites:0,strictFlush:true,baselineDigest:state.baselineDigest});
      await completeVerifiedOwnership(source,target,{...context,expectedRevision:(await read()).revision,attemptId:state.forwardId,projectionId:state.projectionId});
      state.sqlProcess=randomUUID();await register('sql',state.sqlProcess);await reverse();
    }else if(stage==='empty-export'||stage==='changed-export'){
      if(stage==='changed-export'){
        await change({action:'abort',attemptId:state.reverseId});state.sqlProcess=randomUUID();const registered=await register('sql',state.sqlProcess);
        await editOwnedDefenderWorkflow(target,{...context,findingId:state.findingId,projectionId:state.projectionId,expectedRevision:0,patch:{assignee:'private-recovery-fixture'}},
          {companyId:context.companyId,processId:state.sqlProcess,owner:'sql',epoch:registered.epoch});await reverse();
      }
      const exported=await prepareOwnedReverseExport(source,target,state.request);assert.equal(exported.artifact.changes.length,stage==='empty-export'?0:1);
      result.artifactBytes=Buffer.byteLength(JSON.stringify(exported.artifact));result.changedFindings=exported.artifact.changes.length;
    }else if(stage==='verify'){
      await verifyOwnedReverseRestore(source,target,state.request);result.receipts=Number((await target.query('SELECT count(*) n FROM defender_reverse_receipts')).rows[0].n);assert.equal(result.receipts,1);
    }else if(stage==='reject-unrestored'){
      await assert.rejects(()=>verifyOwnedReverseRestore(source,target,state.request),/does not match/);result.unrestoredChangeRejected=true;
      assert.equal(Number((await target.query('SELECT count(*) n FROM defender_reverse_receipts')).rows[0].n),1);
      await assert.rejects(()=>publishDefenderShadow(target,{...context,projectionId:state.projectionId,expectedRevision:0}),/comparison-only/);
      await assert.rejects(()=>completeVerifiedOwnership(source,target,{...state.request,projectionId:state.projectionId}),/reverse export/);
      assert.equal((await read()).phase,'reversing');result.activationBlocked=true;
    }else throw Error('Unknown scale stage');
    result.elapsedMs=Date.now()-started;result.peakRssKiB=process.resourceUsage().maxRSS;result.passed=true;
    await writeFile(statePath,JSON.stringify(state));await writeFile(`reverse-scale-${stage}.json`,JSON.stringify(result,null,2));console.log(JSON.stringify(result));
  }finally{await source.end().catch(()=>{});await target.end().catch(()=>{});}
}
