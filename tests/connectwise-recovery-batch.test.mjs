import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {spawnSync} from 'node:child_process';
import {mkdtemp,readFile,writeFile,rm} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import path from 'node:path';
import test from 'node:test';
import {preflightRecovery,executeRecovery,retryIndex17,exclusiveWrite,classifyLookup,boundedGet} from '../lib/connectwise-recovery-batch.mjs';
import {readRecoveryDatabase,sendConnectWiseGet,runRecoveryCommand} from '../scripts/connectwise-recovery-batch.mjs';

const hash=value=>createHash('sha256').update(value).digest('hex');
const id=i=>`00000000-0000-4000-8000-${String(i).padStart(12,'0')}`;
const scope='a'.repeat(64);
const target=hash('api-na.myconnectwise.net/test');
const expected={companyId:32628,boardId:159,appCompanyId:'CO-147284'};

test('operator command keeps batch execution disabled before preflight',()=>{
  const script=path.resolve('scripts/connectwise-recovery-batch.mjs');
  for(const [args,message] of [[['--execute'],'BATCH_EXECUTION_DISABLED']]){
    const run=spawnSync(process.execPath,[script,...args],{encoding:'utf8'});
    assert.equal(run.status,1);
    assert.match(run.stderr,new RegExp(message));
    assert.doesNotMatch(run.stderr,/EVIDENCE_DIRECTORY_MISSING|DATABASE_NOT_READ_ONLY/);
  }
});

async function fixture(t){
  const dir=await mkdtemp(path.join(tmpdir(),'cw-recovery-test-'));
  t.after(()=>rm(dir,{recursive:true,force:true}));
  const pending=Array.from({length:72},(_,i)=>({requestId:id(i),scopeHash:scope,reason:'not_queried'}));
  const checkpoint=JSON.stringify({cohortSize:96,pending});
  const prior={requestId:id(13),method:'GET',attempt:2,startedAt:'2026-10-13T00:00:00.000Z'};
  const retry={requestId:id(13),method:'GET',attempt:2,checkedAt:'2026-10-13T00:01:00.000Z',httpStatus:200,
    responseSha256:hash('[]'),responseCount:1,classification:'found_verified',ticketId:123,
    referenceMatches:true,companyMatches:true,boardMatches:true};
  const files={
    'checkpoint.json':checkpoint,
    'single-12-result.json':JSON.stringify({requestId:id(12),method:'GET',classification:'found_verified'}),
    'single-13-started.json':JSON.stringify({requestId:id(13),method:'GET',attempt:1,startedAt:'2026-10-12T23:58:00.000Z'}),
    'single-13-retry-01-started.json':JSON.stringify(prior),
    'single-13-retry-01-result.json':JSON.stringify(retry),
  };
  for(const [name,content] of Object.entries(files))await writeFile(path.join(dir,name),content);
  const pins=Object.fromEntries(Object.entries(files).map(([name,content])=>[name,hash(content)]));
  const rows=pending.slice(13).map(item=>({requestId:item.requestId,scopeHash:scope,state:'uncertain',ticketId:null,
    cwTarget:target,companyId:32628,boardId:159,appCompanyId:'CO-147284'}));
  const readDb=async()=>({database:'recovery_merge_fenced',readOnly:true,cohortCount:96,rows,connection:{
    endpoint:'https://api-na.myconnectwise.net/v4_6_release/apis/3.0',companyId:'TEST',clientId:'client',
    publicKey:'public',privateKey:'private',target,
  }});
  return {dir,pins,pending,rows,readDb};
}

async function seedRateLimit(f){
  let previous=f.pins['single-13-retry-01-result.json'];
  for(let index=14;index<=17;index++){
    const startedAt=`2026-10-13T00:${String((index-13)*5).padStart(2,'0')}:00.000Z`;
    await exclusiveWrite(`single-${index}-started.json`,{
      requestId:id(index),method:'GET',attempt:1,index,scopeHash:scope,
      checkpointSha256:f.pins['checkpoint.json'],previousResultSha256:previous,startedAt,
    },f.dir);
    const result={requestId:id(index),method:'GET',attempt:1,index,checkedAt:startedAt,
      httpStatus:index===17?429:200,responseSha256:hash('[]'),
      ...(index===17?{classification:'rate_limited',retryAfter:'30'}:{classification:'not_found',responseCount:0})};
    previous=await exclusiveWrite(`single-${index}-result.json`,result,f.dir);
  }
  for(const name of ['single-17-started.json','single-17-result.json'])
    f.pins[name]=hash(await readFile(path.join(f.dir,name)));
}

test('CLI dispatch permits only the explicitly authorized index-17 retry',async t=>{
  const f=await fixture(t);await seedRateLimit(f);let calls=0,dbReads=0;
  const options={dir:f.dir,pins:f.pins,readDb:async ids=>{dbReads++;return f.readDb(ids);},
    now:()=>new Date('2026-10-13T00:25:00.000Z'),
    sendGet:async()=>{calls++;return {status:200,headers:{},body:'[]'};}};
  for(const args of [['--retry-index-17'],['--authorize-index-17'],['--execute'],
    ['--authorize-index-17','--retry-index-17'],
    ['--execute','--authorize-index-17'],['--retry-index-17','--execute'],
    ['--retry-index-17','--authorize-index-17','--execute'],['--retry-index-17','--retry-index-17'],
    ['--unknown']]){
    await assert.rejects(runRecoveryCommand(args,options),/RETRY_AUTHORIZATION_REQUIRED|BATCH_EXECUTION_DISABLED|INVALID_ARGUMENTS/);
  }
  assert.equal(calls,0);assert.equal(dbReads,0);
  const result=await runRecoveryCommand(['--retry-index-17','--authorize-index-17'],options);
  assert.equal(result.index,17);assert.equal(result.classification,'not_found');
  assert.equal(calls,1);
  await assert.rejects(runRecoveryCommand(['--retry-index-17','--authorize-index-17'],options),/RETRY_ALREADY_ATTEMPTED/);
  assert.equal(calls,1);
});

test('index-17 rate limit requires pinned originals and blocks normal execution',async t=>{
  const f=await fixture(t);await seedRateLimit(f);let calls=0;
  const plan=await preflightRecovery({dir:f.dir,pins:f.pins,readDb:f.readDb});
  assert.equal(plan.nextIndex,17);assert.equal(plan.retryRequired,true);
  await assert.rejects(executeRecovery({dir:f.dir,pins:f.pins,readDb:f.readDb,
    sendGet:async()=>{calls++;return {status:200,headers:{},body:'[]'};}}),/INDEX_17_RETRY_REQUIRED/);
  assert.equal(calls,0);
  delete f.pins['single-17-result.json'];
  await assert.rejects(preflightRecovery({dir:f.dir,pins:f.pins,readDb:f.readDb}),/EVIDENCE_PIN_MISSING/);
});

test('index-17 retry needs authorization and durable five-minute cooldown',async t=>{
  const f=await fixture(t);await seedRateLimit(f);let calls=0;
  const sendGet=async()=>{calls++;return {status:200,headers:{},body:'[]'};};
  const options={dir:f.dir,pins:f.pins,readDb:f.readDb,sendGet};
  await assert.rejects(retryIndex17({...options,now:()=>new Date('2026-10-13T00:26:00.000Z')}),/RETRY_NOT_AUTHORIZED/);
  await assert.rejects(retryIndex17({...options,authorized:true,
    now:()=>new Date('2026-10-13T00:24:59.999Z')}),/COOLDOWN_ACTIVE/);
  assert.equal(calls,0);
  await retryIndex17({...options,authorized:true,now:()=>new Date('2026-10-13T00:25:00.000Z')});
  assert.equal(calls,1);
  const plan=await preflightRecovery({dir:f.dir,pins:f.pins,readDb:f.readDb});
  assert.equal(plan.nextIndex,18);assert.equal(plan.retryRequired,false);
  await assert.rejects(retryIndex17({...options,authorized:true,
    now:()=>new Date('2026-10-13T00:31:00.000Z')}),/RETRY_ALREADY_ATTEMPTED/);
  assert.equal(calls,1);
});

test('index-17 pins reject changed originals and incomplete retry evidence',async t=>{
  const f=await fixture(t);await seedRateLimit(f);
  const result=path.join(f.dir,'single-17-result.json');
  await writeFile(result,'{}');
  await assert.rejects(preflightRecovery({dir:f.dir,pins:f.pins,readDb:f.readDb}),/EVIDENCE_CHANGED/);
  const g=await fixture(t);await seedRateLimit(g);
  await exclusiveWrite('single-17-retry-01-started.json',{requestId:id(17)},g.dir);
  await assert.rejects(preflightRecovery({dir:g.dir,pins:g.pins,readDb:g.readDb}),/INCOMPLETE_ATTEMPT/);
  let calls=0;
  await assert.rejects(retryIndex17({dir:g.dir,pins:g.pins,readDb:g.readDb,authorized:true,
    now:()=>new Date('2026-10-13T00:26:00.000Z'),sendGet:async()=>{calls++;}}),/INCOMPLETE_ATTEMPT/);
  assert.equal(calls,0);
  const h=await fixture(t);
  await writeFile(path.join(h.dir,'single-17-retry-01-result.json.sha256'),hash('{}'));
  await assert.rejects(preflightRecovery({dir:h.dir,pins:h.pins,readDb:h.readDb}),/INCOMPLETE_ATTEMPT/);
});

test('index-17 retry stops on another 429, identity mismatch, transport and evidence write failure',async t=>{
  for(const response of [
    {status:429,headers:{'retry-after':'600'},body:'{}'},
    {status:401,headers:{},body:'{}'},
    {status:200,headers:{},body:JSON.stringify([{id:1,externalXRef:'wrong',company:{id:32628},board:{id:159}}])},
    new Error('GET_TIMEOUT'),
  ]){
    const f=await fixture(t);await seedRateLimit(f);let calls=0;
    await assert.rejects(retryIndex17({dir:f.dir,pins:f.pins,readDb:f.readDb,authorized:true,
      now:()=>new Date('2026-10-13T00:26:00.000Z'),sendGet:async()=>{
        calls++;if(response instanceof Error)throw response;return response;
      }}),/LOOKUP_STOPPED/);
    assert.equal(calls,1);
    await assert.rejects(preflightRecovery({dir:f.dir,pins:f.pins,readDb:f.readDb}),/INVALID_EVIDENCE|INCOMPLETE_ATTEMPT/);
    await assert.rejects(retryIndex17({dir:f.dir,pins:f.pins,readDb:f.readDb,authorized:true,
      now:()=>new Date('2026-10-13T00:40:00.000Z'),sendGet:async()=>{calls++;}}),/INVALID_EVIDENCE|INCOMPLETE_ATTEMPT/);
    assert.equal(calls,1);
  }
  const f=await fixture(t);await seedRateLimit(f);let calls=0;
  await assert.rejects(retryIndex17({dir:f.dir,pins:f.pins,readDb:f.readDb,authorized:true,
    now:()=>new Date('2026-10-13T00:26:00.000Z'),sendGet:async()=>{
      calls++;return {status:200,headers:{},body:'[]'};
    },writeEvidence:async(name,value,dir)=>{
      if(name.endsWith('-result.json'))throw Error('disk full');
      return exclusiveWrite(name,value,dir);
    }}),/EVIDENCE_WRITE_FAILED/);
  assert.equal(calls,1);
  await assert.rejects(preflightRecovery({dir:f.dir,pins:f.pins,readDb:f.readDb}),/INCOMPLETE_ATTEMPT/);
});

test('index-18 waits across restarts and honors a longer Retry-After from the retry',async t=>{
  const f=await fixture(t);await seedRateLimit(f);
  await retryIndex17({dir:f.dir,pins:f.pins,readDb:f.readDb,authorized:true,
    now:()=>new Date('2026-10-13T00:25:00.000Z'),
    sendGet:async()=>({status:200,headers:{'retry-after':'600'},body:'[]'})});
  const plan=await preflightRecovery({dir:f.dir,pins:f.pins,readDb:f.readDb});
  assert.equal(plan.nextAllowedAt,Date.parse('2026-10-13T00:35:00.000Z'));
  let calls=0;
  await assert.rejects(executeRecovery({dir:f.dir,pins:f.pins,readDb:f.readDb,
    now:()=>new Date('2026-10-13T00:34:59.999Z'),sleep:async()=>{},
    sendGet:async()=>{calls++;return {status:200,headers:{},body:'[]'};}}),/COOLDOWN_ACTIVE/);
  assert.equal(calls,0);
  await assert.rejects(executeRecovery({dir:f.dir,pins:f.pins,readDb:f.readDb,maxRequests:1,
    now:()=>new Date('2026-10-13T00:35:00.000Z'),sleep:async()=>{},
    sendGet:async()=>{calls++;return {status:200,headers:{},body:'[]'};}}),/BATCH_PAUSED/);
  assert.equal(calls,1);
  const resumed=await preflightRecovery({dir:f.dir,pins:f.pins,readDb:f.readDb});
  assert.equal(resumed.nextIndex,19);
  assert.equal(resumed.nextAllowedAt,Date.parse('2026-10-13T00:40:00.000Z'));
});

test('preflight pins checkpoint and index-13 retry, validates 58 unqueried scopes without sending GET',async t=>{
  const f=await fixture(t);let calls=0;
  const plan=await preflightRecovery({dir:f.dir,pins:f.pins,readDb:async()=>{calls++;return f.readDb();}});
  assert.equal(calls,1);assert.equal(plan.nextIndex,14);assert.equal(plan.remaining,58);
  assert.equal(plan.connection.target,target);
});

test('preflight rejects missing or modified pinned evidence and an invalid index-13 retry',async t=>{
  const f=await fixture(t);
  await writeFile(path.join(f.dir,'checkpoint.json'),'{}');
  await assert.rejects(preflightRecovery({dir:f.dir,pins:f.pins,readDb:f.readDb}),/CHECKPOINT_CHANGED/);
  await writeFile(path.join(f.dir,'checkpoint.json'),JSON.stringify({cohortSize:96,pending:f.pending}));
  await rm(path.join(f.dir,'single-13-retry-01-result.json'));
  await assert.rejects(preflightRecovery({dir:f.dir,pins:f.pins,readDb:f.readDb}),/EVIDENCE_MISSING/);
  const bad={requestId:id(13),method:'GET',attempt:2,httpStatus:200,classification:'not_found'};
  await writeFile(path.join(f.dir,'single-13-retry-01-result.json'),JSON.stringify(bad));
  f.pins['single-13-retry-01-result.json']=hash(JSON.stringify(bad));
  await assert.rejects(preflightRecovery({dir:f.dir,pins:f.pins,readDb:f.readDb}),/INDEX_13_RETRY_INVALID/);
});

test('preflight rejects duplicate IDs, changed scope, target, board, company and non-read-only DB',async t=>{
  const f=await fixture(t);
  for(const change of [
    d=>{d.rows[0].scopeHash='c'.repeat(64);},d=>{d.rows[0].cwTarget='c'.repeat(64);},
    d=>{d.rows[0].boardId=160;},d=>{d.rows[0].companyId=42;},
    d=>{d.rows[0].appCompanyId='CO-OTHER';},d=>{d.readOnly=false;},
    d=>{d.cohortCount=95;},
  ]){
    const state=await f.readDb();state.rows=structuredClone(state.rows);change(state);
    await assert.rejects(preflightRecovery({dir:f.dir,pins:f.pins,readDb:async()=>state}),/SCOPE_MISMATCH|DATABASE_NOT_READ_ONLY/);
  }
  const duplicate=structuredClone(f.pending);duplicate[15].requestId=duplicate[14].requestId;
  const raw=JSON.stringify({cohortSize:96,pending:duplicate});
  await writeFile(path.join(f.dir,'checkpoint.json'),raw);f.pins['checkpoint.json']=hash(raw);
  await assert.rejects(preflightRecovery({dir:f.dir,pins:f.pins,readDb:f.readDb}),/CHECKPOINT_INVALID/);
});

test('preflight refuses prior attempt, incomplete result and later noncontiguous evidence',async t=>{
  const f=await fixture(t);
  await writeFile(path.join(f.dir,'single-14-started.json'),'{}');
  await assert.rejects(preflightRecovery({dir:f.dir,pins:f.pins,readDb:f.readDb}),/INCOMPLETE_ATTEMPT/);
  await rm(path.join(f.dir,'single-14-started.json'));
  await writeFile(path.join(f.dir,'single-15-result.json'),'{}');
  await assert.rejects(preflightRecovery({dir:f.dir,pins:f.pins,readDb:f.readDb}),/NONCONTIGUOUS_EVIDENCE/);
});

test('HTTP 200 classification requires zero or one exact match and rejects ambiguity and identity drift',()=>{
  const scopeRow={requestId:id(14),companyId:32628,boardId:159};
  const ticket={id:42,externalXRef:`GMI-GRP-${id(14)}`,company:{id:32628},board:{id:159}};
  assert.equal(classifyLookup(200,'[]',scopeRow).classification,'not_found');
  assert.equal(classifyLookup(200,JSON.stringify([ticket]),scopeRow).classification,'found_verified');
  assert.equal(classifyLookup(200,JSON.stringify([ticket,ticket]),scopeRow).classification,'ambiguous');
  for(const changed of [{...ticket,externalXRef:'wrong'},{...ticket,company:{id:1}},{...ticket,board:{id:1}},
    {...ticket,id:0}])assert.equal(classifyLookup(200,JSON.stringify([changed]),scopeRow).classification,'mismatch');
  assert.equal(classifyLookup(200,'{}',scopeRow).classification,'invalid_response');
});

test('execution records one GET at a time, preserves results, and resumes without duplicate requests',async t=>{
  const f=await fixture(t);const calls=[];
  const sendGet=async({requestId})=>{calls.push(requestId);return {status:200,headers:{},body:'[]'};};
  let clock=Date.parse('2026-10-14T00:00:00.000Z');
  await assert.rejects(executeRecovery({dir:f.dir,pins:f.pins,readDb:f.readDb,sendGet,
    maxRequests:2,now:()=>new Date(clock),sleep:async ms=>{clock+=ms;}}),/BATCH_PAUSED/);
  assert.deepEqual(calls,[id(14),id(15)]);
  assert.equal(JSON.parse(await readFile(path.join(f.dir,'single-14-result.json'),'utf8')).classification,'not_found');
  const plan=await preflightRecovery({dir:f.dir,pins:f.pins,readDb:f.readDb});
  assert.equal(plan.nextIndex,16);
  clock=Date.parse('2026-10-15T00:00:00.000Z');
  await assert.rejects(executeRecovery({dir:f.dir,pins:f.pins,readDb:f.readDb,sendGet,
    maxRequests:1,now:()=>new Date(clock),sleep:async ms=>{clock+=ms;}}),/INDEX_17_RETRY_REQUIRED/);
  assert.deepEqual(calls,[id(14),id(15),id(16)]);
});

test('execution halts before another GET if the cooldown clock has not advanced',async t=>{
  const f=await fixture(t);let calls=0;
  await assert.rejects(executeRecovery({dir:f.dir,pins:f.pins,readDb:f.readDb,
    sendGet:async()=>{calls++;return {status:200,headers:{},body:'[]'};},
    now:()=>new Date('2026-10-14T00:00:00.000Z'),sleep:async()=>{}}),/COOLDOWN_ACTIVE/);
  assert.equal(calls,1);
});

test('all 58 sequential results produce a verified report and repeat execution sends no GET',async t=>{
  const f=await fixture(t);await seedRateLimit(f);
  await retryIndex17({dir:f.dir,pins:f.pins,readDb:f.readDb,authorized:true,
    now:()=>new Date('2026-10-13T00:25:00.000Z'),
    sendGet:async()=>({status:200,headers:{},body:'[]'})});
  let calls=0,active=0;
  const sendGet=async()=>{calls++;active++;assert.equal(active,1);active--;return {status:200,headers:{},body:'[]'};};
  let clock=Date.parse('2026-10-14T00:00:00.000Z');
  const options={dir:f.dir,pins:f.pins,readDb:f.readDb,sendGet,
    now:()=>new Date(clock),sleep:async ms=>{clock+=ms;}};
  const report=await executeRecovery(options);
  assert.equal(calls,54);assert.equal(report.processed,58);
  assert.equal(report.totalVerified,34);assert.equal(report.totalUnresolved,62);
  assert.equal(report.records.length,58);
  const saved=JSON.parse(await readFile(path.join(f.dir,'batch-14-71-report.json'),'utf8'));
  assert.deepEqual(saved,report);
  assert.deepEqual(await executeRecovery(options),report);
  assert.equal(calls,54);
  await writeFile(path.join(f.dir,'batch-14-71-report.json'),'{}');
  await assert.rejects(preflightRecovery({dir:f.dir,pins:f.pins,readDb:f.readDb}),/EVIDENCE_CHANGED/);
});

test('HTTP 401, 403, 429 and 500 persist one result and stop with no automatic retry',async t=>{
  for(const status of [401,403,429,500]){
    const f=await fixture(t);let calls=0;
    await assert.rejects(executeRecovery({dir:f.dir,pins:f.pins,readDb:f.readDb,
      sendGet:async()=>{calls++;return {status,headers:{'retry-after':'30'},body:'{}'};},
      now:()=>new Date('2026-10-14T00:00:00.000Z'),sleep:async()=>{}}),/LOOKUP_STOPPED/);
    assert.equal(calls,1);
    const result=JSON.parse(await readFile(path.join(f.dir,'single-14-result.json'),'utf8'));
    assert.equal(result.httpStatus,status);assert.equal(result.classification,status===429?'rate_limited':'http_error');
    assert.equal(result.retryAfter,'30');
  }
});

test('ambiguous, malformed and wrong-identity 200 responses stop after one evidence record',async t=>{
  const ticket={id:42,externalXRef:`GMI-GRP-${id(14)}`,company:{id:32628},board:{id:159}};
  for(const [body,classification] of [[JSON.stringify([ticket,ticket]),'ambiguous'],['{}','invalid_response'],
    [JSON.stringify([{...ticket,board:{id:160}}]),'mismatch']]){
    const f=await fixture(t);let calls=0;
    await assert.rejects(executeRecovery({dir:f.dir,pins:f.pins,readDb:f.readDb,
      sendGet:async()=>{calls++;return {status:200,headers:{},body};},
      now:()=>new Date('2026-10-14T00:00:00.000Z'),sleep:async()=>{}}),/LOOKUP_STOPPED/);
    assert.equal(calls,1);
    assert.equal(JSON.parse(await readFile(path.join(f.dir,'single-14-result.json'),'utf8')).classification,classification);
  }
});

test('transport timeout, connection error and failed evidence write leave an irreversible attempt marker',async t=>{
  for(const error of [Object.assign(new Error('timeout'),{code:'ETIMEDOUT'}),Object.assign(new Error('connection'),{code:'ECONNRESET'})]){
    const f=await fixture(t);let calls=0;
    await assert.rejects(executeRecovery({dir:f.dir,pins:f.pins,readDb:f.readDb,
      sendGet:async()=>{calls++;throw error;},now:()=>new Date('2026-10-14T00:00:00.000Z'),sleep:async()=>{}}),/LOOKUP_STOPPED/);
    assert.equal(calls,1);
    await assert.rejects(preflightRecovery({dir:f.dir,pins:f.pins,readDb:f.readDb}),/INCOMPLETE_ATTEMPT/);
  }
  const f=await fixture(t);
  await assert.rejects(executeRecovery({dir:f.dir,pins:f.pins,readDb:f.readDb,
    sendGet:async()=>({status:200,headers:{},body:'[]'}),
    writeEvidence:async(name,data,dir)=>{if(name.endsWith('-result.json'))throw Error('disk full');
      const {exclusiveWrite}=await import('../lib/connectwise-recovery-batch.mjs');return exclusiveWrite(name,data,dir);},
    now:()=>new Date('2026-10-14T00:00:00.000Z'),sleep:async()=>{}}),/EVIDENCE_WRITE_FAILED/);
  await assert.rejects(preflightRecovery({dir:f.dir,pins:f.pins,readDb:f.readDb}),/INCOMPLETE_ATTEMPT/);
  const before=await fixture(t);let calls=0;
  await assert.rejects(executeRecovery({dir:before.dir,pins:before.pins,readDb:before.readDb,
    sendGet:async()=>{calls++;return {status:200,headers:{},body:'[]'};},
    writeEvidence:async()=>{throw Error('disk full');},
    now:()=>new Date('2026-10-14T00:00:00.000Z'),sleep:async()=>{}}),/disk full/);
  assert.equal(calls,0);
});

test('bounded GET rejects oversized response, timeout and connection failure without retry',async()=>{
  for(const response of [
    {status:200,headers:{},body:'x'.repeat(101)},
    Object.assign(new Error('timeout'),{code:'ETIMEDOUT'}),
    Object.assign(new Error('connection'),{code:'ECONNRESET'}),
  ]){
    let calls=0;
    await assert.rejects(boundedGet({url:new URL('https://api-na.myconnectwise.net/v4_6_release/apis/3.0/service/tickets'),
      ip:'8.8.8.8',headers:{Accept:'application/json'},limit:100,requestImpl:async()=>{calls++;
        if(response instanceof Error)throw response;return response;}}),/RESPONSE_TOO_LARGE|timeout|connection/);
    assert.equal(calls,1);
  }
});

test('database adapter uses the named recovery clone and a read-only transaction',async()=>{
  const calls=[];
  const client={connect:async()=>{},end:async()=>{},query:async(sql,args)=>{
    calls.push({sql,args});
    if(sql.includes('current_database()'))return {rows:[{database:'recovery_merge_fenced',readOnly:true}]};
    if(sql.includes('count(*)'))return {rows:[{count:96}]};
    if(sql.includes('patch_group_ticket_requests'))return {rows:[]};
    if(sql.includes('patch_connectwise_connection'))return {rows:[{secret:'v1.iv.tag.data',target}]};
    return {rows:[]};
  }};
  await assert.rejects(readRecoveryDatabase(Array.from({length:59},(_,i)=>id(i+13)),
    {clientFactory:()=>client,readSecret:async()=>('x'.repeat(32))}),/CONNECTION_DECRYPT_FAILED/);
  assert.equal(calls[0].sql,'BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY');
  assert.ok(calls.every(({sql})=>!/\b(?:UPDATE|INSERT|DELETE|TRUNCATE)\b/i.test(sql)));
  assert.ok(calls.some(({sql,args})=>sql.includes('patch_group_ticket_requests')&&args[0][0]===id(13)));
  assert.equal(calls.at(-1).sql,'ROLLBACK');
});

test('HTTPS adapter issues one scoped GET with pinned public DNS and rejects private targets',async()=>{
  const connection={endpoint:'https://api-na.myconnectwise.net/v4_6_release/apis/3.0',companyId:'TEST',target,
    publicKey:'public',privateKey:'private',clientId:'client'};
  const row={requestId:id(14),companyId:32628,boardId:159};
  let calls=0;
  const response=await sendConnectWiseGet({requestId:id(14),row,connection},{
    lookup:async()=>({address:'8.8.8.8',family:4}),
    get:async({url,ip,headers})=>{calls++;assert.equal(url.pathname,'/v4_6_release/apis/3.0/service/tickets');
      assert.equal(url.searchParams.get('conditions'),`externalXRef="GMI-GRP-${id(14)}"`);
      assert.equal(url.searchParams.get('pageSize'),'2');assert.equal(ip,'8.8.8.8');
      assert.equal(headers.Accept,'application/json');return {status:200,headers:{},body:'[]'};},
  });
  assert.equal(response.status,200);assert.equal(calls,1);
  await assert.rejects(sendConnectWiseGet({requestId:id(14),row,connection},{
    lookup:async()=>({address:'127.0.0.1',family:4}),get:async()=>{calls++;}}),/NONPUBLIC_DNS/);
  assert.equal(calls,1);
  await assert.rejects(sendConnectWiseGet({requestId:id(14),row,connection},{
    lookup:async()=>new Promise(()=>{}),dnsTimeoutMs:5,get:async()=>{calls++;}}),/DNS_TIMEOUT/);
  assert.equal(calls,1);
});
