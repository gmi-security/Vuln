import assert from 'node:assert/strict';
import test from 'node:test';
import {parseDisposableTarget,assertDisposableIdentity,validateRehearsalConfig,
 committedSnapshotSha256,verifiedManifestSha256,verifiedPlanHash,assertCleanEnvironment} from '../lib/db/gate3-disposable.mjs';
import {assertStageBaseline} from '../lib/db/gate3-disposable.mjs';
import {compareEvidence,relationshipSummary,collectGate3Evidence,assertHistoricalParity} from '../lib/db/gate3-evidence.mjs';
import {parseArgs,writeOnce,assertNoPriorAttempt} from '../scripts/gate3-disposable-rehearsal.mjs';
import {runConsolidation} from '../scripts/consolidate-approved-customers.mjs';
import {mkdtemp,readFile,rm} from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';

const root='/home/codex/vuln-recovery/gate3-4-abc123';
const target={root,socket:`${root}/socket`,database:'gate34_fault_abc123',port:55484,user:'codex'};

test('disposable target rejects preserved and production database names',()=>{
 assert.deepEqual(parseDisposableTarget(target),target);
 for(const database of ['vuln','recovery_merge_fenced','recovery_application','gate3_restore_verify','recovery_merge'])
  assert.throws(()=>parseDisposableTarget({...target,database}),/disposable database/i);
 assert.throws(()=>parseDisposableTarget({...target,socket:'/var/run/postgresql'}),/socket/i);
 assert.throws(()=>parseDisposableTarget({...target,port:5432}),/port/i);
});

test('database identity requires a private socket-only cluster inside the evidence root',()=>{
 const identity={database:'gate34_fault_abc123',serverAddress:null,sockets:`${root}/socket`,dataDirectory:`${root}/data`,listenAddresses:'',version:180000};
 assert.doesNotThrow(()=>assertDisposableIdentity(target,identity));
 assert.throws(()=>assertDisposableIdentity(target,{...identity,serverAddress:'127.0.0.1'}),/socket-only/i);
 assert.throws(()=>assertDisposableIdentity(target,{...identity,dataDirectory:'/var/lib/postgresql/18/main'}),/data directory/i);
 assert.throws(()=>assertDisposableIdentity(target,{...identity,database:'recovery_merge_fenced'}),/identity/i);
 assert.throws(()=>assertDisposableIdentity(target,{...identity,version:190000}),/identity/i);
});

test('complete evidence comparison refuses a changed audit table or authority',()=>{
 const before={schemaSha256:'a',tables:[{name:'patch_group_ticket_audit',count:1,sha256:'b'}],authority:{mode:'legacy',epoch:'1',revision:'1'},relationships:{orphans:0}};
 assert.doesNotThrow(()=>compareEvidence(before,structuredClone(before)));
 assert.throws(()=>compareEvidence(before,{...before,tables:[{name:'patch_group_ticket_audit',count:2,sha256:'c'}]}),/logical evidence changed/i);
 assert.throws(()=>compareEvidence(before,{...before,authority:{mode:'sql',epoch:'2',revision:'0'}}),/logical evidence changed/i);
});

test('authority rehearsal preserves every customer bucket and historical ticket table',()=>{
 const before={bucketHashes:[{key:'companies:00',sha256:'a'},{key:'meta',sha256:'b'}],
  tables:[{name:'patch_group_ticket_requests',count:1,sha256:'c'},
   {name:'patch_group_ticket_audit',count:1,sha256:'d'},
   {name:'vuln_metrics_history',count:1,sha256:'e'},
   {name:'customer_consolidation_runs',count:1,sha256:'f'}]};
 const after=structuredClone(before);after.bucketHashes[1].sha256='new-metadata';
 assert.doesNotThrow(()=>assertHistoricalParity(before,after));
 after.tables[1].sha256='changed';
 assert.throws(()=>assertHistoricalParity(before,after),/historical/i);
 after.tables[1].sha256='d';after.bucketHashes[0].sha256='changed';
 assert.throws(()=>assertHistoricalParity(before,after),/historical/i);
});

test('relationship check detects missing and cross-customer scan ownership',()=>{
 const rows={companies:[['CO-1',{id:'CO-1'}]],folders:[['FLD-1',{id:'FLD-1',companyId:'CO-1'}]],
  scans:[['S-1',{id:'S-1',companyId:'CO-1',folderId:'FLD-1'}]],
  findings:[['F-1',{id:'F-1',companyId:'CO-1',scanId:'S-1'}]],assets:[]};
 assert.equal(relationshipSummary(rows).orphans,0);
 rows.findings[0][1].companyId='CO-2';
 assert.equal(relationshipSummary(rows).orphans,1);
 rows.findings[0][1].scanId='missing';
 assert.equal(relationshipSummary(rows).orphans,1);
});

test('repeat requires committed backup and fault injection requires pinned precommit backup',()=>{
 const base={...target,database:'gate34_repeat_abc123',expectedCommit:'a'.repeat(40),
  sourceDump:{path:`${root}/committed.dump`,sha256:'a'.repeat(64),kind:'postcommit'},
  expectedSnapshotSha256:committedSnapshotSha256,
  manifestPath:'/home/codex/vuln-recovery/customer-verified-manifest-ygkf_nxc/manifest.json',
  manifestSha256:verifiedManifestSha256,planHash:verifiedPlanHash};
 assert.doesNotThrow(()=>validateRehearsalConfig(base,'repeat'));
 assert.throws(()=>validateRehearsalConfig({...base,sourceDump:{...base.sourceDump,kind:'precommit'}},'repeat'),/postcommit/i);
 assert.throws(()=>validateRehearsalConfig({...base,database:'gate34_fault_before_abc123'},'fault-before'),/precommit/i);
 const pre={...base,database:'gate34_fault_before_abc123',sourceDump:{path:'/home/codex/vuln-recovery/gate3-precommit-ZSHf45/precommit.dump',
  sha256:'e8a52f902c834f8485ccdb6e2622e9355944d17596d569164d6c7b71512e1a23',kind:'precommit'}};
 assert.doesNotThrow(()=>validateRehearsalConfig(pre,'fault-before'));
 assert.throws(()=>validateRehearsalConfig({...pre,sourceDump:{...pre.sourceDump,sha256:'a'.repeat(64)}},'fault-before'),/precommit/i);
});

test('CLI requires an explicit config, phase and unique evidence prefix',()=>{
 assert.deepEqual(parseArgs(['--config','a','--mode','preflight','--evidence-prefix','b']),
  {configPath:'a',mode:'preflight',prefix:'b'});
 assert.throws(()=>parseArgs(['--mode','repeat']),/use --config/i);
 assert.throws(()=>parseArgs(['--config','a','--mode','repeat','--evidence-prefix','b','--execute']),/use --config/i);
});

test('rehearsal refuses inherited production database and provider configuration',()=>{
 assert.doesNotThrow(()=>assertCleanEnvironment({HOME:'/home/codex',PATH:'/usr/bin'}));
 assert.throws(()=>assertCleanEnvironment({DATABASE_URL:'redacted'}),/environment/i);
 assert.throws(()=>assertCleanEnvironment({NESSUS_API_KEY:'redacted'}),/environment/i);
 assert.throws(()=>assertCleanEnvironment({NEXTAUTH_SECRET:'redacted'}),/environment/i);
});

test('offline preflight rejects a precommit restore presented as the committed baseline',()=>{
 const evidence={snapshotSha256:committedSnapshotSha256,
  ledger:[{id:'gmi-valor-v1',company_lineage:2,scan_reference_lineage:2,scheduler_lineage:8}],
  authority:{mode:'legacy',enforced:true,epoch:'1',revision:'1'},
  aliases:{count:55,legacySourcePrefixes:0,mappingsRecorded:true},
  relationships:{sourceCustomers:[],orphans:0,idMismatches:0,duplicateIds:0},invalidForeignKeys:[]};
 assert.doesNotThrow(()=>assertStageBaseline({database:'gate34_repeat_abc123',sourceDump:{kind:'postcommit'}},evidence));
 assert.throws(()=>assertStageBaseline({database:'gate34_repeat_abc123',sourceDump:{kind:'postcommit'}},
  {...evidence,snapshotSha256:'0'.repeat(64)}),/baseline/i);
 assert.throws(()=>assertStageBaseline({database:'gate34_repeat_abc123',sourceDump:{kind:'precommit'}},evidence),/baseline/i);
 const pre={...evidence,snapshotSha256:'1'.repeat(64),ledger:[],
  relationships:{...evidence.relationships,sourceCustomers:['CO-9150','CO-9153']},
  aliases:{count:0,legacySourcePrefixes:0,mappingsRecorded:false}};
 assert.doesNotThrow(()=>assertStageBaseline({database:'gate34_fault_before_abc123',sourceDump:{kind:'precommit'}},
  pre,'1'.repeat(64),evidence.authority));
 assert.throws(()=>assertStageBaseline({database:'gate34_fault_before_abc123',sourceDump:{kind:'precommit'}},
  pre,'1'.repeat(64),{...evidence.authority,revision:'0'}),/baseline/i);
});

test('consolidation refuses a mismatched disposable connection before reading a manifest',async()=>{
 await assert.rejects(runConsolidation({mode:'--commit',target,
  args:{'--socket':target.socket,'--database':'recovery_merge_fenced','--port':'55484','--user':'codex'}}),
  /connection arguments/i);
 await assert.rejects(runConsolidation({mode:'--dry-run',target,
  args:{'--socket':target.socket,'--database':target.database,'--port':'55484','--user':'codex'},faultAt:'scans'}),
  /fault injection requires a commit/i);
});

test('evidence cannot be overwritten and has a stable SHA-256',async()=>{
 const dir=await mkdtemp(path.join(os.tmpdir(),'gate34-test-'));
 try{
  const file=path.join(dir,'result.json');
  assert.equal(await writeOnce(file,{status:'verified'}),'a738232f080ef2af308af4672ecd9215771bd565b7dbf962ad1df21b60c74fc8');
  await assert.rejects(writeOnce(file,{status:'changed'}),/exist/i);
  assert.equal(JSON.parse(await readFile(file,'utf8')).status,'verified');
 }finally{await rm(dir,{recursive:true,force:true})}
});

test('an interrupted mutating rehearsal cannot be silently replayed',()=>{
 const prior=[{mode:'fault-scans',target:{database:'gate34_fault_scans_abc123'}}];
 assert.throws(()=>assertNoPriorAttempt(prior,'fault-scans','gate34_fault_scans_abc123'),/already attempted/i);
 assert.doesNotThrow(()=>assertNoPriorAttempt(prior,'fault-scans','gate34_fault_scans_other1'));
 assert.doesNotThrow(()=>assertNoPriorAttempt(prior,'preflight','gate34_fault_scans_abc123'));
});

test('streamed full-table fingerprint detects an altered finding without SQL writes',async()=>{
 const fake=company=>{
  let fetched=false;const statements=[];
  return {statements,async query(sql){
   const q=String(sql);statements.push(q);
   if(q.includes('FROM pg_class c JOIN pg_namespace'))return {rows:[{table_name:'vuln_store',attnum:1,attname:'key',data_type:'text'}]};
   if(q.includes('FROM pg_constraint'))return {rows:[]};
   if(q.includes('FROM pg_indexes'))return {rows:[]};
   if(q.includes('FROM pg_views')||q.includes('FROM pg_sequences')||q.includes('FROM pg_trigger')||q.includes('FROM pg_proc p'))return {rows:[]};
   if(q.includes('FROM pg_index i'))return {rows:[{attname:'key'}]};
   if(q.startsWith('DECLARE')){fetched=false;return {rows:[]}}
   if(q.startsWith('FETCH')){
    if(fetched)return {rows:[]};fetched=true;
    return {rows:[{payload:JSON.stringify({key:'companies:00',data:[['CO-1',{id:'CO-1'}]]})},
     {payload:JSON.stringify({key:'findings:00',data:[['F-1',{id:'F-1',companyId:company,scanId:'S-1'}]]})},
     {payload:JSON.stringify({key:'folders:00',data:[['FLD-1',{id:'FLD-1',companyId:'CO-1'}]]})},
     {payload:JSON.stringify({key:'scans:00',data:[['S-1',{id:'S-1',companyId:'CO-1',folderId:'FLD-1'}]]})}]};
   }
   if(q.startsWith('CLOSE'))return {rows:[]};
   if(q.includes("to_regclass('public.app_store_authority')"))return {rows:[{relation:'app_store_authority'}]};
   if(q.includes('FROM public.app_store_authority'))return {rows:[{mode:'legacy',enforced:true,epoch:'1',revision:'1'}]};
   if(q.includes("to_regclass('public.customer_consolidation_runs')"))return {rows:[{relation:null}]};
   throw Error(`Unexpected SQL: ${q}`);
  }};
 };
 const clean=fake('CO-1'),changed=fake('CO-2');
 const a=await collectGate3Evidence(clean),b=await collectGate3Evidence(changed);
 assert.equal(a.relationships.orphans,0);
 assert.equal(b.relationships.orphans,1);
 assert.notEqual(a.logicalSha256,b.logicalSha256);
 assert.ok(clean.statements.every(q=>!/^(INSERT|UPDATE|DELETE|TRUNCATE|COMMIT)/i.test(q)));
});
