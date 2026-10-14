#!/usr/bin/env node
// Gate 3.4 disposable-only evidence and transaction rehearsals. No dotenv, URL or provider clients.
import {readFile,realpath,mkdir,open,stat,readdir} from 'node:fs/promises';
import {createHash} from 'node:crypto';
import {execFileSync} from 'node:child_process';
import {pathToFileURL,fileURLToPath} from 'node:url';
import path from 'node:path';
import pg from 'pg';
import {parseDisposableTarget,assertDisposableIdentity,validateRehearsalConfig,
 committedSnapshotSha256,verifiedManifestSha256,assertCleanEnvironment,assertStageBaseline} from '../lib/db/gate3-disposable.mjs';
import {collectGate3Evidence,compareEvidence,assertHistoricalParity} from '../lib/db/gate3-evidence.mjs';
import {runConsolidation} from './consolidate-approved-customers.mjs';
import {transitionPlatformStore,loadPlatformStore,savePlatformStore} from '../lib/db/platform-store.mjs';
import {readPlatformAuthority,bindPlatformWriter} from '../lib/db/platform-authority.mjs';
import {createReportingInputDigests,publishReportingInputRevisions} from '../lib/db/customer-reporting-revisions.mjs';

const fail=message=>{throw Error(message)};
const sha=value=>createHash('sha256').update(value).digest('hex');
const shaFile=async file=>{const h=createHash('sha256');const handle=await open(file,'r');try{
 for await(const chunk of handle.createReadStream())h.update(chunk);
}finally{await handle.close()}return h.digest('hex')};
const currentCommit=()=>execFileSync('git',['rev-parse','HEAD'],{encoding:'utf8'}).trim();
const targetArgs=(target,manifestPath,planHash)=>({'--socket':target.socket,'--database':target.database,
 '--port':String(target.port),'--user':target.user,'--manifest':manifestPath,'--expect-plan-hash':planHash});

export function parseArgs(argv){
 if(argv.length!==6||argv[0]!=='--config'||argv[2]!=='--mode'||argv[4]!=='--evidence-prefix')
  fail('Use --config PATH --mode MODE --evidence-prefix PATH.');
 return {configPath:argv[1],mode:argv[3],prefix:argv[5]};
}

export function assertNoPriorAttempt(prior,mode,database){
 if(mode==='repeat'||mode==='authority'||mode.startsWith('fault-'))
  if(prior.some(row=>row.mode===mode&&row.target?.database===database))
   fail('This disposable rehearsal was already attempted. Use a fresh database after review.');
}

export async function writeOnce(file,value){
 const handle=await open(file,'wx',0o600);
 try{await handle.writeFile(JSON.stringify(value,null,2)+'\n');await handle.sync();}finally{await handle.close()}
 return shaFile(file);
}

async function guardedClient(target){
 const client=new pg.Client({host:target.socket,port:target.port,database:target.database,user:target.user,
  ssl:false,application_name:'vuln2-gate34-disposable',connectionTimeoutMillis:15000});
 await client.connect();
 try{
  const row=(await client.query(`SELECT current_database() database,
   current_setting('server_version_num')::int version,current_setting('unix_socket_directories') sockets,
   inet_server_addr() "serverAddress",current_setting('data_directory') "dataDirectory",
   current_setting('listen_addresses') "listenAddresses"`)).rows[0];
  assertDisposableIdentity(target,row);
  const peers=Number((await client.query(`SELECT count(*)::text n FROM pg_stat_activity
   WHERE datname=current_database() AND pid<>pg_backend_pid()`)).rows[0].n);
  if(peers!==0)fail('Other database sessions remain.');
  return client;
 }catch(error){await client.end();throw error}
}

async function fingerprint(target){
 const client=await guardedClient(target);let opened=false;
 try{
  await client.query('BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY');opened=true;
  await client.query("SET LOCAL search_path=public;SET LOCAL TIME ZONE 'UTC';SET LOCAL statement_timeout='0';SET LOCAL idle_in_transaction_session_timeout='1800s'");
  const evidence=await collectGate3Evidence(client);
  await client.query('COMMIT');opened=false;
  return evidence;
 }finally{if(opened)await client.query('ROLLBACK').catch(()=>{});await client.end()}
}

async function transition(target,direction,expected){
 const client=await guardedClient(target);let opened=false;
 try{
  await client.query('BEGIN');opened=true;
  await client.query("SET LOCAL search_path=public;SET LOCAL lock_timeout='5s';SET LOCAL idle_in_transaction_session_timeout='1800s'");
  const authority=await readPlatformAuthority(client);
  if(JSON.stringify(authority)!==JSON.stringify(expected))fail('Authority changed since evidence capture.');
  const reporting=createReportingInputDigests();
  const result=await transitionPlatformStore(client,direction,authority,{actor:'gate34-disposable',reporting});
  await publishReportingInputRevisions(client,reporting.finish());
  await client.query('COMMIT');opened=false;return result;
 }finally{if(opened)await client.query('ROLLBACK').catch(()=>{});await client.end()}
}

async function expectRejected(target,fn,label,expected){
 const client=await guardedClient(target);let opened=false;
 try{
  await client.query('BEGIN');opened=true;
  let rejected=false;
  try{await fn(client)}catch(error){
   if(!expected.test(error.message))throw Error(`${label} failed for an unexpected reason: ${error.message}`);
   rejected=true;
  }
  if(!rejected)fail(`${label} unexpectedly succeeded.`);
  return {name:label,rejected};
 }finally{if(opened)await client.query('ROLLBACK').catch(()=>{});await client.end()}
}

async function authorityRehearsal(target,before){
 if(before.authority?.mode!=='legacy'||before.authority.enforced!==true||
  before.authority.epoch!=='1'||before.authority.revision!=='1')fail('Unexpected starting authority.');
 const checks=[];
 checks.push(await expectRejected(target,client=>client.query('UPDATE app_store_metadata SET payload=payload WHERE id=1'),
  'unauthorized SQL writer in legacy mode',/stale|registered|SQL store/i));
 checks.push(await expectRejected(target,client=>transitionPlatformStore(client,'sql',
  {...before.authority,revision:'0'},{actor:'gate34-stale'}),'stale forward revision',/authority changed/i));
 compareEvidence(before,await fingerprint(target));
 const forward=await transition(target,'sql',before.authority);
 const sql=await fingerprint(target);
 if(sql.authority.mode!=='sql'||sql.authority.epoch!=='2'||sql.authority.revision!=='0'||
  sql.snapshotSha256!==before.snapshotSha256)fail('Forward authority or snapshot changed unexpectedly.');
 assertHistoricalParity(before,sql);
 checks.push(await expectRejected(target,client=>client.query("UPDATE vuln_store SET data=data WHERE key='meta'"),
  'obsolete legacy writer',/stale|registered|snapshot writes/i));
 checks.push(await expectRejected(target,client=>bindPlatformWriter(client,before.authority),
  'stale epoch writer',/authority changed/i));
 checks.push(await expectRejected(target,client=>transitionPlatformStore(client,'sql',sql.authority,{actor:'gate34-repeat'}),
  'repeated forward transition',/opposite current authority/i));
 compareEvidence(sql,await fingerprint(target));
 const client=await guardedClient(target);let opened=false;
 try{
  await client.query('BEGIN');opened=true;
  const loaded=await loadPlatformStore(client,sql.authority);
  loaded.data.gate34Rehearsal={test:'authority-persistence'};
  const reporting=createReportingInputDigests();
  const saved=await savePlatformStore(client,loaded.data,loaded.state,{actor:'gate34-disposable',reporting});
  if(saved.authority.revision!=='1'||saved.authority.epoch!=='2')fail('SQL revision did not advance once.');
  await publishReportingInputRevisions(client,reporting.finish());
  await client.query('COMMIT');opened=false;
 }finally{if(opened)await client.query('ROLLBACK').catch(()=>{});await client.end()}
 const saved=await fingerprint(target);
 if(saved.authority.revision!=='1'||saved.relationships.orphans!==before.relationships.orphans)
  fail('SQL save did not preserve customer relationships.');
 assertHistoricalParity(before,saved);
 checks.push(await expectRejected(target,client=>bindPlatformWriter(client,sql.authority),
  'stale SQL revision writer',/authority changed/i));
 checks.push(await expectRejected(target,client=>transitionPlatformStore(client,'legacy',
  {...saved.authority,revision:'0'},{actor:'gate34-stale'}),'stale reverse revision',/authority changed/i));
 const reverse=await transition(target,'legacy',saved.authority);
 const after=await fingerprint(target);
 if(after.authority.mode!=='legacy'||after.authority.epoch!=='3'||after.authority.revision!=='0'||
  after.relationships.orphans!==before.relationships.orphans)fail('Reverse authority or relationships changed unexpectedly.');
 assertHistoricalParity(before,after);
 const check=await guardedClient(target);
 try{const row=(await check.query("SELECT data->'gate34Rehearsal' value FROM vuln_store WHERE key='meta'")).rows[0];
  if(row?.value?.test!=='authority-persistence')fail('SQL metadata edit was lost during reverse.');
 }finally{await check.end()}
 checks.push(await expectRejected(target,client=>bindPlatformWriter(client,saved.authority),
  'obsolete SQL writer',/authority changed/i));
 checks.push(await expectRejected(target,client=>transitionPlatformStore(client,'legacy',after.authority,{actor:'gate34-repeat'}),
  'repeated reverse transition',/opposite current authority/i));
 return {forward,sql,saved,reverse,after,checks};
}

export async function main(argv=process.argv.slice(2)){
 const {configPath,mode,prefix}=parseArgs(argv);
 if(process.platform!=='linux'||process.getuid?.()===0)fail('Run as the unprivileged codex account on Linux.');
 process.umask(0o077);
 if(await realpath(process.cwd())!=='/home/codex/vuln-recovery/cw-runner-pr52')
  fail('Run only from the separate PR #52 recovery checkout.');
 assertCleanEnvironment(process.env);
 const configRaw=await readFile(configPath);
 const config=JSON.parse(configRaw);
 const target=validateRehearsalConfig(config,mode);
 if(await realpath(target.root)!==target.root||await realpath(target.socket)!==target.socket||
  await realpath(`${target.root}/data`)!==`${target.root}/data`)fail('Disposable paths contain a symlink.');
 const rootStat=await stat(target.root);
 if(rootStat.uid!==process.getuid()||(rootStat.mode&0o077)!==0)fail('Disposable root ownership or permissions mismatch.');
 if(await realpath(configPath)!==`${target.root}/config.json`)fail('Unexpected config path.');
 if(await realpath(config.sourceDump.path)!==config.sourceDump.path)fail('Backup path contains a symlink.');
 const evidenceDir=`${target.root}/evidence`;
 await mkdir(evidenceDir,{recursive:true,mode:0o700});
 if(!prefix.startsWith(`${evidenceDir}/`)||!/^[a-z0-9-]{6,80}$/.test(path.basename(prefix)))
  fail('Evidence prefix must be a unique private file stem.');
 const backupHash=await shaFile(config.sourceDump.path);
 if(backupHash!==config.sourceDump.sha256)fail('Backup SHA-256 mismatch.');
 if(config.manifestPath&&await shaFile(config.manifestPath)!==verifiedManifestSha256)
  fail('Verified manifest SHA-256 mismatch.');
 const commit=currentCommit();
 if(commit!==config.expectedCommit)fail('Reviewed Git commit does not match checkout.');
 const scripts=Object.fromEntries(await Promise.all([
  ['gate3-disposable-rehearsal.mjs',import.meta.url],
  ['consolidate-approved-customers.mjs',new URL('./consolidate-approved-customers.mjs',import.meta.url)],
  ['gate3-disposable.mjs',new URL('../lib/db/gate3-disposable.mjs',import.meta.url)],
  ['gate3-evidence.mjs',new URL('../lib/db/gate3-evidence.mjs',import.meta.url)]
 ].map(async([name,url])=>[name,await shaFile(fileURLToPath(url))])));
 const started={mode,commit,scripts,configSha256:sha(configRaw),target,backupPath:config.sourceDump.path,backupSha256:backupHash,
  startedAt:new Date().toISOString()};
 if(mode==='repeat'||mode==='authority'||mode.startsWith('fault-')){
  const prior=[];
  for(const file of await readdir(evidenceDir))if(file.endsWith('.started.json'))
   prior.push(JSON.parse(await readFile(`${evidenceDir}/${file}`,'utf8')));
  assertNoPriorAttempt(prior,mode,target.database);
  await writeOnce(`${evidenceDir}/${target.database}.${mode}.lock.json`,started);
 }
 await writeOnce(`${prefix}.started.json`,started);
 let result;
 try{
  const before=await fingerprint(target);
  if(before.relationships.orphans!==0||before.relationships.idMismatches!==0||
   before.relationships.duplicateIds!==0||before.invalidForeignKeys.length!==0)
   fail('Existing records or foreign keys are inconsistent.');
  const precommitExpected=config.sourceDump.kind==='precommit'?
   JSON.parse(await readFile(config.manifestPath,'utf8')).expected:undefined;
  if(mode==='preflight'||mode==='repeat'||mode.startsWith('fault-')||mode==='authority'||mode==='app')
   assertStageBaseline(config,before,precommitExpected?.snapshotSha256,precommitExpected?.authority);
  if(mode==='preflight'||mode==='fingerprint')result={before,noDatabaseWrites:true,noExternalRequests:true};
  else if(mode==='repeat'){
   if(before.snapshotSha256!==committedSnapshotSha256||before.ledger.length!==1||
    before.relationships.sourceCustomers.length!==0)fail('Committed repeat-run baseline mismatch.');
   let refusal;
   try{await runConsolidation({mode:'--commit',args:targetArgs(target,config.manifestPath,config.planHash),target})}
   catch(error){refusal=error.message}
   if(!/Observed snapshot.*drifted|already applied/i.test(refusal??''))fail('Repeat run was not safely refused.');
   const after=await fingerprint(target);compareEvidence(before,after);
   result={before,after,refusal,noChanges:true};
  }else if(mode.startsWith('fault-')){
   const boundary=mode.slice(6);
   if(before.ledger.length||before.relationships.sourceCustomers.join(',')!=='CO-9150,CO-9153')
    fail('Precommit fault baseline mismatch.');
   const manifest=JSON.parse(await readFile(config.manifestPath,'utf8'));
   if(before.snapshotSha256!==manifest.expected?.snapshotSha256)fail('Precommit snapshot differs from manifest.');
   let injected=false;
   try{await runConsolidation({mode:'--commit',args:targetArgs(target,config.manifestPath,config.planHash),target,faultAt:boundary})}
   catch(error){if(error.code==='22012'||/division by zero/i.test(error.message))injected=true;else throw error}
   if(!injected)fail('Database-level fault was not observed.');
   const after=await fingerprint(target);compareEvidence(before,after);
   result={before,after,boundary,injectedSqlstate:'22012',rolledBack:true};
  }else if(mode==='authority'){
   if(before.snapshotSha256!==committedSnapshotSha256||before.ledger.length!==1)fail('Authority baseline mismatch.');
   result={before,...await authorityRehearsal(target,before)};
  }else if(mode==='restore'){
   if(!config.baselineEvidencePath||!/^[a-f0-9]{64}$/.test(config.baselineEvidenceSha256)||
    await shaFile(config.baselineEvidencePath)!==config.baselineEvidenceSha256)
    fail('Independent baseline evidence missing or changed.');
   const expected=JSON.parse(await readFile(config.baselineEvidencePath,'utf8')).result?.before;
   if(!expected)fail('Invalid baseline evidence.');
   compareEvidence(expected,before);result={before,restoredMatchesBaseline:true};
  }else if(mode==='app')result={before,applicationLaunchAuthorized:false};
  else fail('Unsupported mode.');
  const resultSha256=await writeOnce(`${prefix}.result.json`,{...started,completedAt:new Date().toISOString(),result});
  console.log(JSON.stringify({status:'verified',mode,commit,evidence:`${prefix}.result.json`,resultSha256,
   logicalSha256:result.after?.logicalSha256??result.before.logicalSha256}));
 }catch(error){
  const category=/^[A-Z0-9_]{2,8}$/.test(error.code??'')?error.code:'REHEARSAL_STOP';
  try{await writeOnce(`${prefix}.failure.json`,{...started,failedAt:new Date().toISOString(),category,message:error.message})}
  catch{console.error('FAILURE_EVIDENCE_WRITE_FAILED')}
  throw error;
 }
}

if(process.argv[1]&&import.meta.url===pathToFileURL(process.argv[1]).href)
 await main().catch(error=>{console.error(`GATE34_STOPPED: ${error.message}`);process.exitCode=1});
