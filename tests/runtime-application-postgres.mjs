// Actual built Next application, disposable Unix-socket database, no providers.
import assert from 'node:assert/strict';
import { readFile, realpath } from 'node:fs/promises';
import { randomUUID, randomBytes } from 'node:crypto';
import { spawn } from 'node:child_process';
import { once } from 'node:events';
import { createServer } from 'node:net';
import { setTimeout as delay } from 'node:timers/promises';
import pg from 'pg';
import { encode } from 'next-auth/jwt';
import { platformCollections, platformBucket } from '../lib/db/platform-records.mjs';
import { readPlatformAuthority } from '../lib/db/platform-authority.mjs';
import { transitionPlatformStore, loadPlatformStore, savePlatformDelta } from '../lib/db/platform-store.mjs';

const socket=await realpath(process.argv[2]||'.');
assert.ok(socket.startsWith('/home/codex/vuln-recovery/')&&socket.endsWith('/socket'));
const config={host:socket,port:55483,user:'codex',connectionTimeoutMillis:5000,statement_timeout:30000};
const name='vuln2_runtime_test_'+randomUUID().replaceAll('-','');
const admin=new pg.Client({...config,database:'postgres'});let db,created=false,child,output='',checks=0;
const pass=text=>{checks++;console.log('PASS '+text);};
const tx=async action=>{await db.query('BEGIN');try{const value=await action();await db.query('COMMIT');return value;}catch(error){await db.query('ROLLBACK');throw error;}};
const reserve=createServer().listen(0,'127.0.0.1');await once(reserve,'listening');const port=reserve.address().port;await new Promise(done=>reserve.close(done));
const base=`http://127.0.0.1:${port}`,secret=randomBytes(32).toString('hex');
const cookie='next-auth.session-token='+await encode({secret,token:{name:'Runtime Fixture',email:'fixture@example.invalid',orgMember:true,orgRole:'MEMBER'},maxAge:1200});
const env=Object.fromEntries(Object.entries(process.env).filter(([key])=>['PATH','HOME','LANG','LD_LIBRARY_PATH'].includes(key)));
Object.assign(env,{NODE_ENV:'production',NEXTAUTH_SECRET:secret,NEXTAUTH_URL:base,VULN_RUNTIME_SPLIT:'true',VULN_PLATFORM_STORE:'sql',
  DATABASE_URL:`postgresql://codex@localhost/${name}?host=${encodeURIComponent(socket)}&port=55483&sslmode=disable`,
  VULN_DISABLE_SCHEDULER:'true',SCANNER_ELASTIC_EXPORT_ENABLED:'false',VULNERS_BRIDGE_SCHEDULER_ENABLED:'false',VULN_REMEDIATION_UI:'true',ELASTIC_VULN_ENABLED:'true'});
async function request(path,options={}){return fetch(base+path,{...options,headers:{cookie,...options.headers},signal:AbortSignal.timeout(5000)});}
async function waitFor(check,ms=60000){const deadline=Date.now()+ms;while(Date.now()<deadline){if(await check().catch(()=>false))return;await delay(100);}throw Error('Timed out waiting for fixture: '+output.slice(-5000));}
async function start(){child=spawn(process.execPath,['scripts/start-app.mjs','-H','127.0.0.1','-p',String(port)],{env,stdio:['ignore','pipe','pipe']});child.stdout.on('data',d=>output+=d);child.stderr.on('data',d=>output+=d);await waitFor(async()=>{const r=await request('/api/health');const h=await r.json();return r.ok&&h.hydrated&&h.runtimeRole==='web';});}
async function stop(){if(!child||child.exitCode!==null)return;const exited=once(child,'exit');child.kill('SIGTERM');await Promise.race([exited,delay(15000).then(()=>{throw Error('Runtime did not stop');})]);child=null;}
try{
  await admin.connect();const guard=(await admin.query("SELECT current_setting('data_directory') dir,current_setting('listen_addresses') listen")).rows[0];
  assert.ok(guard.dir.startsWith('/home/codex/vuln-recovery/')&&!guard.listen);
  await admin.query(`CREATE DATABASE ${name}`);created=true;db=new pg.Client({...config,database:name});await db.connect();
  const company={id:'CO-FIXTURE',name:'Runtime Fixture Company',kind:'client',industry:'Test',createdAt:'2026-10-01T00:00:00Z',contactName:'',contactEmail:''};
  const fixture={companies:[[company.id,company]],folders:[],scans:[],assets:[],findings:Array.from({length:10000},(_,i)=>[`F-${i}`,{
    id:`F-${i}`,companyId:company.id,companyName:company.name,scanId:'S-1',connector:'defender',cve:`CVE-2026-${10000+i%10}`,asset:`host-${i%100}`,
    title:'Test vulnerability',description:'Fixture',remediation:'Install update',status:'Open',severity:'Critical',cvss:9.8,cvssV3:9.8,cvssV2:9.8,
    epss:0.1,kev:false,exploitAvailable:false,realRisk:50,riskPriority:'High',firstSeen:'2026-10-01T00:00:00Z',lastSeen:'2026-10-14T00:00:00Z',
    assetExposure:'Internal',assetCriticality:'Normal',tags:[],evidence:[]}]),identityAliases:[],compensatingControls:[],counter:1000,
    settings:{autoScanNewAssets:false,schedule:{autoSyncEnabled:false,alertsEnabled:false,monthlyReportsEnabled:false},sla:{Critical:7,High:30,Medium:60,Low:90}},
    meta:{autoSyncDefaultMigrated:true,defenderGenerations:{}}};
  await db.query('CREATE TABLE vuln_store(key text PRIMARY KEY,data jsonb NOT NULL,updated_at timestamptz NOT NULL DEFAULT now())');
  for(const[k,c]of Object.entries(platformCollections))for(let b=0;b<c.buckets;b++)await db.query('INSERT INTO vuln_store(key,data) VALUES($1,$2)',[`${k}:${String(b).padStart(2,'0')}`,JSON.stringify(fixture[k].filter(([id])=>platformBucket(id,c.buckets)===b))]);
  await db.query("INSERT INTO vuln_store(key,data) VALUES('meta',$1)",[JSON.stringify(Object.fromEntries(Object.entries(fixture).filter(([k])=>!platformCollections[k])))]);
  for(const file of ['001_core_storage.sql','002_platform_store_authority.sql']){const sql=await readFile('db/migrations/'+file,'utf8');await tx(()=>db.query(sql));}
  for(const file of ['customer-reporting-inputs.sql','customer-reporting-buckets.sql','customer-reporting-sections.sql','customer-reporting-executive.sql'])await db.query(await readFile('docs/sql/'+file,'utf8'));
  const initial=await readPlatformAuthority(db);await tx(()=>transitionPlatformStore(db,'sql',initial,{actor:'fixture'}));
  await start();pass('built Next app starts as web plus private worker with SQL hydration');
  let response=await request('/api/companies');assert.equal(response.status,200);let body=await response.json();
  assert.equal(body.companies.find(c=>c.id===company.id).openFindings,10000);pass('web reads verified customer findings');
  response=await fetch(base+'/api/companies',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({name:'Unauthorized'}),signal:AbortSignal.timeout(5000)});
  assert.equal(response.status,401);assert.equal((await db.query("SELECT COUNT(*)::int n FROM app_companies")).rows[0].n,1);pass('forwarded mutation still requires application authentication');
  response=await request('/api/companies',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({name:'Created by worker'})});
  assert.equal(response.status,201,await response.clone().text());
  await waitFor(async()=>{const r=await request('/api/companies');return(await r.json()).companies.some(c=>c.name==='Created by worker');});
  pass('authenticated mutation commits in worker and becomes visible in web');
  const writer=await tx(async()=>loadPlatformStore(db,await readPlatformAuthority(db)));
  const changed={...writer.data,findings:writer.data.findings.map(([id,f])=>[id,id==='F-0'?{...f,status:'Resolved'}:f])};
  await db.query('BEGIN');await savePlatformDelta(db,changed,writer.state,{findings:['F-0']});
  let worstMs=0;
  for(let i=0;i<5;i++){
    const started=Date.now();response=await request('/api/companies');worstMs=Math.max(worstMs,Date.now()-started);
    assert.equal(response.status,200);body=await response.json();assert.equal(body.companies.find(c=>c.id===company.id).openFindings,10000);
    assert.equal((await request('/api/health')).status,200);await delay(250);
  }
  await db.query('COMMIT');pass(`pages stayed committed and responsive during open writer transaction (slowest ${worstMs}ms)`);
  await waitFor(async()=>{const r=await request('/api/companies');return(await r.json()).companies.find(c=>c.id===company.id).openFindings===9999;});
  pass('web switches to completed generation after commit');
  await stop();await start();response=await request('/api/companies');body=await response.json();
  assert.equal(body.companies.find(c=>c.id===company.id).openFindings,9999);assert.ok(body.companies.some(c=>c.name==='Created by worker'));
  pass('committed data survives full supervisor restart');
  assert.ok(!output.includes('[scheduler] auto-sync'),'no provider scheduler in isolated fixture');
  console.log(JSON.stringify({checks,providersUsed:false,productionDatabaseUsed:false}));
} catch(error) { console.error(error); console.error(output.slice(-12000)); process.exitCode=1; }
finally {await stop().catch(error=>{console.error(error.message);process.exitCode=1;});await db?.end();if(created)await admin.query(`DROP DATABASE ${name} WITH (FORCE)`);await admin.end();}
