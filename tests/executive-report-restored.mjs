// Read-only historical application snapshot. Compares the connected executive
// calculation with its legacy orchestration at one fixed time and KEV context.
import assert from 'node:assert/strict';
import {realpath} from 'node:fs/promises';
import pg from 'pg';
import {executiveHarness} from './executive-report-harness.mjs';

const socket=await realpath(process.argv[2]||'.');assert.ok(socket.startsWith('/home/codex/vuln-recovery/')&&socket.endsWith('/socket'));
const db=new pg.Client({host:socket,port:55483,user:'codex',database:'recovery_application',connectionTimeoutMillis:5000,statement_timeout:15000});
const h=await executiveHarness(),transport=x=>JSON.parse(JSON.stringify(x));
const fields={
 findings:['id','companyId','companyName','connector','cve','title','asset','category','status','severity','realRisk','riskPriority','cvss','cvssV2','cvssV3','epss','firstSeen','lastSeen','resolvedAt','kev','ransomware','exploitAvailable','assetExposure','assetCriticality'],
 scans:['id','companyId','completedAt','status'],assets:['id','companyId','identifier','hostname','ipAddresses','source'],
};
try{
 await db.connect();const g=(await db.query("SELECT current_setting('data_directory') dir,current_setting('listen_addresses') listen")).rows[0];
 assert.ok(g.dir.startsWith('/home/codex/vuln-recovery/')&&!g.listen);
 await db.query('BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY');
 const savedSla=(await db.query("SELECT data->'settings'->'sla' sla FROM vuln_store WHERE key='meta'")).rows[0].sla;
 assert.ok(savedSla&&['Critical','High','Medium','Low'].every(k=>Number.isFinite(savedSla[k])),'Retained SLA settings required');
 for(const [companyId,label] of [['CO-230784','Retained Defender'],['CO-147284','Retained mixed scanners']]){
  const company=(await db.query("SELECT e->1 company FROM vuln_store,LATERAL jsonb_array_elements(data) e WHERE key='companies:00' AND e->>0=$1",[companyId])).rows[0].company;
  assert.ok(company&&!company.isDemo);const s={companies:new Map([[company.id,company]]),folders:new Map(),findings:new Map(),scans:new Map(),assets:new Map(),
   identityAliases:new Map(),compensatingControls:new Map(),meta:{},seeded:true,counter:1000,
   settings:{sla:savedSla,autoScanNewAssets:false,schedule:{autoSyncEnabled:false,alertsEnabled:false,monthlyReportsEnabled:false}}};
  const start=Date.now();
  for(const [kind,n] of [['findings',64],['scans',8],['assets',16]])for(let i=0;i<n;i++){
   assert.ok(Date.now()-start<300000,'Read deadline');
   const select=`jsonb_build_object(${fields[kind].flatMap(k=>[`'${k}'`,`f->'${k}'`]).join(',')})`;
   const {rows}=await db.query(`SELECT ${select} record FROM vuln_store,LATERAL jsonb_array_elements(data) WITH ORDINALITY x(e,n),LATERAL(SELECT e->1 f) y
    WHERE key=$1 AND f->>'companyId'=$2 ORDER BY n`,[`${kind}:${String(i).padStart(2,'0')}`,companyId]);
   for(const {record:r} of rows){assert.ok(!s[kind].has(r.id));s[kind].set(r.id,r);}
  }
  h.setState(s);const legacyStart=performance.now(),expected=h.legacy.legacyExecutiveReport(h.store,s,companyId),legacyMs=performance.now()-legacyStart;
  const runs=[];let actual;
  for(let i=0;i<3;i++){const t=performance.now();actual=h.store.computeExecReport(companyId);runs.push(Math.round(performance.now()-t));assert.deepEqual(transport(actual),transport(expected));}
  assert.equal(actual.findings.open,companyId==='CO-230784'?215891:80000);
  console.log(JSON.stringify({cohort:label,records:s.findings.size,assets:s.assets.size,scans:s.scans.size,open:actual.findings.open,
   legacyCalculationMs:Math.round(legacyMs),connectedCalculationMs:runs,outputBytes:Buffer.byteLength(JSON.stringify(actual)),
   findingsSources:[...new Set([...s.findings.values()].map(f=>f.connector))].sort(),inventorySources:[...new Set([...s.assets.values()].map(a=>a.source))].sort()}));
 }
 await db.query('COMMIT');console.log(JSON.stringify({peakComparisonProcessRssMiB:Math.ceil(process.resourceUsage().maxRSS/1024),sourceCalls:0,
  context:'fixed observation time, retained SLA, same offline catalog for both calculations; not current live threat acceptance'}));
 console.log('PASS every executive report field matches the legacy report for both retained customers');
}finally{await db.end();}
