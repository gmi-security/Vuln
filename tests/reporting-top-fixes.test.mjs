import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { resolve, dirname } from 'node:path';
import { SourceTextModule, SyntheticModule } from 'node:vm';
import test from 'node:test';
import ts from 'typescript';
import {setImmediate as nextTurn} from 'node:timers/promises';

let yieldNow=nextTurn;

const modules = new Map();
async function load(path) {
  path = resolve(path);
  if (modules.has(path)) return modules.get(path);
  const code = ts.transpileModule(await readFile(path,'utf8'), {compilerOptions:{target:ts.ScriptTarget.ES2022,module:ts.ModuleKind.ESNext}}).outputText;
  const mod = new SourceTextModule(code,{identifier:path}); modules.set(path,mod);
  await mod.link(async name => {
    if (name.startsWith('.')) return load(resolve(dirname(path),name+'.ts'));
    const values=name==='node:timers/promises'?{setImmediate:(...args)=>yieldNow(...args)}:await import(name);
    return new SyntheticModule(Object.keys(values),function(){for(const key of Object.keys(values))this.setExport(key,values[key]);});
  });
  return mod;
}
const mod=await load('lib/reporting-top-fixes.ts'); await mod.evaluate();
const {buildTopFixes, cachedTopFixes}=mod.namespace;
const companyId='CO-147284';
const finding=(id,overrides={})=>({id,companyId,connector:'crowdstrike',cve:'CVE-2026-1234',asset:'device-'+id,
  status:'Open',remediation:'Install Example 3.2',severity:'High',realRisk:72,...overrides});

test('ranks open fixes without tickets; counts devices once per fix and excludes other customers and closed findings',async()=>{
  const result=await buildTopFixes(companyId,[finding('one'),finding('two',{status:'In Remediation'}),finding('duplicate',{asset:'device-one',connector:'nessus'}),
    finding('critical',{cve:'CVE-2026-4567',severity:'Critical',realRisk:100}),
    finding('closed',{status:'Resolved'}),finding('fp',{status:'False Positive'}),finding('other',{companyId:'CO-230784'}),
    finding('osint',{connector:'spiderfoot'}),finding('service',{cve:'NMAP-445'})]);
  assert.equal(result.totalFixes,2);
  assert.equal(result.affectedDevices,3);
  assert.equal(result.findingCount,4);
  assert.equal(result.uniqueCves,2);
  assert.deepEqual(result.rows.map(r=>[r.cve,r.deviceCount,r.findingCount,r.maxRisk]),[['CVE-2026-1234',2,3,72],['CVE-2026-4567',1,1,100]]);
  assert.deepEqual(result.remediationWorklist.rows.map(r=>r.cves),[['CVE-2026-4567'],['CVE-2026-1234']]);
  assert.ok(result.remediationWorklist.rows.every(r=>r.grouping==='single-cve'),'generic prose must not imply cross-CVE patch coverage');
});

test('severity worklist selects from all platform groups, not the old device-ranked top 50',async()=>{
  const rows=Array.from({length:55},(_,i)=>finding(String(i),{remediation:'Patch '+i,realRisk:i}));
  rows.push(finding('critical',{asset:'',severity:'Critical',remediation:'Critical patch'}));
  const result=await buildTopFixes(companyId,rows);
  assert.equal(result.rows[0].severity,'High');
  assert.equal(result.remediationWorklist.rows[0].remediation,'Critical patch');
  assert.equal(result.remediationWorklist.totalGroups,56);
});

test('normalizes action whitespace and case but never merges unrelated CVEs or different fixes',async()=>{
  const result=await buildTopFixes(companyId,[finding('1'),finding('2',{remediation:'  install  example 3.2 '}),finding('3',{remediation:'Install Example 4.0'}),
    finding('4',{cve:'cve-2026-1234'}),finding('5',{cve:'CVE-2026-5678'})]);
  assert.equal(result.totalFixes,3); assert.equal(result.rows[0].deviceCount,3);
  assert.equal(new Set(result.rows.map(r=>r.id)).size,3);
  const reversed=await buildTopFixes(companyId,[finding('2',{remediation:'  install  example 3.2 '}),finding('1')]);
  assert.equal(reversed.rows[0].id,result.rows[0].id);
});

test('risk breaks impact ties and absent remediation/device values are explicit, not invented coverage',async()=>{
  const result=await buildTopFixes(companyId,[finding('low',{remediation:'Patch A',realRisk:10}),finding('high',{remediation:'Patch B',realRisk:100,severity:'Critical'}),
    finding('unknown',{asset:'',remediation:'Patch C',realRisk:NaN}),finding('missing',{remediation:'  '})]);
  assert.equal(result.missingRemediation,1);assert.equal(result.missingDevice,1);
  assert.equal(result.affectedDevices,2);assert.equal(result.findingCount,3);
  assert.deepEqual(result.rows.map(r=>[r.remediation,r.deviceCount,r.maxRisk]),[['Patch B',1,100],['Patch A',1,10],['Patch C',0,0]]);
});

test('limits response rows while retaining full totals and does not include host lists or ticket packets',async()=>{
  const result=await buildTopFixes(companyId,Array.from({length:70},(_,i)=>finding(String(i),{remediation:'Patch '+i,asset:'same-device',realRisk:i})));
  assert.equal(result.rows.length,50);assert.equal(result.totalFixes,70);assert.equal(result.affectedDevices,1);assert.equal(result.findingCount,70);
  assert.equal(result.rows[0].maxRisk,69);
  assert.ok(result.rows.every(r=>!('csv' in r)&&!('hosts' in r)&&!('ticketBody' in r)));
});

test('cache invalidates when findings change and keeps customer scopes separate',async()=>{
  const findings=new Map([['one',finding('one')],['other',finding('other',{companyId:'CO-230784'})]]);
  const first=await cachedTopFixes(companyId,findings,1);
  assert.equal(await cachedTopFixes(companyId,findings,1),first);
  findings.set('two',finding('two'));
  assert.equal((await cachedTopFixes(companyId,findings,2)).findingCount,2);
  assert.equal((await cachedTopFixes('CO-230784',findings,2)).findingCount,1);
  assert.equal((await cachedTopFixes(companyId,new Map(),2)).findingCount,0);
});

test('source policy changes invalidate cached rankings and long scans yield to other requests',async()=>{
  const findings=new Map(Array.from({length:12000},(_,i)=>[String(i),finding(String(i),{connector:i%2?'defender':'crowdstrike'})]));
  let yielded=false;setImmediate(()=>{yielded=true;});
  const full=await cachedTopFixes(companyId,findings,1,'legacy');
  assert.equal(yielded,true);assert.equal(full.findingCount,12000);
  const filtered=await cachedTopFixes(companyId,findings,1,'completed-spotlight',r=>r.connector!=='crowdstrike');
  assert.equal(filtered.findingCount,6000);
  const [a,b]=await Promise.all([cachedTopFixes(companyId,findings,2),cachedTopFixes(companyId,findings,2)]);
  assert.equal(a,b);
});

test('aborted queued requests settle before the active scan and never scan their obsolete generation',async()=>{
  const activeRows=new Map(Array.from({length:5001},(_,i)=>[String(i),finding(String(i))]));
  let release,scans=0,settled=false;
  yieldNow=()=>new Promise(resolve=>{release=resolve;});
  const active=cachedTopFixes(companyId,activeRows,30);
  const obsolete=new Map([['old',finding('old')]]),values=obsolete.values.bind(obsolete);
  obsolete.values=()=>{scans++;return values();};
  const controller=new AbortController();
  const queued=cachedTopFixes(companyId,obsolete,31,'platform',undefined,undefined,undefined,controller.signal)
    .then(()=>{settled=true;return null;},error=>{settled=true;return error;});
  controller.abort();
  try {
    await nextTurn();
    assert.equal(settled,true,'abandoned request must not wait for another customer scan');
    assert.equal((await queued)?.name,'AbortError');
  } finally {yieldNow=nextTurn;release();await active;await queued;}
  assert.equal(scans,0,'abandoned generation must never be scanned');
});

test('active cancellation discards partial summaries and a live shared waiter retries successfully',async()=>{
  const rows=new Map(Array.from({length:5001},(_,i)=>[String(i),finding(String(i))]));
  let release,scans=0;const values=rows.values.bind(rows);
  rows.values=()=>{scans++;return values();};
  yieldNow=()=>new Promise(resolve=>{release=resolve;});
  const owner=new AbortController();
  const active=cachedTopFixes(companyId,rows,40,'platform',undefined,undefined,undefined,owner.signal)
    .then(()=>null,error=>error);
  const waiter=cachedTopFixes(companyId,rows,40);
  owner.abort();yieldNow=nextTurn;release();
  assert.equal((await active)?.name,'AbortError');
  const result=await waiter;
  assert.equal(result.findingCount,5001);assert.equal(scans,2);
  assert.equal(await cachedTopFixes(companyId,rows,40),result);
  assert.equal(scans,2,'only the complete retry is cached');
});

test('already aborted requests cannot use a cached result or start a scan',async()=>{
  const rows=new Map([['one',finding('one')]]);
  await cachedTopFixes(companyId,rows,50);
  const controller=new AbortController();controller.abort();
  await assert.rejects(cachedTopFixes(companyId,rows,50,'platform',undefined,undefined,undefined,controller.signal),{name:'AbortError'});
  await assert.rejects(buildTopFixes(companyId,rows.values(),undefined,undefined,undefined,controller.signal),{name:'AbortError'});
});
