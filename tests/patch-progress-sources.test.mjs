import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {SourceTextModule,SyntheticModule} from 'node:vm';
import ts from 'typescript';
const code=ts.transpileModule(readFileSync('lib/patch-progress-sources.ts','utf8'),{compilerOptions:{target:ts.ScriptTarget.ES2022,module:ts.ModuleKind.ESNext}}).outputText;
const module=new SourceTextModule(code);
await module.link(async name=>{const v=name==='node:crypto'?await import(name):name==='./patch-progress'?{assessProgress(){}}:name==='./nessus-evidence-scope'?{nessusEvidenceScope(){}}:name==='./customer-scanner-routing-server'?{loadReviewedScannerRoutes(){}}:name==='./spotlight-summary-model'?{matchesSpotlightTenant:()=>true}:{storedSpotlightContext(){},storedSpotlightProof(){}};return new SyntheticModule(Object.keys(v),function(){for(const k of Object.keys(v))this.setExport(k,v[k]);});});await module.evaluate();const api=module.namespace;
test('Defender requires published current generation and a device observation, not just an import time',()=>{
 const f={defender:{runId:'r'}},r={id:'r',published:true,finishedAt:'2026-10-25T00:00:00Z'};
 assert.equal(api.defenderProgressEvidence(f,r,{lastSeen:'2026-10-24T00:00:00Z'},false).covered,true);
 assert.equal(api.defenderProgressEvidence(f,r,undefined,false).complete,false);
 assert.equal(api.defenderProgressEvidence(f,{...r,published:false},{lastSeen:'2026-10-24'},false).complete,false);
 assert.equal(api.defenderProgressEvidence(f,{...r,id:'different'},{lastSeen:'2026-10-24'},false).scopeMatches,false);
 assert.equal(api.defenderProgressEvidence(f,r,{lastSeen:'2026-10-26'},true).complete,false);
});

test('Defender retains dated source absence from an earlier completed import, never a workflow label',()=>{
 const old={id:'old',published:true,revision:1,finishedAt:'2026-10-22T00:00:00Z'};
 const current={...old,id:'current',finishedAt:'2026-10-25T00:00:00Z'};
 const f={status:'Resolved',defender:{deviceId:'device',runId:'old',active:false,observedAt:old.finishedAt}};
 const history={run:old,device:{lastSeen:'2026-10-21T00:00:00Z'},present:false};
 const result=api.defenderProgressEvidence(f,current,undefined,false,history);
 assert.equal(result.complete,true);assert.equal(result.scopeMatches,true);assert.equal(result.covered,true);
 assert.equal(result.assessmentAt,'2026-10-21T00:00:00Z');assert.equal(result.generation,'old');assert.equal(result.retained,true);
 assert.deepEqual(result.defenderProof,{deviceId:'device',revision:1,observedAt:old.finishedAt});
 for(const bad of [undefined,{...history,present:true},{...history,device:undefined},{...history,device:{lastSeen:'2026-10-26'}},
   {...history,run:{...old,published:false}},{...history,run:{...old,revision:2}},{...history,run:{...old,id:'foreign'}},
   {...history,run:{...old,finishedAt:'2026-10-23'}}]){
   const e=api.defenderProgressEvidence(f,current,undefined,false,bad);assert.ok(!e.complete||!e.scopeMatches||!e.covered);
 }
 assert.equal(api.defenderProgressEvidence({...f,defender:{...f.defender,active:true}},current,undefined,false,history).covered,false);
 assert.equal(api.defenderProgressEvidence(f,{...current,published:false},undefined,false,history).complete,false);
});

test('Defender keeps verified proof after raw retention but rejects changed identity, scope and new positives',()=>{
 const observedAt='2026-10-22T00:00:00Z',current={id:'current',published:true,revision:1,finishedAt:'2026-10-25T00:00:00Z'};
 const f={defender:{deviceId:'device',runId:'old',active:false,observedAt}};
 const previous={state:'clear',generation:'old',assessmentAt:'2026-10-21T00:00:00Z',defenderProof:{deviceId:'device',revision:1,observedAt}};
 const result=api.defenderProgressEvidence(f,current,undefined,false,undefined,previous);
 assert.equal(result.complete,true);assert.equal(result.covered,true);assert.equal(result.assessmentAt,previous.assessmentAt);
 const pruning={run:{...current,id:'old',finishedAt:observedAt},device:undefined,present:false};
 assert.equal(api.defenderProgressEvidence(f,current,undefined,false,pruning,previous).complete,true,'raw device pruning before run pruning must preserve previously verified proof');
 for(const bad of [{...previous,state:'unknown'},{...previous,generation:'other'},{...previous,assessmentAt:'bad'},
  {...previous,assessmentAt:'2026-10-26'},{...previous,defenderProof:undefined},
  {...previous,defenderProof:{...previous.defenderProof,revision:2}},
  {...previous,defenderProof:{...previous.defenderProof,deviceId:'other'}},
  {...previous,defenderProof:{...previous.defenderProof,observedAt:'2026-10-23'}}]){
  const e=api.defenderProgressEvidence(f,current,undefined,false,undefined,bad);assert.ok(!e.complete||!e.scopeMatches||!e.covered);
 }
 const returned=api.defenderProgressEvidence(f,current,{lastSeen:'2026-10-24'},true,undefined,previous);
 assert.equal(returned.present,true);assert.notEqual(returned.retained,true);
 const fresh=api.defenderProgressEvidence({...f,defender:{...f.defender,active:true,runId:'current',observedAt:current.finishedAt}},current,{lastSeen:'2026-10-24'},true,undefined,previous);
 assert.equal(fresh.complete,true);assert.equal(fresh.scopeMatches,true);assert.equal(fresh.present,true);assert.notEqual(fresh.retained,true);
});
test('Nessus cannot use one clean policy to erase another positive or unassessed policy',()=>{
 const a='2026-10-23T00:00:00Z',b='2026-10-24T00:00:00Z';
 const f={nessusObservations:{'1':{present:false,observedAt:a},'2':{present:true,observedAt:b}}},scans=new Map([['1',{imported:true,version:1,completedAt:a}],['2',{imported:true,version:1,completedAt:b}]]),allowed=new Set(['1','2']);
 assert.equal(api.nessusProgressEvidence(f,scans,allowed).present,true);
 f.nessusObservations['2'].present=false;assert.equal(api.nessusProgressEvidence(f,scans,allowed).assessmentAt,a);
 allowed.delete('2');assert.equal(api.nessusProgressEvidence(f,scans,allowed).scopeMatches,false);
 scans.get('1').version=0;assert.equal(api.nessusProgressEvidence(f,scans,new Set(['1'])).covered,false);
});
test('generic history counts all normalized vulnerability sources and never records failed scan totals',async()=>{
 const seen=[];const client={async query(sql,params){seen.push([sql,params]);
  if(sql.includes('customer_spotlight_routes'))return {rows:[]};
  if(sql.includes('FROM spotlight_import_current'))return {rows:[]};
  if(sql.includes('FROM app_scans'))return {rows:[{connector:'nessus',status:'Completed',completed_at:'2026-10-24',payload:{id:'s',vendor:{imported:true}}},{connector:'zap',status:'Completed',completed_at:'2026-10-24',payload:{id:'z'}}]};
  if(sql.includes('patch_progress_trends'))return {rows:[],rowCount:0};
  if(sql.includes('FROM app_findings'))return {rows:[{connector:'nessus',n:10},{connector:'zap',n:3},{connector:'new-scanner',n:2}]};throw Error(sql);
 }};
 const rows=await api.collectProgressTrends(client,'CO-A');assert.equal(rows.find(r=>r.source==='total').count,15);assert.equal(rows.find(r=>r.source==='new-scanner').count,2);
 assert.ok(seen.every(([,params])=>params[0]==='CO-A'));
 assert.ok(seen.some(([sql])=>sql.includes("'Open','In Remediation'")));
 const failed={query:async(sql,p)=>sql.includes('FROM app_scans')?{rows:[{connector:'nessus',status:'Failed',payload:{}}]}:client.query(sql,p)};
 assert.deepEqual(await api.collectProgressTrends(failed,'CO-A'),[]);
});
test('repeat completed publication skips aggregation instead of duplicating a history point',async()=>{
 const client={async query(sql){if(sql.includes('customer_spotlight_routes')||sql.includes('FROM spotlight_import_current'))return {rows:[]};if(sql.includes('FROM app_scans'))return {rows:[{connector:'defender',status:'Completed',payload:{id:'s'},completed_at:'2026-10-24'}]};if(sql.includes('patch_progress_trends'))return {rowCount:1};throw Error('unexpected aggregation');}};
 assert.deepEqual(await api.collectProgressTrends(client,'CO-A'),[]);
});
