import assert from 'node:assert/strict';
import test from 'node:test';
import {readFileSync} from 'node:fs';
import {resolve,dirname} from 'node:path';
import {SourceTextModule,SyntheticModule} from 'node:vm';
import ts from 'typescript';
const modules=new Map();
async function load(file){file=resolve(file);if(modules.has(file))return modules.get(file);
 const mod=new SourceTextModule(ts.transpileModule(readFileSync(file,'utf8'),{compilerOptions:{target:ts.ScriptTarget.ES2022,module:ts.ModuleKind.ESNext}}).outputText,{identifier:file});modules.set(file,mod);
 await mod.link(async(name,parent)=>{if(name.startsWith('.'))return load(resolve(dirname(parent.identifier),name+'.ts'));const values=await import(name);return new SyntheticModule(Object.keys(values),function(){for(const k of Object.keys(values))this.setExport(k,values[k]);});});return mod;}
const mod=await load('lib/reporting-top-fixes.ts');await mod.evaluate();
const buildTopFixes=(company,rows,include,threats=new Map())=>mod.namespace.buildTopFixes(company,rows,include,threats);
const company='CO-ONE',f=(id,extra={})=>({id,companyId:company,connector:'nessus',cve:'CVE-2026-1000',asset:'host-'+id,status:'Open',severity:'High',realRisk:50,cvss:7.5,remediation:'Update product to 2.0',title:'Example product vulnerability',kev:false,exploitAvailable:false,epss:0,assetExposure:'Internal',assetCriticality:'Normal',assetSource:'inferred',lastSeen:'2026-10-20T00:00:00Z',firstSeen:'2026-10-01T00:00:00Z',assignee:null,...extra});

test('priority selection considers all findings, so a single exploited host outranks 55 high-volume fixes',async()=>{
 const input=Array.from({length:55},(_,i)=>f(String(i),{remediation:'Update '+i}));
 input.push(f('urgent',{cve:'CVE-2026-2000',kev:true,severity:'Medium',cvss:5,remediation:'Emergency patch'}));
 const r=await buildTopFixes(company,input);
 assert.ok(r.priorityWorklist,'full-cohort priority summaries must be present');
 assert.equal(r.priorityWorklist.byRemediation[0].remediation,'Emergency patch');
 assert.equal(r.priorityWorklist.totalRemediations,56);
 assert.equal(r.priorityWorklist.byRemediation.length,50);
 assert.equal(r.priorityWorklist.byCve[0].cves[0],'CVE-2026-2000');
});

test('CVE view deduplicates devices across fixes and includes findings lacking a remediation',async()=>{
 const r=await buildTopFixes(company,[f('a'),f('b',{asset:'host-a',remediation:'Update other product'}),f('c',{remediation:''}),f('foreign',{companyId:'CO-OTHER'}),f('closed',{status:'Resolved'})]);
 const p=r.priorityWorklist;assert.ok(p);
 assert.equal(p.byCve.length,1);assert.equal(p.byCve[0].deviceCount,2);assert.equal(p.byCve[0].findingCount,3);
 assert.equal(p.byRemediation.length,2);assert.equal(p.byCve[0].missingRemediation,1);
 assert.equal(p.byCve[0].exposedDevices,null,'inferred exposure is not verified');
 assert.equal(p.byCve[0].criticalDevices,null);assert.equal(p.byCve[0].epss,null,'zero placeholder is not an EPSS observation');
});

test('known threat evidence elevates priority without inventing per-device context; owners and dates stay explicit',async()=>{
 const threats=new Map([['CVE-2026-1000',{kev:true,active:true,epss:0.8,updatedAt:'2026-10-21T00:00:00Z'}]]);
 const r=await buildTopFixes(company,[f('a',{assetSource:'manual',assetExposure:'Internet-facing',assetCriticality:'High',assignee:'Patch team',dueAt:'2026-10-21T00:00:00Z'}),f('b',{assetSource:'manual'})],undefined,threats);
 const row=r.priorityWorklist.byCve[0];assert.equal(row.urgency,1);assert.equal(row.kev,true);assert.equal(row.active,true);assert.equal(row.epss,0.8);
 assert.equal(row.exposedDevices,1);assert.equal(row.criticalDevices,1);assert.deepEqual(row.owners,['Patch team']);assert.equal(row.unassignedFindings,1);
 assert.equal(row.dueAt,'2026-10-21T00:00:00.000Z');assert.equal(row.lastObserved,'2026-10-20T00:00:00.000Z');
});

test('incomplete evidence never gives an apparently safe routine priority',async()=>{
 const r=await buildTopFixes(company,[f('unknown',{severity:'Low',cvss:2,kev:false,exploitAvailable:false})]);
 const row=r.priorityWorklist.byCve[0];assert.notEqual(row.urgency,4);assert.ok(row.gaps.length);
});

test('missing asset identity is incomplete, never an exact zero or safe routine tier',async()=>{
 const threats=new Map([['CVE-2026-1000',{kev:false,active:false,epss:0,updatedAt:'2026-10-21T00:00:00Z'}]]);
 const r=await buildTopFixes(company,[f('missing',{asset:'',assetSource:'manual',severity:'Low',cvss:2})],undefined,threats);
 const row=r.priorityWorklist.byCve[0];assert.equal(row.urgency,3);assert.equal(row.deviceCountIsLowerBound,true);
 assert.equal(row.exposedDevices,null);assert.equal(row.criticalDevices,null);assert.ok(row.gaps.includes('Device identity missing'));
});

test('cross-source CVE counts are explicit lower bounds and preserve the stronger threat signal',async()=>{
 const {combinePriorityWorklists}=modules.get(resolve('lib/patch-priority.ts')).namespace;
 const a=(await buildTopFixes(company,[f('one')])).priorityWorklist;
 const b=structuredClone(a);b.byCve[0].source='crowdstrike';b.byCve[0].sources=['crowdstrike'];b.byCve[0].deviceCount=4;
 b.byCve[0].findingCount=4;b.byCve[0].urgency=1;b.byCve[0].kev=true;b.byCve[0].reasons=['CISA KEV recorded'];
 const row=combinePriorityWorklists([a,b]).byCve[0];assert.equal(row.deviceCount,4);assert.equal(row.deviceCountIsLowerBound,true);
 assert.equal(row.urgency,1);assert.equal(row.kev,true);assert.equal(row.findingCount,5);
});

test('existing worklist path does not build optional priority metadata',async()=>{
 const r=await mod.namespace.buildTopFixes(company,[f('a')]);assert.equal(r.priorityWorklist,undefined);assert.equal(r.rows.length,1);
});

test('large platform fix populations retain all counts and select the best 50 before formatting device evidence',async()=>{
 const {createPriorityWorklist}=modules.get(resolve('lib/patch-priority.ts')).namespace,acc=createPriorityWorklist('platform');
 const input={severity:'High',cvss:7.5,cvssSource:'fixture',kev:false,active:false,publicExploit:false,epss:0,exposed:null,critical:null,products:[],remediation:'Update'};
 for(let i=0;i<120000;i++)acc.addFix('fix'+i,'CVE-2026-1000','host',input);
 acc.addFix('urgent','CVE-2026-2000','host',{...input,kev:true});const result=acc.finish();
 assert.equal(result.totalRemediations,120001);assert.equal(result.byRemediation.length,50);assert.equal(result.byRemediation[0].id,'urgent');
 assert.equal(result.byRemediation[0].exposedDevices,null);
});
