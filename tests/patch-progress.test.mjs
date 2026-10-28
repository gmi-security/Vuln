import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {resolve,dirname} from 'node:path';
import {SourceTextModule,SyntheticModule} from 'node:vm';
import ts from 'typescript';
async function load(entry){const cache=new Map();function read(path){path=resolve(path);if(cache.has(path))return cache.get(path);const m=new SourceTextModule(ts.transpileModule(readFileSync(path,'utf8'),{compilerOptions:{target:ts.ScriptTarget.ES2022,module:ts.ModuleKind.ESNext}}).outputText,{identifier:path});cache.set(path,m);return m;}const m=read(entry);await m.link(async(s,p)=>{if(s.startsWith('.'))return read(resolve(dirname(p.identifier),s+'.ts'));const v=await import(s);return new SyntheticModule(Object.keys(v),function(){for(const k of Object.keys(v))this.setExport(k,v[k]);});});await m.evaluate();return m.namespace;}
const api=await load('lib/patch-progress.ts');
const cve='CVE-2026-100202',other='CVE-2026-100203',cid='a'.repeat(32);
const ticket=(packet={})=>({id:'t',kind:'group',companyId:'CO-A',ticketId:123,hostCount:2,createdAt:'2026-10-20T00:00:00Z',scopeHash:'hash',packet:{appCompanyId:'CO-A',source:'stored-findings',connectors:['defender'],reviewRows:[{asset:'a',cve,findingId:'f1'},{asset:'b',cve,findingId:'f2'}],...packet}});
test('original platform scope preserves required sources and rejects partial or foreign baselines',()=>{
 const s=api.progressScope(ticket());assert.equal(s.pairs.length,2);assert.equal(s.error,undefined);
 assert.match(api.progressScope(ticket({appCompanyId:'CO-B'})).error,/customer/i);
 assert.match(api.progressScope({...ticket(),hostCount:3}).error,/complete/i);
 const mixed=api.progressScope(ticket({connectors:['defender','nessus']}));assert.equal(mixed.pairs.length,4);
});
test('compact CrowdStrike coverage never invents a host by CVE cross product',()=>{
 const s=api.progressScope(ticket({connectors:['crowdstrike'],tenantId:cid,cves:[cve,other],hostScope:[JSON.stringify([cid,'a']),JSON.stringify([cid,'b'])],deviceCveCoverage:{cves:[cve,other],hosts:[{cid,hostId:'a',bits:'Aw=='},{cid,hostId:'b',bits:'AQ=='}]}}));
 assert.equal(s.pairs.length,3);assert.equal(s.pairs.filter(p=>p.hostId==='b'&&p.cve===other).length,0);
});
test('only later completed covered evidence verifies absence; ticket status has no role',()=>{
 const p=api.progressScope(ticket()).pairs[0],base='2026-10-20T00:00:00Z';
 const ev={complete:true,scopeMatches:true,assessmentAt:'2026-10-21T00:00:00Z',generation:'r',present:false,covered:true};
 assert.equal(api.assessProgress(p,base,ev).state,'clear');
 for(const change of [{complete:false},{scopeMatches:false},{covered:false},{assessmentAt:base},{assessmentAt:null},{suppressed:true}])assert.equal(api.assessProgress(p,base,{...ev,...change}).state,'unknown');
 assert.equal(api.assessProgress(p,base,{...ev,present:true}).state,'detected');
 assert.equal(api.assessProgress(p,base,null).state,'unknown');
});
test('all original CVEs and sources must clear per device; reappearance is retained',()=>{
 const s=api.progressScope(ticket());const a=s.pairs[0],b=s.pairs[1];
 const row=(p,state)=>({...p,state,reason:'test',assessmentAt:'2026-10-21',generation:'r'});
 let rows=[row(a,'clear'),row({...a,key:a.key+'2',cve:other},'unknown'),row(b,'clear')];
 assert.deepEqual(api.summarizeProgress(rows),{devices:2,detected:0,clear:1,unknown:1,reappeared:0,pairs:3});
 rows=[row(a,'detected'),row(b,'clear')];api.markReappearances(rows,new Set([a.key]));
 assert.equal(api.summarizeProgress(rows).reappeared,1);
 rows.push(row({...a,key:a.key+'2',source:'nessus'},'unknown'));assert.equal(api.summarizeProgress(rows).detected,1);
});
test('single CVE tickets accept exact host lists and invalid dates never become verified',()=>{
 const t={...ticket(),kind:'single',packet:{appCompanyId:'CO-A',cve,hostScope:[JSON.stringify([cid,'a']),JSON.stringify([cid,'b'])]}};
 assert.equal(api.progressScope(t).pairs.length,2);
 assert.match(api.progressScope({...t,createdAt:'bad'}).error,/creation/i);
});
test('CrowdStrike disappearance is a fix only after a complete later import with matching scope',()=>{
 const p={...api.progressScope(ticket()).pairs[0],source:'crowdstrike'},base='2026-10-20T00:00:00Z';
 const evidence={complete:true,scopeMatches:true,assessmentAt:'2026-10-21T00:00:00Z',generation:'cs-run',present:false,covered:false,absenceIsFix:true};
 assert.equal(api.assessProgress(p,base,evidence).state,'clear');
 assert.match(api.assessProgress(p,base,evidence).reason,/no longer reported/i);
 for(const change of [{complete:false},{scopeMatches:false},{assessmentAt:base},{suppressed:true}])assert.equal(api.assessProgress(p,base,{...evidence,...change}).state,'unknown');
 assert.equal(api.assessProgress({...p,source:'nessus'},base,evidence).state,'unknown');
});
