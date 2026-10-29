import assert from 'node:assert/strict';
import test from 'node:test';
import {readFile} from 'node:fs/promises';
import {resolve,dirname} from 'node:path';
import {SourceTextModule,SyntheticModule} from 'node:vm';
import * as React from 'react';
import * as jsx from 'react/jsx-runtime';
import {renderToStaticMarkup} from 'react-dom/server';
import ts from 'typescript';
const synthetic=v=>new SyntheticModule(Object.keys(v),function(){for(const[k,x]of Object.entries(v))this.setExport(k,x);});
const cache=new Map();
async function load(path){
 path=resolve(path);if(cache.has(path))return cache.get(path);
 const mod=new SourceTextModule(ts.transpileModule(await readFile(path,'utf8'),{compilerOptions:{jsx:ts.JsxEmit.ReactJSX,target:ts.ScriptTarget.ES2022,module:ts.ModuleKind.ESNext}}).outputText,{identifier:path});cache.set(path,mod);
 await mod.link(spec=>{
  if(spec==='react/jsx-runtime')return synthetic(jsx);
  if(spec==='next/link')return synthetic({default:({children,...props})=>React.createElement('a',props,children)});
  if(spec.endsWith('CveText'))return synthetic({default:({text})=>React.createElement('span',null,text),cveIdentifier:()=>true});
  if(spec.endsWith('customer-cve-context'))return synthetic({useCustomerCve:()=>()=>{}});
  if(spec.endsWith('.css'))return synthetic({default:{}});
  return load(resolve(dirname(path),spec+'.tsx'));
 });return mod;
}
const mod=await load('components/reporting/CustomerReportSections.tsx');await mod.evaluate();
const baseline={company:{id:'A',name:'Atlas'},metrics:{vulnerabilities:{open:80000,critical:887,kev:2,bySeverity:{Critical:887}},attackSurface:{open:302},webTesting:{open:0}},assessmentState:'assessed',sourceActivity:[{source:'crowdstrike',evidence:'scan',scanCount:1,openObservations:80000,runningCount:1,completedCount:0,failedCount:0,lastObservedAt:'2026-10-29T05:11:35Z'}],assets:{inventoryCount:1549,authoritativeFindingCount:123,contextCoveragePercent:68},history:[],legacyHistory:[],priorityRows:[],priorityTotal:80000,recentScans:[],scanTotal:1,attackSurfaceRows:[],webTestingRows:[]};
const current={companyId:'A',source:'crowdstrike',state:'available',generation:{completedAt:'2026-10-29T18:17:56.539Z',freshness:'within-window'},latestAttempt:{status:'succeeded'},summary:{sourceInstances:2500239,uniqueCves:14192,affectedDevices:1502,deviceCveFindings:2487702,unknownSuppressionInstances:0,excludedSuppressedInstances:15,excludedNonCveInstances:2,severity:{sourceInstances:{CRITICAL:75000,HIGH:2425239,MEDIUM:0,LOW:0,NONE:0,UNKNOWN:0},deviceCveFindings:{CRITICAL:74000,HIGH:2413702,MEDIUM:0,LOW:0,NONE:0,UNKNOWN:0}}},cves:{total:14192,rows:[{cve:'CVE-2026-1000',severity:'CRITICAL',cvss:9.8,affectedDevices:824,sourceInstances:900}]}};
const render=source=>renderToStaticMarkup(React.createElement(mod.namespace.default,{model:{...baseline,crowdstrikeReport:source}}));
test('overview uses completed source counts, chart and CVEs; old subset is explicitly separate',()=>{
 const html=render(current),main=html.replace(/<details[\s\S]*?<\/details>/g,'');
 assert.match(main,/<dt[^>]*>Open CrowdStrike findings<\/dt><dd[^>]*>2,487,702<\/dd>/);assert.match(main,/2,500,239 source instances/);assert.match(main,/14,192/);assert.match(main,/1,502/);assert.match(main,/CVE-2026-1000/);
 assert.match(main,/<dt[^>]*>Critical open<\/dt><dd[^>]*>74,000<\/dd>/);assert.match(main,/2,413,702/);assert.doesNotMatch(main,/75,000|2,425,239/);assert.doesNotMatch(main,/80,000|887|Latest recorded source observation/);
 assert.match(main,/2026-10-29T18:17:56.539Z/);assert.match(html,/<details/);assert.match(html,/Historical platform snapshot/);
});
test('missing completed summary is unavailable, never old totals or an invented zero',()=>{
 for(const state of ['summary-pending','inconsistent','no-completed-import','unavailable']){
  const main=render({state,message:'Unavailable'}).replace(/<details[\s\S]*?<\/details>/g,'');
  assert.doesNotMatch(main,/80,000|887|>0</);assert.match(main,/unavailable|waiting|Unavailable/i);
 }
});
test('real completed zero and unknown severity remain distinct; no CS preserves existing report',()=>{
 assert.match(render({...current,summary:{...current.summary,sourceInstances:0,deviceCveFindings:0,uniqueCves:0,affectedDevices:0,severity:{sourceInstances:{UNKNOWN:0,NONE:0},deviceCveFindings:{CRITICAL:0,HIGH:0,MEDIUM:0,LOW:0,NONE:0,UNKNOWN:0}}},cves:{rows:[],total:0}}),/No open CVEs/);
 assert.match(render(null),/80,000/);assert.doesNotMatch(render(null),/Historical platform snapshot/);
 assert.match(render({...current,summary:{...current.summary,severity:{sourceInstances:{UNKNOWN:2,NONE:1}}}}),/Unknown/);
});

test('missing deduplicated severity never falls back to instance counts or an invented critical zero',()=>{
 const summary={...current.summary,severity:{sourceInstances:current.summary.severity.sourceInstances}};
 const main=render({...current,summary}).replace(/<details[\s\S]*?<\/details>/g,'');
 assert.match(main,/<dt[^>]*>Critical open<\/dt><dd[^>]*>Unavailable<\/dd>/);
 assert.match(main,/Severity breakdown is unavailable/);assert.doesNotMatch(main,/75,000|2,425,239/);
});
