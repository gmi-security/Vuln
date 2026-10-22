import assert from 'node:assert/strict';
import test from 'node:test';
import {readFileSync} from 'node:fs';
import {SourceTextModule} from 'node:vm';
import ts from 'typescript';

const mod=new SourceTextModule(ts.transpileModule(readFileSync('lib/patch-worklist-filters.ts','utf8'),{
  compilerOptions:{target:ts.ScriptTarget.ES2022,module:ts.ModuleKind.ESNext},
}).outputText);
await mod.link(()=>{throw Error('Filters must not load server dependencies');});await mod.evaluate();
const filter=mod.namespace.filterPatchWorklist;
const defaults={search:'',severity:'all',signal:'all',ticket:'all'};
const rows=[
  {id:'urgent',cves:['CVE-2026-1000'],products:['Windows 11'],remediation:'Install KB100',severity:'Critical',kev:true,active:null,publicExploit:false,ticketStatus:{state:'partial'}},
  {id:'public',cves:['CVE-2026-2000'],products:['Firefox'],remediation:'Update browser',severity:'HIGH',kev:false,active:false,publicExploit:true,ticketStatus:{state:'open'}},
  {id:'unknown',cves:['CVE-2026-3000'],products:[],remediation:'',severity:'Unknown',kev:null,active:null,publicExploit:null},
  {id:'draft',cves:['CVE-2026-1000','CVE-2026-4000'],products:['Windows 10'],remediation:'Install KB400',severity:'Critical',kev:true,active:true,publicExploit:false,ticketStatus:{state:'draft'}},
];
test('filters preserve the server rank and input records',()=>{
  assert.deepEqual(filter(rows,defaults),rows);
  assert.deepEqual(filter(rows,{...defaults,search:'  WINDOWS ',severity:'CRITICAL',signal:'kev'}).map(r=>r.id),['urgent','draft']);
  assert.equal(filter(rows,defaults)[0],rows[0]);
});
test('search matches CVEs, products and recorded fixes without using hidden customer data',()=>{
  assert.deepEqual(filter(rows,{...defaults,search:'cve-2026-4000'}).map(r=>r.id),['draft']);
  assert.deepEqual(filter(rows,{...defaults,search:'kb100'}).map(r=>r.id),['urgent']);
  assert.deepEqual(filter(rows,{...defaults,search:'other customer'}),[]);
});
test('unknown signals and unavailable ticket coverage never become known negatives or unticketed work',()=>{
  assert.deepEqual(filter(rows,{...defaults,signal:'active'}).map(r=>r.id),['draft']);
  assert.deepEqual(filter(rows,{...defaults,signal:'publicExploit'}).map(r=>r.id),['public']);
  assert.deepEqual(filter(rows,{...defaults,ticket:'none'}),[]);
  assert.deepEqual(filter(rows,{...defaults,ticket:'unavailable'}).map(r=>r.id),['unknown']);
  assert.deepEqual(filter(rows,{...defaults,ticket:'partial'}).map(r=>r.id),['urgent']);
});
