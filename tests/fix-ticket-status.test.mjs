import assert from 'node:assert/strict';
import test from 'node:test';
import {readFileSync} from 'node:fs';
import {resolve,dirname} from 'node:path';
import {SourceTextModule,SyntheticModule} from 'node:vm';
import ts from 'typescript';
async function load(entry){
 const cache=new Map();function read(path){path=resolve(path);if(cache.has(path))return cache.get(path);const m=new SourceTextModule(ts.transpileModule(readFileSync(path,'utf8'),{compilerOptions:{target:ts.ScriptTarget.ES2022,module:ts.ModuleKind.ESNext}}).outputText,{identifier:path});cache.set(path,m);return m;}
 const m=read(entry);await m.link(async(spec,parent)=>{if(spec.startsWith('.'))return read(resolve(dirname(parent.identifier),spec+'.ts'));const value=await import(spec);return new SyntheticModule(Object.keys(value),function(){for(const k of Object.keys(value))this.setExport(k,value[k]);});});await m.evaluate();return m.namespace;
}
const api=await load('lib/fix-ticket-status.ts');
const company='CO-A',cid='a'.repeat(32),cves=['CVE-2026-1234','CVE-2026-2345'];
const action={id:'vendor',title:'Update framework',action:'Install KB1',reference:'KB1',link:'',vendorUrl:'',published:''};
const {remediationVariantId}=await load('lib/patch-recommendations.ts');
const variant=remediationVariantId(action),actionId=`crowdstrike:${cid}:${variant}`;
const row={id:actionId,source:'crowdstrike',grouping:'vendor-remediation',cves,deviceCount:2,findingCount:3,remediation:action.action};
const coverage={cves,hosts:[{cid,hostId:'h1',bits:'Aw=='},{cid,hostId:'h2',bits:'AQ=='}]};
const ticket=(changes={})=>({id:'request-1',companyId:company,tenantId:cid,remediationId:'manual:'+variant,vendorRemediationId:action.id,...action,
 // The request identity must not be overwritten by the vendor action ID.
 id:'request-1',cves,source:'stored-findings',connectors:['crowdstrike'],state:'created',reviewState:'approved',ticketId:101,ticketUrl:'https://tickets.example/101',closed:false,...changes});
const evidence={id:actionId,coverage,findingCount:3};
function status(tickets,scopes=[{id:'request-1',coverage}],current=evidence,r=row){return api.fixTicketStatus(company,r,tickets,scopes,current);}

test('open ticket coverage is exact device/CVE membership, not a Cartesian product',()=>{
 const result=status([ticket()]);assert.equal(result.state,'open');assert.deepEqual(result.coverage,{coveredDevices:2,remainingDevices:0,totalDevices:2});assert.equal(result.tickets[0].ticketId,101);
 const partial=status([ticket()],[{id:'request-1',coverage:{cves,hosts:[{cid,hostId:'h1',bits:'AQ=='}]}}]);
 assert.equal(partial.state,'partial');assert.deepEqual(partial.coverage,{coveredDevices:0,remainingDevices:2,totalDevices:2});
 const union=status([ticket(),ticket({id:'request-2',ticketId:102})],[{id:'request-1',coverage:{cves,hosts:[{cid,hostId:'h1',bits:'AQ=='}]}},{id:'request-2',devices:[{cid,hostId:'h1',cve:cves[1]},{cid,hostId:'h2',cve:cves[0]}]}]);
 assert.equal(union.coverage.coveredDevices,2);
});
test('same CVE with a different action, tenant or customer never establishes coverage',()=>{
 assert.equal(status([ticket({kind:'single'})]).state,'related');
 for(const change of [{action:'Install KB2',remediationId:'manual:other'},{tenantId:'b'.repeat(32)}]){
  const result=status([ticket(change)]);assert.equal(result.state,'related');assert.equal(result.coverage,undefined);assert.equal(result.tickets[0].sameFix,false);
 }
 assert.equal(status([ticket({companyId:'CO-B'})]).state,'none');
 const top={...row,id:'crowdstrike:'+cves[0]+':vendor',cve:cves[0],grouping:undefined};
 assert.equal(status([ticket()],[],undefined,top).state,'related','legacy CVE/vendor groups can mix action versions');
});
test('approved drafts, sending, uncertain outcomes, failed and closed tickets have distinct states',()=>{
 for(const [changes,state] of [[{ticketId:null,state:'prepared',reviewState:'pending'},'draft'],[{ticketId:null,state:'prepared'},'approved'],[{ticketId:null,state:'creating'},'sending'],[{ticketId:null,state:'uncertain'},'uncertain'],[{ticketId:null,state:'failed'},'failed'],[{closed:true},'closed']]){
  const result=status([ticket(changes)]);assert.equal(result.state,state);assert.equal(result.coverage,undefined);
 }
 assert.equal(status([ticket({state:'prepared',ticketId:null,reviewState:'dismissed'})]).state,'none');
});
test('missing, changed, malformed or over-budget evidence never claims complete coverage',()=>{
 for(const current of [null,{...evidence,findingCount:9},{...evidence,coverage:{...coverage,hosts:coverage.hosts.slice(0,1)}}])assert.equal(status([ticket()],[],current).coverage,undefined);
 assert.equal(status([ticket()],[{id:'request-1',coverage:{cves,hosts:[{cid,hostId:'h1',bits:'???'}]}}]).coverage,undefined);
 const wrong=coverage.hosts.map(h=>({...h,cid:'other'}));assert.equal(status([ticket()],[],{...evidence,coverage:{...coverage,hosts:wrong}}).coverage,undefined);
});
test('platform rows match exact CVE and normalized remediation, with coverage left unverified',async()=>{
 const {createHash}=await import('node:crypto');
 const id=createHash('sha256').update(`${company}\0${JSON.stringify([cves[0],'install kb1'])}`).digest('hex').slice(0,32);
 const result=status([ticket({tenantId:company,connectors:['defender'],cves:[cves[0]]})],[],null,{...row,id,source:'platform',cve:cves[0],cves:undefined});
 assert.equal(result.state,'open');assert.equal(result.coverage,undefined);assert.equal(result.tickets[0].sameFix,true);
});
test('comparison budget and unsafe links never produce false complete coverage or executable URLs',()=>{
 const many=Array.from({length:1001},(_,i)=>`CVE-2026-${10000+i}`),bits=Buffer.alloc(Math.ceil(many.length/8),255);bits[bits.length-1]=1;
 const cov={cves:many,hosts:Array.from({length:1000},(_,i)=>({cid,hostId:'host-'+i,bits:bits.toString('base64')}))};
 const current={id:actionId,coverage:cov,findingCount:1001000},r={...row,cves:many,deviceCount:1000,findingCount:1001000};
 const result=status([ticket({cves:many,ticketUrl:'javascript:alert(1)'})],[{id:'request-1',coverage:cov}],current,r);
 assert.equal(result.state,'open');assert.equal(result.coverage,undefined);assert.equal(result.tickets[0].url,undefined);
});
test('lookup failure preserves findings and explicitly reports unknown status',async()=>{
 const {withFixTicketStatus}=await load('lib/customer-fix-ticket-status.ts');
 const result={companyId:company,rows:[row],remediationWorklist:{rows:[row]}};
 const before=JSON.stringify(result),bad={connect:async()=>{throw Error('database unavailable');}};
 const output=await withFixTicketStatus(bad,result,'run',()=>bad);assert.equal(JSON.stringify(result),before);
 assert.equal(output.rows[0].ticketStatus.state,'unavailable');assert.equal(output.remediationWorklist.rows[0].ticketStatus.state,'unavailable');
});
