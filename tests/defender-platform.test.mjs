// node --experimental-vm-modules --test tests/finding-correlation.test.mjs
//
// Exercises the cross-connector correlation logic in lib/store.ts: the same
// (company, CVE, asset) reported by more than one scanner must merge into
// one finding — never duplicated, never silently dropped, never merged
// across companies. This is the exact behavior a real MSSP customer's data
// depends on for correct severity counts and non-duplicated patch tickets.
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { resolve, dirname } from "node:path";
import { SourceTextModule, SyntheticModule } from "node:vm";
import test from "node:test";
import ts from "typescript";

const ROOT=resolve("."),modules=new Map();
async function getModule(path) {
 path=resolve(path);
 if(modules.has(path))return modules.get(path);
 const promise=(async()=>new SourceTextModule(ts.transpileModule(await readFile(path,"utf8"),{compilerOptions:{target:ts.ScriptTarget.ES2022,module:ts.ModuleKind.ESNext}}).outputText,{identifier:path}))();
 modules.set(path,promise);return promise;
}
async function linker(name,parent) {
 if(name.startsWith("."))return getModule(resolve(dirname(parent.identifier),`${name}.ts`));
 if(name.startsWith("@/"))return getModule(resolve(ROOT,`${name.slice(2)}.ts`));
 const imported=await import(name),values=name === "rrule"?{...imported.default,...imported}:imported;
 return new SyntheticModule(Object.keys(values),function(){for(const k of Object.keys(values))this.setExport(k,values[k]);});
}
async function load(path) { const m=await getModule(path);if(m.status === "unlinked")await m.link(linker);return m; }
const storeModule = await load("lib/store.ts"); await storeModule.evaluate();
const store = storeModule.namespace;
const projectionModule = await load("lib/defender-projection.ts"); await projectionModule.evaluate();
const { planDefenderProjection } = projectionModule.namespace;
const reportModule = await load("lib/reporting-customer-model.ts"); await reportModule.evaluate();
const groupModule = await load("lib/reporting-consolidation.ts"); await groupModule.evaluate();
const configModule = await load("lib/defender-config.ts"); await configModule.evaluate();
const verificationModule = await load("lib/defender-verification.ts"); await verificationModule.evaluate();
const { assessDefenderPatch } = verificationModule.namespace;
const company = {id:"CO-TEST",name:"Example Customer",kind:"client",industry:"Test",createdAt:"2026-10-01T00:00:00Z",contactName:"",contactEmail:""};
const observedAt = "2026-10-07T12:00:00Z";
const device = (id="d1",hostname="host1")=>({deviceId:id,hostname,os:"Windows 11",ip:"10.0.0.1",lastSeen:observedAt});
const finding = (deviceId="d1",hostname="host1",cve="CVE-2026-12345")=>({deviceId,hostname,cve,severity:"CRITICAL",cvss:9.8,firstSeen:"2026-10-01T00:00:00Z",lastSeen:observedAt,remediation:"Browser 1: install KB123",exploitAvailable:true});
const snapshot = (overrides={})=>({companyId:company.id,runId:"run1",observedAt,devices:[device()],findings:[finding()],...overrides});
const plan = (snap=snapshot(),findings=[],assets=[])=>planDefenderProjection(snap,company.name,findings,assets,()=>({realRisk:75,riskPriority:"High"}));
const one = changes=>[...changes.findings.values()][0];
function fixture() {
 return {companies:new Map([[company.id,company]]),folders:new Map(),scans:new Map(),findings:new Map(),assets:new Map(),
 compensatingControls:new Map(),identityAliases:new Map(),settings:{autoScanNewAssets:false,schedule:{autoSyncEnabled:false,alertsEnabled:false,monthlyReportsEnabled:false},sla:{Critical:7,High:30,Medium:60,Low:90}},meta:{defenderGenerations:{}},seeded:true,counter:1000};
}
test("Defender publication feeds shared findings, inventory, metrics, executive report and patch packets",async()=>{
 globalThis.__vulnStore=fixture();
 store.publishDefenderSnapshot(snapshot());
 assert.equal(store.listFindings({companyId:company.id}).length,1);
 assert.equal(store.listAssets({companyId:company.id}).length,1);
 assert.equal(store.computeExecReport(company.id).findings.critical,1);
 assert.ok(store.computeExecReport(company.id).topRisks.some(f=>f.cve === "CVE-2026-12345"));
 const findings=store.listFindings(),scans=await store.listScans({companyId:company.id}),assets=store.listAssets();
 const report=reportModule.namespace.buildCustomerReportingModel(company,findings,scans,assets,[]);
 assert.equal(report.assessmentState,"assessed");assert.equal(report.metrics.vulnerabilities.open,1);
 assert.ok(report.sourceActivity.some(r=>r.source === "defender"));
 const groups=groupModule.namespace.buildStoredFindingGroups(company,findings);
 assert.equal(groups.length,1);assert.equal(groups[0].source,"stored-findings");assert.deepEqual(groups[0].connectors,["defender"]);
 assert.match(groups[0].csv,/host1/);assert.match(groups[0].csv,/KB123/);assert.match(groups[0].ticketBody,/KB123/);
 assert.doesNotMatch(groups[0].ticketBody,/host1/);
 store.publishDefenderSnapshot(snapshot());assert.equal(store.listFindings().length,1);
 assert.equal(store.defenderProjectedRun(company.id),"run1");
 assert.throws(()=>store.publishDefenderSnapshot(snapshot({companyId:"other"})),/no longer exists/);
});
test("device identity survives rename, same names and shared IP do not collapse devices or customers",()=>{
 const first=plan(snapshot({devices:[device("d1","same"),device("d2","same")],findings:[finding("d1","same"),finding("d2","same")]}));
 assert.equal(first.findings.size,2);assert.equal(first.assets.size,2);
 const lookupStore=fixture();lookupStore.assets=first.assets;
 assert.equal(store.lookupAsset(lookupStore,"same",company.id),undefined);
 assert.equal(store.lookupAsset(lookupStore,"10.0.0.1",company.id),undefined);
 assert.ok(store.lookupAsset(lookupStore,"defender:d1",company.id));
 const renamed=plan(snapshot({runId:"run2",devices:[device("d1","renamed"),device("d2","same")],findings:[finding("d1","renamed"),finding("d2","same")]}),[...first.findings.values()],[...first.assets.values()]);
 assert.deepEqual([...renamed.findings.keys()].sort(),[...first.findings.keys()].sort());
 assert.deepEqual([...renamed.assets.keys()].sort(),[...first.assets.keys()].sort());
 const other=plan(snapshot({companyId:"OTHER"}),[...first.findings.values()],[...first.assets.values()]);
 assert.notEqual(one(other).id,one(first).id);
});
test("new generations preserve analyst decisions; confirmed absence resolves, reappearance reopens",()=>{
 const first=plan();const f=one(first);f.assignee="analyst";f.status="In Remediation";
 const next=snapshot({runId:"run2",observedAt:"2026-10-08T12:00:00Z",devices:[{...device(),lastSeen:"2026-10-08T11:00:00Z"}],findings:[]});
 const closed=one(plan(next,[f],[...first.assets.values()]));assert.equal(closed.status,"Resolved");assert.equal(closed.defender.active,false);
 const stillClosed=one(plan({...next,runId:"run-later",observedAt:"2026-10-09T12:00:00Z",devices:[{...device(),lastSeen:"2026-10-09T11:00:00Z"}]},[closed],[...first.assets.values()]));assert.equal(stillClosed.defender.runId,"run-later");assert.equal(stillClosed.status,"Resolved");
 const reopened=one(plan(snapshot({runId:"run3"}),[closed],[...first.assets.values()]));assert.equal(reopened.id,f.id);assert.equal(reopened.status,"Open");assert.equal(reopened.assignee,"analyst");
 const accepted={...f,status:"Risk Accepted"};assert.equal(one(plan(snapshot({runId:"run4"}),[accepted],[...first.assets.values()])).status,"Risk Accepted");
});
test("missing or stale devices never supply patch closure evidence",()=>{
 const first=plan(),f=one(first);
 assert.equal(plan(snapshot({runId:"run2",devices:[],findings:[]}),[f],[...first.assets.values()]).findings.size,0);
 assert.equal(plan(snapshot({runId:"run2",devices:[{...device(),lastSeen:"2026-10-01T00:00:00Z"}],findings:[]}),[f],[...first.assets.values()]).findings.size,0);
 assert.equal(plan(snapshot({runId:"run2",devices:[{...device(),lastSeen:"invalid timestamp"}],findings:[]}),[f],[...first.assets.values()]).findings.size,0);
});
test("existing inventory and Nessus corroboration are reused; Defender cannot close another source",()=>{
 const first=plan(),asset={...[...first.assets.values()][0],id:"INVENTORY-1",identifier:"host1",source:"manual",defenderDeviceId:undefined,criticality:"Crown Jewel"};
 const nessus={...one(first),id:"NESSUS-1",connector:"nessus",seenBy:["nessus"],asset:"host1",defender:undefined,remediation:"Nessus vendor fix"};
 const second=plan(snapshot(),[nessus],[asset]);assert.equal(second.assets.size,1);assert.equal([...second.assets.keys()][0],"INVENTORY-1");
 assert.equal(one(second).id,"NESSUS-1");assert.deepEqual(one(second).seenBy,["nessus","defender"]);
 const cleared=one(plan(snapshot({runId:"run2",findings:[],devices:[{...device(),lastSeen:"2026-10-08T00:00:00Z"}]}),[one(second)],[...second.assets.values()]));
 assert.equal(cleared.status,"Open");assert.deepEqual(cleared.seenBy,["nessus"]);
 const again=one(plan(snapshot({runId:"run3"}),[one(second)],[...second.assets.values()]));assert.match(again.remediation,/Nessus vendor fix/);
});
test("server config resolves explicit existing name or ID and rejects ambiguous customers",()=>{
 const {defenderEnvironment,resolveDefenderCustomer}=configModule.namespace;
 assert.equal(resolveDefenderCustomer(company.name,[company]),company.id);assert.equal(resolveDefenderCustomer(company.id,[company]),company.id);
 assert.throws(()=>resolveDefenderCustomer("Example",[company]),/one existing customer/);
 assert.throws(()=>resolveDefenderCustomer(company.name,[company,{...company,id:"another"}]),/one existing customer/);
 assert.deepEqual(defenderEnvironment({}),[]);
 assert.throws(()=>defenderEnvironment({DEFENDER_TENANT_ID:"invalid"}),/CUSTOMER/);
 const configs=defenderEnvironment({DEFENDER_TENANT_ID:"00000000-0000-0000-0000-000000000001",DEFENDER_CLIENT_ID:"00000000-0000-0000-0000-000000000002",DEFENDER_CLIENT_SECRET:"fake",DEFENDER_CUSTOMER:company.name});
 assert.equal(configs.length,1);assert.equal(configs[0].daily,true);
});
test("patch verification requires complete fresh source evidence and is device-scoped",()=>{
 const first=plan(),f=one(first),packet=groupModule.namespace.buildStoredFindingGroups(company,[f])[0];
 const time=Date.parse(observedAt)+1000,created="2026-10-06T12:00:00Z";
 assert.equal(assessDefenderPatch(packet,[f],"run1",observedAt,created,time).state,"still_open");
 const closed={...f,status:"Resolved",defender:{...f.defender,active:false}};
 assert.equal(assessDefenderPatch(packet,[closed],"run1",observedAt,created,time).state,"verified");
 for(const rows of [[],[{...closed,companyId:"OTHER"}],[{...closed,defender:{...closed.defender,runId:"old"}}]]) assert.throws(()=>assessDefenderPatch(packet,rows,"run1",observedAt,created,time),/fresh evidence/);
 assert.throws(()=>assessDefenderPatch(packet,[closed],"run1",observedAt,created,time+172800000),/24 hours/);
 assert.throws(()=>assessDefenderPatch({...packet,connectors:["defender","nessus"]},[closed],"run1",observedAt,created,time),/all of its source scanners/);
});
