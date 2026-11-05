// node --experimental-vm-modules --test tests/external-scan-plan.test.mjs
import test from "node:test";
import assert from "node:assert/strict";
import ts from "typescript";
import {readFile} from "node:fs/promises";
import {SourceTextModule,SyntheticModule} from "node:vm";

const src=await readFile("lib/external-scan-plan.ts","utf8");
const js=ts.transpileModule(src,{compilerOptions:{
  target:ts.ScriptTarget.ES2022,module:ts.ModuleKind.ESNext
}}).outputText;
const keys=value=>{
  if(typeof value!=="string"||!value||value.includes("/")||
     value.includes("*")||value.includes("://")||value.includes(" "))
    throw Error("Invalid exact target");
  return value.toLowerCase().replace(/\.$/,"");
};
const ip4=s=>/^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$/.test(s)&&
  s.split(".").every(n=>Number(n)<=255)
    ?s.split(".").reduce((v,n)=>v*256+Number(n),0):null;
const matcher=targets=>{
  if(!Array.isArray(targets)||!targets.length||targets.length>100)
    throw Error("Invalid Nessus reviewed scope");
  const rules=targets.map(t=>{
    const m=t.match(/^((?:[0-9]{1,3}\.){3}[0-9]{1,3})\/([0-9]|[12][0-9]|3[0-2])$/);
    if(!m)return {exact:keys(t)};
    const n=ip4(m[1]),size=2**(32-Number(m[2]));
    if(n===null)throw Error("Invalid network");
    return {low:Math.floor(n/size)*size,size};
  });
  return host=>rules.some(r=>{
    if(r.exact!==undefined)return r.exact===keys(host);
    const n=ip4(host);
    return n!==null&&n>=r.low&&n<r.low+r.size;
  });
};
const module=new SourceTextModule(js);
await module.link(async name=>{
  assert.equal(name,"./scanner-target-scope");
  return new SyntheticModule(["scannerExactTargetKey","scannerTargetMatcher"],function(){
    this.setExport("scannerExactTargetKey",keys);
    this.setExport("scannerTargetMatcher",matcher);
  });
});
await module.evaluate();
const {buildExternalScanPlan:plan}=module.namespace;

const scan=(id=11,at="2026-11-04T01:00:00Z")=>({
  nessusScanId:id,scanName:"Nessus "+id,enabled:true,
  nextOccurrence:at,
  offsetNextTrigger:new Date(Date.parse(at)+3600_000).toISOString()
});
const matrix=(scans=[scan()])=>({
  generatedAt:"2026-11-03T20:00:00Z",
  companies:[{companyId:"CO-A",companyName:"Customer A",scans}]
});
const v=(targets=["alpha.example"])=>({
  companyId:"CO-A",provider:"vulners",targets
});
const n=(targets=["alpha.example"],folder="7")=>({
  companyId:"CO-A",provider:"nessus",sourceScope:folder,targets
});
const d=(id=11,targets=["alpha.example"],folderId=7)=>({
  companyId:"CO-A",nessusScanId:id,folderId,source:"nessus-editor",targets
});
const run=(m=matrix(),vs=[v()],ns=[n()],defs=[d()])=>
  plan(m,vs,ns,defs);

test("missing reviewed routes or definitions produces no candidates",()=>{
  for(const args of [[null,null,null],[[v()],null,[d()]],
                     [[v()],[n()],null]]) {
    const p=plan(matrix(),...args);
    assert.equal(p.candidates.length,0);
    assert.equal(p.launchesEnabled,false);
    assert.ok(p.blocked.length>0);
  }
});
test("one reviewed scan matches only its configured targets, not all approved hosts",()=>{
  const p=run(matrix(),[v(["alpha.example","old.example"])],
    [n(["alpha.example","old.example"])],[d()]);
  assert.equal(p.candidates.length,1);
  assert.equal(p.candidates[0].target,"alpha.example");
  assert.equal(p.candidates[0].nessusScanId,11);
  assert.equal(p.candidates[0].state,"review-required");
  assert.equal(p.launchesEnabled,false);
});
test("different Nessus scan definitions never get the company-wide union",()=>{
  const m=matrix([scan(11),scan(12,"2026-11-04T03:00:00Z")]);
  const p=run(m,
    [v(["alpha.example","bravo.example","historic.example"])],
    [n(["alpha.example","bravo.example","historic.example"])],
    [d(11,["alpha.example"]),d(12,["bravo.example"])]);
  assert.equal(p.candidates.length,2);
  assert.deepEqual(p.candidates.map(x=>[x.nessusScanId,x.target]),[
    [11,"alpha.example"],[12,"bravo.example"]
  ]);
});
test("same host in two Nessus definitions remains bound to each source scan",()=>{
  const p=run(matrix([scan(11),scan(12,"2026-11-04T03:00:00Z")]),
    [v()],[n()],[d(11),d(12)]);
  assert.equal(p.candidates.length,2);
  assert.deepEqual(p.candidates.map(x=>x.nessusScanId),[11,12]);
});
test("partial permission cannot silently remove a Nessus source target",()=>{
  const p=run(matrix(),[v(["alpha.example"])],
    [n(["alpha.example","bravo.example"])],
    [d(11,["alpha.example","bravo.example"])]);
  assert.equal(p.candidates.length,0);
  assert.match(p.blocked[0].reason,/every exact Nessus/i);
});
test("missing, duplicated, or wrong-folder source definition always blocks",()=>{
  for(const defs of [[],[d(11,["alpha.example"],9)],[d(),d()]]) {
    const p=run(matrix(),[v()],[n()],defs);
    assert.equal(p.candidates.length,0);
    assert.ok(p.blocked.length);
  }
});
test("duplicated, malformed, or non-exact approved routes are blocked",()=>{
  for(const source of [
    [v(["alpha.example","ALPHA.example"])],
    [v(["10.0.0.0/24"])],
    [v([])]
  ]) {
    const p=run(matrix(),source,[n()],[d()]);
    assert.equal(p.candidates.length,0);
    assert.ok(p.blocked.length);
  }
});
test("cross-customer shared target is blocked, not assigned by name",()=>{
  const m=matrix();
  m.companies.push({companyId:"CO-B",companyName:"Customer B",scans:[scan(13)]});
  const approvedV=[v(),{companyId:"CO-B",provider:"vulners",targets:["ALPHA.example"]}];
  const approvedN=[n(),{companyId:"CO-B",provider:"nessus",sourceScope:"99",targets:["ALPHA.example"]}];
  const definitions=[d(),{companyId:"CO-B",nessusScanId:13,folderId:99,
    source:"nessus-editor",targets:["ALPHA.example"]}];
  const p=run(m,approvedV,approvedN,definitions);
  assert.equal(p.candidates.length,0);
  assert.equal(p.blocked.length,2);
});
test("invalid enabled source recurrence and offset produce no tasks",()=>{
  const m=matrix([{...scan(11),offsetNextTrigger:"2026-11-04T01:00:00Z"}]);
  const p=run(m,[v()],[n()],[d()]);
  assert.equal(p.candidates.length,0);
});
test("wrong source company or unverified source marker blocks",()=>{
  const other={...d(),companyId:"CO-B"};
  for(const defs of [[other],[{...d(),source:"user-request"}]]){
    const p=run(matrix(),[v()],[n()],defs);
    assert.equal(p.candidates.length,0);
  }
});
test("admin endpoint is read-only and requires both reviewed providers",async()=>{
  const route=await readFile("app/api/admin/external-scan-plan/route.ts","utf8");
  assert.match(route,/adminTokenOk\(request\)/);
  assert.match(route,/loadReviewedScannerRoutes\("nessus"\)/);
  assert.match(route,/loadReviewedScannerRoutes\("vulners"\)/);
  assert.match(route,/nessusConfiguredTargetsForDefinition/);
  assert.doesNotMatch(route,/export (?:async )?function POST|startScan\(/);
});
test("the old full-company port endpoint no longer launches anything",async()=>{
  const route=await readFile("app/api/admin/port-nessus-to-bridge/route.ts","utf8");
  assert.match(route,/status:\s*409/);
  assert.doesNotMatch(route,/startScan\(|nessusBridgeTargetsForCompany/);
});
test("the legacy scheduler starter never creates an interval",async()=>{
  const store=await readFile("lib/store.ts","utf8");
  const start=store.indexOf("function startVulnersBridgeScheduler(): void {");
  const end=store.indexOf("\nasync function vulnersBridgeTick()",start);
  assert.ok(start>=0&&end>start);
  const body=store.slice(start,end);
  assert.doesNotMatch(body,/setInterval|vulnersBridgeTick\(/);
});

test("reviewed Nessus CIDR can approve the full exact Greenbone host set",()=>{
  const m=matrix();
  const exacts=["192.0.2.0","192.0.2.1","192.0.2.2","192.0.2.3"];
  const p=run(m,[v(exacts)],[n(["192.0.2.0/30"])],[d(11,exacts)]);
  assert.equal(p.candidates.length,4);
  assert.equal(p.blocked.length,0);
  assert.equal(p.launchesEnabled,false);
});
test("same CIDR approved on another customer blocks overlapping source host",()=>{
  const p=run(matrix(),[v(["192.0.2.2"])],
    [n(["192.0.2.0/30"]),
     {companyId:"CO-B",provider:"nessus",
       sourceScope:"10",targets:["192.0.2.0/29"]}],
    [d(11,["192.0.2.2"])]);
  assert.equal(p.candidates.length,0);
  assert.ok(p.blocked.length>0);
});
