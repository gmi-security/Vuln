// node --experimental-vm-modules --test tests/nessus-run-proof.test.mjs
import test from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { SourceTextModule, SyntheticModule } from "node:vm";
import ts from "typescript";
const source = await readFile("lib/nessus-run-proof.ts","utf8");
const js = ts.transpileModule(source, {
  compilerOptions:{target:ts.ScriptTarget.ES2022,module:ts.ModuleKind.ESNext},
}).outputText;
const mod = new SourceTextModule(js);
await mod.link(async name => {
  assert.equal(name,"./scanner-target-scope");
  return new SyntheticModule(["scannerExactTargetKey"],function(){
    this.setExport("scannerExactTargetKey",(value)=>{
      if(typeof value!=="string" || !value || value.includes("/") || value.includes("*"))throw Error("Invalid");
      return value.toLowerCase().replace(/\.$/,"");
    });
  });
});
await mod.evaluate();
const {verifyCompletedNessusOccurrence} = mod.namespace;
const candidate={companyId:"CO-A",target:"alpha.example",nessusScanId:11,scheduledOccurrenceAt:"2026-11-04T01:00:00Z"};
const now="2026-11-04T02:20:00Z", folderId=15;
const timestamp = iso => Date.parse(iso)/1000;
const historyUuid = "e397e8e9-848a-40c4-a5a0-6cafbbc54a18";
function data() {
  return {
    roster:[{id:11,folderId:15,name:"Customer A Nessus",status:"completed",lastModified:timestamp("2026-11-04T02:04:00Z")}],
    summary:{history:[{history_id:88,uuid:historyUuid,status:"completed",creation_date:timestamp("2026-11-04T01:01:00Z")}]},
    pinned:{history_id:88,uuid:historyUuid,
      info:{status:"completed",scan_start:timestamp("2026-11-04T01:02:00Z"),
        scan_end:timestamp("2026-11-04T02:04:00Z"),incomplete_targets:0},
      hosts:[{host_id:5,hostname:"alpha.example"},{host_id:6,hostname:"beta.example"}]},
    details:{5:{host_id:5,info:{"host-fqdn":"ALPHA.EXAMPLE","host-ip":"198.51.100.10"},vulnerabilities:[]},
      6:{host_id:6,info:{"host-fqdn":"beta.example","host-ip":"198.51.100.11"},vulnerabilities:[]}},
  };
}
function reader(d,seen=[]){
  return {
    listScans:async id=>{seen.push(["list",id]);return d.roster;},
    rejectsUnknownHistoryId:async(id,historyId)=>{seen.push(["invalid",id,historyId]);return d.rejectsUnknown !== false;},
    scanDetails:async(id,historyId)=>{seen.push(["scan",id,historyId]);return historyId===undefined?d.summary:d.pinned;},
    hostDetails:async(id,hostId,historyId)=>{seen.push(["host",id,hostId,historyId]);return d.details[hostId];},
  };
}
const check=(d,c=candidate,f=folderId)=>verifyCompletedNessusOccurrence(c,f,reader(d),now);
test("completed historical Nessus run requires exact folder, UUID, run times and host results",async()=>{
  const d=data(), seen=[];
  const result=await verifyCompletedNessusOccurrence(candidate,folderId,reader(d,seen),now);
  assert.deepEqual(result,{
    scanId:11,status:"completed",
    startedAt:"2026-11-04T01:02:00.000Z",completedAt:"2026-11-04T02:04:00.000Z",
    reportId:historyUuid,coveredTargets:["alpha.example"],
  });
  assert.deepEqual(seen,[
    ["list",15],["scan",11,undefined],["scan",11,88],["host",11,5,88],["host",11,6,88],
  ]);
});
test("folder mismatch or unreviewed exact target cannot yield proof",async()=>{
  assert.equal(await check(data(),candidate,16),null);
  assert.equal(await check(data(),{...candidate,target:"other.example"}),null);
  assert.equal(await check(data(),{...candidate,target:"10.0.0.0/24"}),null);
});
test("no completed Nessus history, ambiguous run or stale occurrence holds",async()=>{
  const d=data();d.summary.history[0].status="running";assert.equal(await check(d),null);
  const e=data();e.summary.history.push({...e.summary.history[0],history_id:89});
  assert.equal(await check(e),null);
  assert.equal(await check(data(),{...candidate,scheduledOccurrenceAt:"2026-10-01T01:00:00Z"}),null);
});
test("pinning ignored, wrong UUID and current run substitution must hold",async()=>{
  const d=data();d.pinned.history_id=99;assert.equal(await check(d),null);
  const e=data();e.pinned.uuid="00000000-0000-0000-0000-000000000000";assert.equal(await check(e),null);
  const f=data();delete f.pinned.history_id;assert.equal(await check(f),null);
});
test("unfinished, partially covered or inconsistent historical run holds",async()=>{
  const d=data();d.pinned.info.status="running";assert.equal(await check(d),null);
  const e=data();e.pinned.info.incomplete_targets=1;assert.equal(await check(e),null);
  const f=data();delete f.pinned.info.incomplete_targets;assert.equal(await check(f),null);
  const g=data();g.pinned.info.scan_end=timestamp("2026-11-05T02:04:00Z");assert.equal(await check(g),null);
});
test("historical host detail is required, not only the configured targets or scan roster",async()=>{
  const d=data();d.details[5].info["host-fqdn"]="other.example";
  d.details[5].info["host-ip"]="192.0.2.17";
  d.pinned.hosts[0].hostname="alpha.example";
  assert.equal(await check(d),null);
  const e=data();delete e.details[5].vulnerabilities;assert.equal(await check(e),null);
  const f=data();f.pinned.hosts.push({...f.pinned.hosts[0]});assert.equal(await check(f),null);
});
test("missing Nessus API data or errors never produce proof",async()=>{
  const d=data();d.summary.history=[];assert.equal(await check(d),null);
  const e=data();e.details[5]=null;assert.equal(await check(e),null);
  assert.equal(await verifyCompletedNessusOccurrence(candidate,15,{
    listScans:async()=>{throw Error("scanner offline");},
    rejectsUnknownHistoryId:async()=>{throw Error("not called");},
    scanDetails:async()=>{throw Error("not called");},
    hostDetails:async()=>{throw Error("not called");},
  },now),null);
});

function idlessTwoRunFixture() {
  const d=data();
  delete d.pinned.history_id;
  delete d.pinned.uuid;
  d.summary.history.push({
    history_id:87,
    uuid:"889e2266-9ca3-46ed-9b2d-9a240cb58903",
    status:"completed",
    creation_date:timestamp("2026-11-03T21:01:00Z"),
  });
  d.alternate={
    info:{status:"completed",scan_start:timestamp("2026-11-03T21:02:00Z"),
      scan_end:timestamp("2026-11-03T21:50:00Z")},
  };
  return d;
}
test("Nessus live shape: absent top-level ID/UUID allowed only with proven historical isolation",async()=>{
  const d=idlessTwoRunFixture();
  const seen=[];
  const r=await verifyCompletedNessusOccurrence(candidate,folderId,{
    ...reader(d,seen),
    scanDetails:async(id,hid)=>{
      seen.push(["scan",id,hid]);
      return hid===undefined?d.summary:hid===87?d.alternate:d.pinned;
    },
  },now);
  assert.ok(r);
  assert.equal(r.reportId,historyUuid);
  assert.deepEqual(seen.slice(0,5),[
    ["list",15],["scan",11,undefined],["scan",11,88],
    ["invalid",11,2147483647],["scan",11,87],
  ]);
});
test("Nessus live shape: ignored history_id, invalid-ID acceptance or identical history blocks",async()=>{
  for(const variation of ["invalid accepted","same start","wrong historic start","missing sibling"]) {
    const d=idlessTwoRunFixture();
    if(variation==="invalid accepted")d.rejectsUnknown=false;
    if(variation==="same start")d.alternate.info.scan_start=d.pinned.info.scan_start;
    if(variation==="wrong historic start")d.alternate.info.scan_start=timestamp("2026-11-02T21:02:00Z");
    if(variation==="missing sibling")d.summary.history.pop();
    const r=await verifyCompletedNessusOccurrence(candidate,folderId,{
      ...reader(d),
      scanDetails:async(id,hid)=>hid===undefined?d.summary:hid===87?d.alternate:d.pinned,
    },now);
    assert.equal(r,null,variation);
  }
});
