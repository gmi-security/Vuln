import test from "node:test";
import assert from "node:assert/strict";
import { loadTs } from "./helpers/load-ts-module.mjs";

const {verifyGreenboneTerminalTarget} = await loadTs("lib/greenbone-terminal-proof.ts");

const NOW = Date.parse("2026-11-06T02:00:00.000Z");
const C = {
  companyId:"CO-TEST",target:"192.0.2.10",nessusScanId:18,
  scheduledOccurrenceAt:"2026-11-06T00:00:00.000Z",
};
const TASK="bridge_task_123";
const RUN="f80d4e73-2a84-4e11-851d-754bf12d148a";
const REPORT="072f4aaa-780c-468f-8bd7-cd0fcb9b0955";
const HOST="982bedef-0217-454b-8fd0-00ff34499fe9";
const nessus=()=>({
  scanId:18,status:"completed",startedAt:"2026-11-06T00:05:00.000Z",
  completedAt:"2026-11-06T00:40:00.000Z",reportId:RUN,coveredTargets:[C.target],
});
const report=()=>({
  source:"gvmd",inventoryComplete:true,taskStatus:"Done",reportStatus:"Done",
  reportComplete:true,allPagesComplete:true,knownTargetCount:1,reportedHostCount:1,
  taskId:TASK,reportId:REPORT,target:C.target,
  startedAt:"2026-11-06T01:10:00.000Z",completedAt:"2026-11-06T01:45:00.000Z",
  generatedAt:"2026-11-06T01:59:55.000Z",
  skippedHostCount:0,failedHostCount:0,reportResultCount:0,
  hosts:[{identity:C.target,status:"completed",assessed:true,evidenceId:HOST}],
});
const check=(payload=report(), source=nessus(), candidate=C, taskId=TASK)=>
  verifyGreenboneTerminalTarget(candidate,taskId,source,payload,NOW);

test("one complete zero-CVE report and exact host result is evidence, not a launcher",()=>{
  const proof=check();
  assert.ok(proof);
  assert.equal(proof.target,C.target);
  assert.equal(proof.taskId,TASK);
  assert.equal(proof.nessusRunId,RUN);
  assert.match(proof.evidenceSha256,/^[0-9a-f]{64}$/);
  assert.equal(check().evidenceSha256,proof.evidenceSha256);
});
test("a Done task with no assessed host fails closed",()=>{
  for(const mut of [
    x=>{x.hosts=[];x.reportedHostCount=0;},
    x=>{x.hosts[0].assessed=false;},
    x=>{x.hosts[0].status="skipped";},
    x=>{x.hosts[0].identity="192.0.2.20";},
    x=>{x.hosts[0].evidenceId=null;},
    x=>{x.skippedHostCount=1;},
    x=>{x.failedHostCount=1;},
    x=>{x.reportedHostCount=2;},
    x=>{x.knownTargetCount=2;},
  ]){const p=report();mut(p);assert.equal(check(p),null);}
});
test("incomplete or untrusted task/report cannot establish parity",()=>{
  for(const mut of [
    x=>{x.source="bridge";},
    x=>{x.inventoryComplete=false;},
    x=>{x.taskStatus="Running";},
    x=>{x.reportStatus="Done";x.reportComplete=false;},
    x=>{x.allPagesComplete=false;},
    x=>{x.taskId="different";},
    x=>{x.reportId="not-a-uuid";},
    x=>{x.target="192.0.2.20";},
    x=>{x.reportResultCount=-1;},
    x=>{x.reportResultCount=undefined;},
  ]){const p=report();mut(p);assert.equal(check(p),null);}
});
test("stale attestation or time travel fails closed",()=>{
  for(const mut of [
    x=>{x.generatedAt="2026-11-06T01:59:00.000Z";},
    x=>{x.generatedAt="2026-11-06T02:00:01.000Z";},
    x=>{x.completedAt="2026-11-06T02:01:00.000Z";},
    x=>{x.completedAt="2026-11-06T01:00:00.000Z";},
    x=>{x.startedAt="2026-11-06T00:30:00.000Z";},
  ]){const p=report();mut(p);assert.equal(check(p),null);}
});
test("Greenbone cannot start before both +60m and the completed Nessus run",()=>{
  const p=report();p.startedAt="2026-11-06T01:10:00.000Z";
  const n=nessus();n.completedAt="2026-11-06T01:20:00.000Z";
  assert.equal(check(p,n),null);
  const before=report();before.startedAt="2026-11-06T00:50:00.000Z";
  assert.equal(check(before),null);
});
test("different Nessus scan, run identity, company target or nonexact alias refuses parity",()=>{
  const n=nessus();n.scanId=19;
  assert.equal(check(report(),n),null);
  const id=nessus();id.reportId="unknown";
  assert.equal(check(report(),id),null);
  const aliases=nessus();aliases.coveredTargets=["192.0.2.10","192.0.2.11"];
  assert.equal(check(report(),aliases),null);
  assert.equal(check(report(),nessus(),{...C,target:"example.test"}),null);
});
test("invalid or missing expected task ID blocks",()=>{
  assert.equal(check(report(),nessus(),C,"not a valid task id"),null);
  assert.equal(check(report(),nessus(),C,""),null);
});
test("no report host result must never become a success from zero CVEs",()=>{
  const p=report();p.hosts=[];p.reportedHostCount=0;p.reportResultCount=0;
  assert.equal(check(p),null);
});
