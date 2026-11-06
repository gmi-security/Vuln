import test from "node:test";
import assert from "node:assert/strict";
import { evaluateReadiness } from "../scripts/audit/external-scan-live-readiness.mjs";

const readiness = (overrides = {}) => ({
  probes: {
    health: {http:200,body:{ready:true,readReady:true,writeReady:true,
      persistence:{dbReachable:true,blocked:false}}},
    plan: {http:200,body:{mode:"preview-only",launchesEnabled:false,routeStatus:"reviewed",
      candidates:[{nessusScanId:18,target:"example.test"}],blocked:[]}},
    capacity: {http:200,body:{scannerCapacityVerified:true,
      capacity:{healthy:true,activeTaskCount:0,queuedTaskCount:0,requestedTaskCount:0,
        checkedAt:new Date().toISOString()}}},
    slot: {http:200,body:{slot:{claim_key:null}}},
  },
  database: {authority:{mode:"sql",enforced:true,epoch:"2",revision:"19587"},
    routes:{nessus:1,vulners:1}},
  flags: {VULNERS_BRIDGE_SCHEDULER_ENABLED:"false",
    GMI_SCAN_ADMISSION_ENABLED:"true",VULN_EXTERNAL_SCAN_DISPATCH_ENABLED:"true"},
  ...overrides,
});
const assess = o => evaluateReadiness(readiness(o));

test("all known passive gates passing never implies permission to scan", () => {
  const x = assess();
  assert.equal(x.outcome,"HOLD");
  assert.equal(x.checks.scannerCapacity.ready,true);
  assert.equal(x.checks.exactDefinitionPlan.ready,true);
  assert.deepEqual(x.blockers,
    ["liveMaintenanceWindow","completedNessusOccurrence","greenboneTerminalReport"]);
});
test("no customer routes leaves scope unapproved", () => {
  const x=assess({database:{authority:{mode:"sql",enforced:true,epoch:"2",revision:"19587"},
    routes:{nessus:0,vulners:0}}});
  assert.equal(x.checks.reviewedRoutesExist.ready,false);
});
test("missing independent reviewed routes or blocked plan fails closed", () => {
  const v=readiness();
  v.probes.plan.body.routeStatus="unavailable";
  v.probes.plan.body.blocked=[{reason:"unreviewed"}];
  assert.equal(evaluateReadiness(v).checks.exactDefinitionPlan.ready,false);
});
test("no candidate target slots is not an actionable plan", () => {
  const v=readiness();v.probes.plan.body.candidates=[];
  assert.equal(evaluateReadiness(v).checks.exactDefinitionPlan.ready,false);
});
test("Greenbone capacity must be fresh, complete and idle", () => {
  for(const change of [
    x => x.probes.capacity.http=503,
    x => x.probes.capacity.body.scannerCapacityVerified=false,
    x => x.probes.capacity.body.capacity.activeTaskCount=1,
    x => x.probes.capacity.body.capacity.queuedTaskCount=1,
    x => x.probes.capacity.body.capacity.requestedTaskCount=1,
    x => x.probes.capacity.body.capacity.checkedAt=new Date(Date.now()-60000).toISOString(),
  ]){
    const v=readiness();change(v);
    assert.equal(evaluateReadiness(v).checks.scannerCapacity.ready,false);
  }
});
test("claimed or missing global SQL slot blocks new starts", () => {
  for(const value of [{http:503,body:null},{http:200,body:{slot:{claim_key:"a".repeat(64)}}}]){
    const v=readiness();v.probes.slot=value;
    assert.equal(evaluateReadiness(v).checks.globalReservationSlot.ready,false);
  }
});
test("new dispatch switches are not auto-enabled by an audit", () => {
  const v=readiness();
  v.flags.GMI_SCAN_ADMISSION_ENABLED="false";
  assert.equal(evaluateReadiness(v).checks.dispatchFlags.ready,false);
  assert.equal(v.flags.GMI_SCAN_ADMISSION_ENABLED,"false");
});
test("legacy company-wide scheduler must remain disabled", () => {
  const v=readiness();v.flags.VULNERS_BRIDGE_SCHEDULER_ENABLED="true";
  assert.equal(evaluateReadiness(v).checks.legacySchedulerDisabled.ready,false);
});
test("unready application and unreachable SQL fail closed", () => {
  const v=readiness();
  v.probes.health.body.writeReady=false;
  v.database.authority.enforced=false;
  assert.equal(evaluateReadiness(v).checks.application.ready,false);
  assert.equal(evaluateReadiness(v).checks.sqlAuthority.ready,false);
});
test("audit result contains no customer IPs or scan task IDs", () => {
  const v=readiness();
  v.probes.plan.body.candidates=[{target:"192.0.2.5",companyId:"SECRET",nessusScanId:18}];
  v.probes.slot.body.events=[{remote_task_id:"TOPSECRET"}];
  const printed=JSON.stringify(evaluateReadiness(v));
  for(const secret of ["192.0.2.5","SECRET","TOPSECRET"])assert.equal(printed.includes(secret),false);
});
