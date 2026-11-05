import test from "node:test";
import assert from "node:assert/strict";
import {
  extractNessusTargetExpressions,normalizeNessusDefinition,
  compareNessusToGreenbonePerScan
} from "./nessus-per-scan-target-parity.mjs";
const editor=value=>({settings:{basic:{inputs:[
  {id:"schedule",value:"FREQ=DAILY"},
  {id:"text_targets",name:"text_targets",value}
]}}});
const entry=(target,route,planned)=>({
  companyId:"CO-9150",nessusScanId:42,
  nessusOccurrenceId:"real-completed-history-uuid",
  nessusEditor:editor(target),
  reviewedExactTargets:route,greenbonePlannedTargets:planned
});
test("Nessus editor text_targets is the source; unrelated sibling fields ignored",()=>{
  assert.deepEqual(extractNessusTargetExpressions(editor("a.example\n10.2.0.1, b.example")),
    ["a.example","10.2.0.1","b.example"]);
});
test("same targets match regardless of order/case; no actual scan proof claimed",()=>{
  const r=compareNessusToGreenbonePerScan(entry(
    "SERVER.EXAMPLE., 10.2.0.1",
    ["server.example","10.2.0.1"],
    ["10.2.0.1","server.example"]
  ));
  assert.equal(r.status,"planned-targets-match");
  assert.equal(r.configuredExactHostCount,2);
  assert.equal(r.canDispatch,false);
  assert.equal(r.executedScanParityVerified,false);
});
test("missing or extra Greenbone target is visible, not silently tolerated",()=>{
  const r=compareNessusToGreenbonePerScan(entry(
    "a.example,b.example",["a.example","b.example","c.example"],
    ["a.example","c.example"]
  ));
  assert.equal(r.status,"targets-differ");
  assert.equal(r.missingFromGreenbone,1);
  assert.equal(r.extraInGreenbone,1);
});
test("the company-wide historical union is not a per-scan target list",()=>{
  const r=compareNessusToGreenbonePerScan(entry(
    "a.example",["a.example","from-old-scan.example"],
    ["a.example","from-old-scan.example"]
  ));
  assert.equal(r.status,"targets-differ");
  assert.equal(r.extraInGreenbone,1);
});
test("one bounded IPv4 CIDR represents every configured address for parity",()=>{
  const p=normalizeNessusDefinition(editor("192.0.2.0/30,db.example"));
  assert.equal(p.expressionCount,2);
  assert.equal(p.exactHostCount,5);
  assert.equal(p.cidrExpressions,1);
  const r=compareNessusToGreenbonePerScan(entry(
    "192.0.2.0/30,db.example",
    ["192.0.2.0","192.0.2.1","192.0.2.2","192.0.2.3","db.example"],
    ["192.0.2.3","db.example","192.0.2.1","192.0.2.2","192.0.2.0"]
  ));
  assert.equal(r.status,"planned-targets-match");
  assert.equal(r.canDispatch,false);
});
test("excessive CIDR, unsupported range, ambiguous or absent editor field block",()=>{
  assert.equal(compareNessusToGreenbonePerScan(entry(
    "10.0.0.0/8",["10.0.0.1"],["10.0.0.1"])).status,"blocked");
  assert.equal(compareNessusToGreenbonePerScan(entry(
    "192.0.2.1-192.0.2.10",["192.0.2.1"],["192.0.2.1"])).status,"blocked");
  assert.throws(()=>extractNessusTargetExpressions({settings:{basic:{inputs:[
    {id:"text_targets",value:"a.example"},
    {name:"text_targets",value:"b.example"}
  ]}}}),/ambiguous/);
});
test("target outside approved scope blocks parity approval",()=>{
  const r=compareNessusToGreenbonePerScan(entry(
    "a.example,b.example",["a.example"],["a.example","b.example"]));
  assert.equal(r.status,"scope-review-required");
  assert.equal(r.unauthorizedSourceTargets,1);
});
test("no reviewed targets, duplicate target or missing occurrence fails closed",()=>{
  assert.equal(compareNessusToGreenbonePerScan(entry(
    "a.example",[],["a.example"])).status,"blocked");
  assert.equal(compareNessusToGreenbonePerScan(entry(
    "a.example,a.example",["a.example"],["a.example"])).status,"blocked");
  assert.throws(()=>compareNessusToGreenbonePerScan({
    ...entry("a.example",["a.example"],["a.example"]),nessusOccurrenceId:""
  }),/Missing exact Nessus/);
});

test("real Nessus editor shape uses text_targets.default when value is absent",()=>{
  const actualShape={settings:{basic:{inputs:[
    {id:"schedule",default:"schedule-not-a-target"},
    {id:"text_targets",name:"textarea",
     default:"SERVER.EXAMPLE.\n10.2.0.1"}
  ]}}};
  assert.deepEqual(extractNessusTargetExpressions(actualShape),
    ["SERVER.EXAMPLE.","10.2.0.1"]);
  const result=compareNessusToGreenbonePerScan({
    ...entry("",["server.example","10.2.0.1"],
      ["10.2.0.1","server.example"]),nessusEditor:actualShape
  });
  assert.equal(result.status,"planned-targets-match");
});
test("divergent value and default fields fail closed",()=>{
  assert.throws(()=>extractNessusTargetExpressions({
    settings:{basic:{inputs:[{id:"text_targets",value:"host-a.example",
      default:"host-b.example"}]}}
  }),/Conflicting Nessus configured target fields/);
});
test("non-string or empty Nessus editor target values cannot be treated as scans",()=>{
  assert.throws(()=>extractNessusTargetExpressions({
    settings:{basic:{inputs:[{id:"text_targets",default:["host.example"]}]}}
  }),/Unexpected Nessus target default type/);
  assert.throws(()=>extractNessusTargetExpressions({
    settings:{basic:{inputs:[{id:"text_targets",default:""}]}}
  }),/Empty configured target field/);
});

test("saved Nessus text_targets accepts comma and whitespace separators",()=>{
  const actual={settings:{basic:{inputs:[{id:"text_targets",
    default:"host-one.example host-two.example,\n10.5.0.1\t10.5.0.2"}]}}};
  assert.deepEqual(extractNessusTargetExpressions(actual),[
    "host-one.example","host-two.example","10.5.0.1","10.5.0.2"
  ]);
});
