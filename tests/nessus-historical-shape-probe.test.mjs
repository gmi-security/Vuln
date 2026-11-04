import assert from "node:assert/strict";
import test from "node:test";
import { summarizeNessusHistoryShape, summarizeNessusAllHostsAudit } from "../scripts/nessus-historical-shape-probe.mjs";

const ID = "e397e8e9-848a-40c4-a5a0-6cafbbc54a18";
const SECRET = "DO_NOT_LOG_SECRET_ACCESS_KEY";
const HOST = "secret-client.private.example";
const HOST_IP = "192.0.2.17";
function fixture() {
  return {
    ordinary:{
      info:{status:"completed",scan_start:1793740000,scan_end:1793743000,
        name:SECRET,uuid:ID},
      history:[{history_id:88,uuid:ID,status:"completed",creation_date:1793740000,
        owner:SECRET}],
    },
    selected:{history_id:88,uuid:ID,status:"completed",creation_date:1793740000},
    pinned:{
      history_id:88,uuid:ID,
      info:{status:"completed",scan_start:1793740000,scan_end:1793743000,
        is_archived:false, incomplete_targets:0,targets:HOST},
      hosts:[{host_id:5,hostname:HOST}],
    },
    host:{host_id:5,hostname:HOST,info:{"host-fqdn":HOST,"host-ip":HOST_IP,
      private_extra_field:SECRET},vulnerabilities:[{cve:"CVE-2026-0001",output:SECRET}]},
    rosterMatched:true,pinnedHttpStatus:200,hostHttpStatus:200,
  };
}
test("Nessus probe reports exact field types and historical binding without raw values",()=>{
  const result=summarizeNessusHistoryShape(fixture());
  assert.equal(result.format,"gmi-nessus-history-shape-v1");
  assert.equal(result.approvedFolderScanMatched,true);
  assert.equal(result.latestScan.historyArray,true);
  assert.equal(result.selectedCompletedHistory.fields.history_id,"number");
  assert.equal(result.selectedCompletedHistory.fields.uuid,"string");
  assert.equal(result.pinnedScan.infoFields.scan_start,"number");
  assert.equal(result.pinnedScan.infoFields.incomplete_targets,"number");
  assert.equal(result.pinnedScan.historyIdMatches,true);
  assert.equal(result.pinnedScan.uuidMatches,true);
  assert.equal(result.pinnedHost.infoFields["host-fqdn"],"string");
  assert.equal(result.pinnedHost.vulnerabilitiesArray,true);
  const rendered=JSON.stringify(result);
  for (const prohibited of [SECRET,HOST,HOST_IP,ID,"CVE-2026-0001","private_extra_field",
    "accessKey","secretKey","private_extra_field"])
    assert.equal(rendered.includes(prohibited),false,"Sensitive value/field leaked: "+prohibited);
});
test("Missing historical identity and incomplete host data are reported, never replaced with default run",()=>{
  const d=fixture();d.pinned={info:{status:"completed",scan_start:1793740000},hosts:[]};d.host=null;
  const r=summarizeNessusHistoryShape(d);
  assert.equal(r.pinnedScan.historyIdMatches,null);
  assert.equal(r.pinnedScan.uuidMatches,null);
  assert.equal(r.pinnedScan.infoFields.incomplete_targets,"missing");
  assert.equal(r.pinnedHost.infoFields["host-fqdn"],"missing");
  assert.equal(r.pinnedHost.vulnerabilitiesArray,false);
});
test("Incorrect history bindings are flagged without printing their UUIDs",()=>{
  const d=fixture();d.pinned.history_id=89;d.pinned.uuid="00000000-0000-0000-0000-000000000000";
  const r=summarizeNessusHistoryShape(d);
  assert.equal(r.pinnedScan.historyIdMatches,false);
  assert.equal(r.pinnedScan.uuidMatches,false);
  assert.equal(JSON.stringify(r).includes("00000000"),false);
});
test("No historical run remains a metadata-only diagnostic, never a scan trigger",()=>{
  const d=fixture();d.selected=null;d.pinned=null;d.host=null;
  const r=summarizeNessusHistoryShape(d);
  assert.equal(r.selectedCompletedHistory.available,false);
  assert.equal(r.pinnedScan.httpStatus,200);
  assert.equal(r.pinnedHost.vulnerabilitiesArray,false);
});

test("historical host timestamp attestation outputs only booleans, never host times",()=>{
  const d=fixture();
  const begin=d.pinned.info.scan_start*1000;
  const end=d.pinned.info.scan_end*1000;
  d.host.info.host_start=new Date(begin+10_000).toISOString();
  d.host.info.host_end=new Date(end-10_000).toISOString();
  const good=summarizeNessusHistoryShape(d);
  assert.deepEqual(good.pinnedHost.timeChecks,{
    parseable:true,startBeforeEnd:true,withinSelectedScan:true,
  });
  assert.equal(JSON.stringify(good).includes(d.host.info.host_end),false);
  d.host.info.host_end=new Date(begin-86_400_000).toISOString();
  const bad=summarizeNessusHistoryShape(d);
  assert.equal(bad.pinnedHost.timeChecks.withinSelectedScan,false);
  d.host.info.host_end="not-a-time";
  const malformed=summarizeNessusHistoryShape(d);
  assert.equal(malformed.pinnedHost.timeChecks.parseable,false);
});

test("bounded historical all-host audit passes with two fully completed hosts",()=>{
 const start=1793740000,finish=1793743000;
 const pinned={info:{status:"completed",scan_start:start,scan_end:finish},
   hosts:[{host_id:1,hostname:HOST},{host_id:2,hostname:"secret-host-2"}]};
 const make=(id)=>({hostId:id,status:200,body:{
   info:{"host_start":new Date((start+10)*1000).toISOString(),
     "host_end":new Date((finish-10)*1000).toISOString(),"host-fqdn":HOST},
   vulnerabilities:[{details:SECRET}],
 }});
 const items=[make(1),make(2)];
 const audit=summarizeNessusAllHostsAudit(pinned,items);
 assert.deepEqual(audit,{totalHosts:2,inventoryValid:true,selectedRunCompleted:true,
   hostResponsesChecked:2,hostsWithValidBoundedCompletion:2,hostsRejected:0,
   allHistoricalHostsComplete:true});
 const json=JSON.stringify(audit);
 for(const secret of [HOST,SECRET,"secret-host-2",String(start),String(finish)])
   assert.equal(json.includes(secret),false);
});
test("all-host audit fails closed on missing, malformed, stale and duplicate host results",()=>{
 const start=1793740000,finish=1793743000;
 const pinned={info:{status:"completed",scan_start:start,scan_end:finish},
   hosts:[{host_id:1},{host_id:2}]};
 const good=(hostId)=>({hostId,status:200,body:{
   info:{host_start:new Date(start*1000).toISOString(),
     host_end:new Date(finish*1000).toISOString()},
   vulnerabilities:[],
 }});
 const both=[good(1),good(2)];
 assert.equal(summarizeNessusAllHostsAudit(pinned,both).allHistoricalHostsComplete,true);
 const scenarios=[
   [good(1)], [good(1),{...good(2),status:404}],
   [good(1),{...good(2),body:{...good(2).body,info:{}}}],
   [good(1),{...good(2),body:{...good(2).body,info:{host_start:"invalid",host_end:"invalid"}}}],
   [good(1),{...good(2),body:{...good(2).body,vulnerabilities:null}}],
   [good(1),{...good(2),body:{...good(2).body,host_id:1}}],
   [good(1),{...good(2),body:{...good(2).body,info:{
     host_start:new Date((start-600)*1000).toISOString(),
     host_end:new Date(finish*1000).toISOString()}}}],
   [good(1),good(1)],
 ];
 for (const bad of scenarios)
   assert.equal(summarizeNessusAllHostsAudit(pinned,bad).allHistoricalHostsComplete,false);
 const duplicate={...pinned,hosts:[{host_id:1},{host_id:1}]};
 assert.equal(summarizeNessusAllHostsAudit(duplicate,both).allHistoricalHostsComplete,false);
 const overflow={...pinned,hosts:Array.from({length:101},(_,i)=>({host_id:i+1}))};
 assert.equal(summarizeNessusAllHostsAudit(overflow,[]).allHistoricalHostsComplete,false);
});
