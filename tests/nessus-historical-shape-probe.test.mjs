import assert from "node:assert/strict";
import test from "node:test";
import { summarizeNessusHistoryShape } from "../scripts/nessus-historical-shape-probe.mjs";

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
