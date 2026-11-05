import test from "node:test";
import assert from "node:assert/strict";
import {previewHistorical} from "./preview-greenbone-historical-manifest.mjs";

const manifestRows=()=>{
  const base={
    companyId:"CO-9150",appScanId:"SCAN-1001",
    nessusOccurrenceId:"test-nessus-occurrence-123",
    configuredTarget:"host.example.invalid",
    taskUuid:"00000000-0000-4000-8000-000000000001",
    reportUuid:"00000000-0000-4000-8000-000000000002",
    resultUuid:"00000000-0000-4000-8000-000000000003",
    targetUuid:"00000000-0000-4000-8000-000000000004",
    cve:"CVE-2026-12345",
    taskStatus:"Done",reportStatus:"Done",hostAttestation:"report_host_details",
    nvtOid:"1.3.6.1.4.1.25623.1.0.1234",nvtVersion:"20261011",
    cveProvenance:"report-snapshot",
    reportStartUtc:"2026-10-12T01:00:00Z",
    reportEndUtc:"2026-10-12T02:00:00Z",
    observedUtc:"2026-10-12T01:30:00Z",
    severity:5.5
  };
  return [
    base,
    {...base}, // identical source occurrence must be idempotently ignored
    {...base,resultUuid:"00000000-0000-4000-8000-000000000005",
      cve:"CVE-2026-12346",severity:7.1},
    {...base,resultUuid:"00000000-0000-4000-8000-000000000006",
      cve:"CVE-2026-12346",severity:9.2},
    {...base,appScanId:"SCAN-9999",resultUuid:"00000000-0000-4000-8000-000000000007"},
    {...base,resultUuid:"00000000-0000-4000-8000-000000000008",
      cveProvenance:"current-NVT"} // not immutable scan-time CVE evidence
  ];
};
const approvals={version:1,approvals:[{
  companyId:"CO-9150",appScanId:"SCAN-1001",
  exactTarget:"HOST.example.invalid.",approvalId:"review-123",approvedBy:"Test Reviewer",
  nessusOccurrenceId:"test-nessus-occurrence-123",
  validFromUtc:"2026-10-11T00:00:00Z",
  validThroughUtc:"2026-10-13T00:00:00Z"
}]};
const existing={version:1,findings:[{
  companyId:"CO-9150",asset:"host.example.invalid",cve:"CVE-2026-12345"
}]};

test("deduplicates source occurrences, stages historical-only, quarantines orphans",()=>{
  const rows=manifestRows();
  const preview=previewHistorical({version:1,observations:rows},approvals,existing);
  assert.equal(preview.inputObservations,6);
  assert.equal(preview.acceptedSourceObservations,3);
  assert.equal(preview.duplicateSourceRows,1);
  assert.equal(preview.eligibleUniqueHostCves,2);
  assert.equal(preview.alreadyInApp,1);
  assert.equal(preview.wouldStageHistoricalOnly,1);
  assert.equal(preview.severity.critical,1);
  assert.equal(preview.quarantine.unapproved_exact_target_or_orphan_scan,1);
  assert.equal(preview.quarantine.unverified_scan_time_cve_lineage,1);
  assert.equal(preview.wouldChangeLiveFindingStatus,0);
  assert.equal(preview.wouldChangeAppScanStatus,0);
  assert.ok(!JSON.stringify(preview).includes("host.example.invalid"));
  assert.deepEqual(preview,previewHistorical({version:1,observations:rows},approvals,existing));
});
test("conflicting source UUID/CVE observation fails closed",()=>{
  const base=manifestRows()[0];
  assert.throws(()=>previewHistorical({version:1,observations:[
    base,{...base,severity:8.7}
  ]},approvals,existing),/Conflicting immutable source/);
});
test("duplicate exact-target authorization fails closed",()=>{
  assert.throws(()=>previewHistorical({version:1,observations:[]},{
    version:1,approvals:[...approvals.approvals,...approvals.approvals]
  },existing),/duplicate target approval/);
});
test("unreviewed targets and time windows are quarantined",()=>{
  const base=manifestRows()[0];
  const result=previewHistorical({version:1,observations:[
    {...base,configuredTarget:"other.example.invalid"},
    {...base,observedUtc:"2026-10-14T01:30:00Z",
      reportStartUtc:"2026-10-14T01:00:00Z",reportEndUtc:"2026-10-14T02:00:00Z"}
  ]},approvals,existing);
  assert.equal(result.acceptedSourceObservations,0);
  assert.equal(result.quarantine.unapproved_exact_target_or_orphan_scan,1);
  assert.equal(result.quarantine.outside_approval_window,1);
  assert.equal(result.wouldStageHistoricalOnly,0);
});

test("current-NVT mappings remain provisional despite valid UUIDs and target approval",()=>{
  const base=manifestRows()[0];
  const result=previewHistorical({version:1,observations:[
    {...base,cveProvenance:"current-nvt-at-recovery"},
    {...base,appScanId:"SCAN-9999",cveProvenance:"current-nvt-at-recovery",
      resultUuid:"00000000-0000-4000-8000-000000000008"}
  ]},approvals,existing);
  assert.equal(result.quarantine.provisional_current_nvt_cve_mapping,1);
  assert.equal(result.quarantine.unapproved_exact_target_or_orphan_scan,1);
  assert.equal(result.acceptedSourceObservations,0);
  assert.equal(result.wouldStageHistoricalOnly,0);
  assert.equal(result.wouldChangeLiveFindingStatus,0);
  assert.equal(result.wouldChangeAppScanStatus,0);
});
test("no approved scope means no historically staged observations",()=>{
  const result=previewHistorical({version:1,observations:manifestRows()},
    {version:1,approvals:[]},existing);
  assert.equal(result.acceptedSourceObservations,0);
  assert.equal(result.wouldStageHistoricalOnly,0);
  assert.equal(result.quarantine.unapproved_exact_target_or_orphan_scan,6);
});

test("approved target cannot use another Nessus scan occurrence",()=>{
  const bad={...manifestRows()[0],
    nessusOccurrenceId:"different-nessus-occurrence",
    resultUuid:"00000000-0000-4000-8000-000000000009"};
  const p=previewHistorical({version:1,observations:[bad]},approvals,existing);
  assert.equal(p.quarantine.nessus_occurrence_not_verified,1);
  assert.equal(p.wouldStageHistoricalOnly,0);
});
test("reused result UUID with a different target UUID fails closed",()=>{
  const base=manifestRows()[0];
  const contradictory={...base,
    targetUuid:"00000000-0000-4000-8000-000000000010"};
  assert.throws(()=>previewHistorical(
    {version:1,observations:[base,contradictory]},
    approvals,existing),/Conflicting immutable source/);
});
