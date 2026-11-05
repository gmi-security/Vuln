#!/usr/bin/env node
// OFFLINE ONLY. Pure, deterministic *preview* of immutable historical
// Greenbone evidence. No PostgreSQL, network, API, scanning, or writes.
// Keep real manifest/approvals/existing snapshots on an approved operator host;
// never commit them, upload to chat, or paste customer targets in logs.
// Usage: node scripts/audit/preview-greenbone-historical-manifest.mjs \
//   --manifest /secure/path/manifest.json \
//   --approvals /secure/path/approvals.json \
//   --existing /secure/path/app-findings.json
import {readFileSync,statSync} from "node:fs";
import {pathToFileURL} from "node:url";

const COMPANIES=new Set(["CO-9150","CO-9153","CO-9156",
                         "CO-9159","CO-9162","CO-9165"]);
const UUID=/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const CVE=/^CVE-[0-9]{4}-[0-9]{4,}$/;
const SCAN=/^SCAN-[0-9]+$/;
const ISO=/^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d{1,3})?Z$/;
const maxRecords=30000;
const normalizeTarget=t=>typeof t==="string"?
  t.trim().toLowerCase().replace(/\.$/,""): "";
const normCve=c=>typeof c==="string"?c.trim().toUpperCase():"";
const tuple=(...xs)=>JSON.stringify(xs);
const validTime=x=>typeof x==="string" && ISO.test(x) &&
  Number.isFinite(Date.parse(x));
const displaySeverity=n=>n>=9?"critical":n>=7?"high":n>=4?"medium":"low";
function validateEnvelope(input,key) {
  if(!input || input.version!==1 || !Array.isArray(input[key]) ||
     input[key].length>maxRecords) throw Error("Invalid or excessive "+key+" input");
  return input[key];
}
function tally(o,key) {o[key]=(o[key]??0)+1;}
const sum=a=>Object.values(a).reduce((n,v)=>n+v,0);

export function previewHistorical(manifest,approvalsInput,existingInput) {
  const observations=validateEnvelope(manifest,"observations");
  const approvals=validateEnvelope(approvalsInput,"approvals");
  const existing=validateEnvelope(existingInput,"findings");

  // Customer/scan/target approval is a positive requirement. Mere
  // ownership in historical app_scans is never authorization.
  const allowed=new Map();
  for(const a of approvals) {
    if(!a || !COMPANIES.has(a.companyId) || !SCAN.test(a.appScanId??"") ||
       !normalizeTarget(a.exactTarget) ||
       !a.approvalId?.trim() || !a.approvedBy?.trim() ||
       !a.nessusOccurrenceId?.trim() ||
       !validTime(a.validFromUtc) || !validTime(a.validThroughUtc) ||
       Date.parse(a.validFromUtc)>Date.parse(a.validThroughUtc)) {
      throw Error("Invalid authorization document (no action taken)");
    }
    const key=tuple(a.companyId,a.appScanId,normalizeTarget(a.exactTarget));
    if(allowed.has(key)) throw Error("Ambiguous duplicate target approval");
    allowed.set(key,a);
  }
  const existingKeys=new Set();
  for(const f of existing) {
    if(!f || !COMPANIES.has(f.companyId) ||
       !normalizeTarget(f.asset) || !CVE.test(normCve(f.cve)))
      throw Error("Invalid existing-findings snapshot");
    existingKeys.add(tuple(f.companyId,normalizeTarget(f.asset),normCve(f.cve)));
  }

  const quarantined={};
  const sourceEvents=new Map();
  const distinct=new Map();
  const stats={version:1,mode:"OFFLINE_PREVIEW_ONLY",
    inputObservations:observations.length,
    approvalRules:allowed.size,
    existingFindingKeys:existingKeys.size,
    acceptedSourceObservations:0,duplicateSourceRows:0,
    eligibleUniqueHostCves:0,alreadyInApp:0,wouldStageHistoricalOnly:0,
    wouldChangeLiveFindingStatus:0,wouldChangeAppScanStatus:0,
    quarantine:quarantined,byCompany:{},severity:{critical:0,high:0,medium:0,low:0}};
  for(const companyId of [...COMPANIES].sort()) stats.byCompany[companyId]={
    uniqueHistorical:0,alreadyInApp:0,wouldStageHistoricalOnly:0,
    severity:{critical:0,high:0,medium:0,low:0}
  };

  for(const o of observations) {
    // Don't throw on one quarantined observation, but don't release data
    // from any observation with incomplete or unverifiable evidence.
    let reason="";
    if(!o || !COMPANIES.has(o.companyId) || !SCAN.test(o.appScanId??""))
      reason="unverified_company_or_scan";
    else if(!normalizeTarget(o.configuredTarget) ||
      !CVE.test(normCve(o.cve))) reason="bad_target_or_cve";
    else if(!UUID.test(o.taskUuid??"") || !UUID.test(o.reportUuid??"") ||
      !UUID.test(o.resultUuid??"") || !UUID.test(o.targetUuid??""))
      reason="missing_source_uuid";
    else if(o.taskStatus!=="Done" || o.reportStatus!=="Done" ||
      !["direct","report_hostname","report_host_details"].includes(o.hostAttestation))
      reason="incomplete_report_or_host_attestation";
    else if(typeof o.nvtOid!=="string" || !o.nvtOid.trim() ||
      typeof o.nvtVersion!=="string" || !o.nvtVersion.trim() ||
      o.cveProvenance!=="report-snapshot")
      reason="unverified_scan_time_cve_lineage";
    else if(!validTime(o.reportStartUtc) || !validTime(o.reportEndUtc) ||
      !validTime(o.observedUtc) ||
      Date.parse(o.reportStartUtc)>Date.parse(o.observedUtc) ||
      Date.parse(o.observedUtc)>Date.parse(o.reportEndUtc))
      reason="invalid_historical_timestamps";
    else if(typeof o.severity!=="number" || !Number.isFinite(o.severity) ||
      o.severity<=0 || o.severity>10)
      reason="invalid_severity";

    const approvalKey=reason?"":tuple(o.companyId,o.appScanId,normalizeTarget(o.configuredTarget));
    const approval=allowed.get(approvalKey);
    if(!reason && !approval) reason="unapproved_exact_target_or_orphan_scan";
    if(!reason && (Date.parse(o.observedUtc)<Date.parse(approval.validFromUtc) ||
                   Date.parse(o.observedUtc)>Date.parse(approval.validThroughUtc)))
      reason="outside_approval_window";

    if(reason) {tally(quarantined,reason);continue;}

    const sourceKey=tuple("greenbone",o.taskUuid.toLowerCase(),
      o.reportUuid.toLowerCase(),o.resultUuid.toLowerCase(),normCve(o.cve));
    const findingKey=tuple(o.companyId,normalizeTarget(o.configuredTarget),normCve(o.cve));
    const obsCanonical=tuple(findingKey,o.nvtOid,o.nvtVersion,
      o.observedUtc,o.severity);
    if(sourceEvents.has(sourceKey)) {
      if(sourceEvents.get(sourceKey)!==obsCanonical)
        throw Error("Conflicting immutable source UUID/CVE identity; STOP");
      stats.duplicateSourceRows++;
      continue;
    }
    sourceEvents.set(sourceKey,obsCanonical);
    stats.acceptedSourceObservations++;
    const old=distinct.get(findingKey);
    if(old) {
      old.maxSeverity=Math.max(old.maxSeverity,o.severity);
    } else distinct.set(findingKey,{companyId:o.companyId,maxSeverity:o.severity});
  }
  stats.eligibleUniqueHostCves=distinct.size;
  for(const [key,rec] of distinct) {
    const company=stats.byCompany[rec.companyId];
    company.uniqueHistorical++;
    if(existingKeys.has(key)) {
      stats.alreadyInApp++;
      company.alreadyInApp++;
    } else {
      stats.wouldStageHistoricalOnly++;
      company.wouldStageHistoricalOnly++;
      const level=displaySeverity(rec.maxSeverity);
      stats.severity[level]++;
      company.severity[level]++;
    }
  }
  if(stats.eligibleUniqueHostCves!==stats.alreadyInApp+stats.wouldStageHistoricalOnly ||
     stats.wouldStageHistoricalOnly!==sum(stats.severity) ||
     stats.acceptedSourceObservations+stats.duplicateSourceRows+
       sum(quarantined)!==observations.length)
    throw Error("Accounting imbalance: no preview produced");
  return stats;  // aggregate counts only: never emit customer targets/CVEs.
}
function readStrictJson(filepath) {
  const st=statSync(filepath);
  if(!st.isFile() || st.size>20*1024*1024) throw Error("Invalid input file size");
  return JSON.parse(readFileSync(filepath,"utf8"));
}
if(process.argv[1] &&
   import.meta.url===pathToFileURL(process.argv[1]).href) {
  try {
    const args=process.argv.slice(2);
    if(args.length!==6 || args[0]!=="--manifest" || args[2]!=="--approvals" ||
       args[4]!=="--existing") throw Error("Required: --manifest PATH --approvals PATH --existing PATH");
    const result=previewHistorical(
      readStrictJson(args[1]),readStrictJson(args[3]),readStrictJson(args[5]));
    console.log(JSON.stringify(result,null,2));
    console.error("NO WRITES. This is NOT a production import plan or scope authorization.");
  } catch(e) {
    console.error("PREVIEW BLOCKED:",e.message);
    process.exitCode=1;
  }
}
