#!/usr/bin/env node
// READ ONLY: GET six historically mapped Nessus folders and each scan's
// configured text_targets; one row PER definition, NOT per company union.
// Never starts a scan, changes routing, or calls any POST.
// Prints only counts and Nessus definition IDs, not target identities.
// Run from /opt/vuln with node --env-file=.env.local on Vuln-NYC1.
// Historical folder-to-company links require independent approval.
import https from "node:https";
import http from "node:http";
import {normalizeNessusDefinition} from "./nessus-per-scan-target-parity.mjs";
const FOLDERS=[
  [7,"CO-9150",4],[11,"CO-9153",5],[114,"CO-9156",3],
  [136,"CO-9159",2],[253,"CO-9162",3],[507,"CO-9165",2],
];
const base=process.env.NESSUS_URL?.replace(/\/+$/,"");
const access=process.env.NESSUS_ACCESS_KEY;
const secret=process.env.NESSUS_SECRET_KEY;
if(!base||!access||!secret)throw Error("Nessus environment credentials unavailable");
const root=new URL(base);
if(!["https:","http:"].includes(root.protocol))throw Error("Bad Nessus scheme");
const transport=root.protocol==="https:"?https:http;
function get(path) {
  return new Promise((resolve,reject)=>{
    const req=transport.request({
      hostname:root.hostname,port:root.port||undefined,
      method:"GET",path:root.pathname.replace(/\/$/,"")+path,
      rejectUnauthorized:process.env.NESSUS_TLS_INSECURE!=="1",
      timeout:15000,
      headers:{"X-ApiKeys":"accessKey="+access+"; secretKey="+secret,
        Accept:"application/json"}
    },res=>{
      if(res.statusCode!==200) {
        res.resume();reject(Error("Nessus GET non-200"));return;
      }
      const chunks=[];let size=0;
      res.on("data",chunk=>{
        size+=chunk.length;
        if(size>4*1024*1024)res.destroy(Error("Nessus response too large"));
        else chunks.push(chunk);
      });
      res.on("end",()=>{try{resolve(JSON.parse(Buffer.concat(chunks).toString("utf8")))}
        catch{reject(Error("Malformed Nessus JSON response"))}});
      res.on("error",reject);
    });
    req.on("timeout",()=>req.destroy(Error("Nessus read timeout")));
    req.on("error",reject);
    req.end();
  });
}
const table=[];
let failed=0,totalConfigured=0,totalRedundant=0;
for(const [folder,company,expectedDefinitions] of FOLDERS) {
  try {
    const roster=await get("/scans?folder_id="+folder);
    const rows=roster?.scans;
    if(!Array.isArray(rows)||rows.length!==expectedDefinitions||
       rows.some(r=>!Number.isSafeInteger(r?.id) || r.id<1 ||
         (r.folder_id!==undefined && r.folder_id!==folder)) ||
       new Set(rows.map(r=>r.id)).size!==rows.length) {
      table.push({company,folder,scanId:null,configuredTargets:0,
        networks:0,problems:"folder roster changed/ambiguous"});
      failed++;continue;
    }
    for(const scan of rows.sort((a,b)=>a.id-b.id)) {
      try {
        const editor=await get("/editor/scan/"+scan.id);
        const parsed=normalizeNessusDefinition(editor);
        const problems=parsed.problems.length;
        if(problems)failed++;
        else {
          totalConfigured+=parsed.exactHostCount;
          totalRedundant+=parsed.redundantHostSlots;
        }
        // Source expression values are sensitive. Categories come only from
        // fixed parser error messages, never the target strings.
        const recognized=new Map([
          ["Not one exact host/IP","non-exact-expression"],
          ["Unsupported hostname/target expression","unsupported-expression"],
          ["IPv6 requires a separately reviewed canonicalizer","ipv6-review-required"],
          ["Invalid IPv4","invalid-ip"],
          ["Invalid prefix","invalid-prefix"],
          ["Network expansion exceeds bounded review limit","cidr-too-large"],
          ["Total target count exceeds bounded review limit","scan-too-large"],
        ]);
        const problemCategories=[...new Set(parsed.problems.map(p=>
          recognized.get(p.reason) ?? "other-unsupported-expression"))].sort();
        table.push({
          company,folder,scanId:scan.id,
          expressions:parsed.expressionCount,
          configuredTargets:parsed.exactHostCount,
          redundantHostSlots:parsed.redundantHostSlots,
          networks:parsed.cidrExpressions,
          problems:problems?"unresolved-target-expression":"none",
          problemCategories:problemCategories.join(",")||"none"
        });
      }catch{
        failed++;
        table.push({company,folder,scanId:scan.id,expressions:null,
          configuredTargets:null,networks:null,
          problems:"editor read/parse failed"});
      }
    }
  }catch{
    failed++;
    table.push({company,folder,scanId:null,expressions:null,
      configuredTargets:null,networks:null,problems:"folder read failed"});
  }
}
console.log("=== PER-NESSUS-SCAN CONFIGURED TARGETS (READ ONLY) ===");
console.table(table);
console.log(JSON.stringify({
  expectedDefinitions:19,readDefinitions:table.filter(x=>x.scanId!==null).length,
  fullyParsedDefinitions:table.filter(x=>x.scanId!==null && x.problems==="none").length,
  configuredHostSlotsAcrossParsedDefinitions:totalConfigured,
  redundantHostSlotsAcrossParsedDefinitions:totalRedundant,
  unresolved:failed,executedNessusGreenboneParityVerified:false,
  canLaunchGreenbone:false
},null,2));
console.log("IMPORTANT: scans are individual definitions; totals may overlap.");
console.log("Repeated targets within one definition count once; redundant slots are visible.");
console.log("CIDR expansion is a bounded planning comparison, not a launch list.");
console.log("No target identities, customer addresses or API keys were displayed.");
console.log("NO SCANS STARTED. NO CUSTOMER RECORDS CHANGED.");
if(failed)process.exitCode=2;
