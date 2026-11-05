#!/usr/bin/env node
// Pure source-target parity model for EACH individual Nessus scan definition.
// No database, scanner API, or process side effects. This is an isolated,
// deterministic planning/validation library, never a launcher.
//
// Nessus uses configured target expressions; Greenbone should receive the
// SAME exact verified hosts/IPs for that scan, not unioned other scan folders,
// old finding assets, or entire company inventory. This is planned scope
// parity, not independent evidence either scanner actually assessed a host.
import {isIP} from "node:net";

function exact(value) {
  if (typeof value!=="string" || !value || value!==value.trim() ||
      value.length>253 || /[\s,*/\\]/.test(value) || value.includes("://") ||
      value.includes("#") || value.includes("?") || value.includes("[") ||
      value.includes("]")) throw Error("Not one exact host/IP");
  if(isIP(value)===4) return value.split(".").map(Number).join(".");
  if(isIP(value)===6) throw Error("IPv6 requires a separately reviewed canonicalizer");
  if(/^[0-9.-]+$/.test(value) ||
     !value.toLowerCase().replace(/\.$/,"").split(".").every(
       s=>/^[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?$/.test(s)
     )) throw Error("Unsupported hostname/target expression");
  return value.toLowerCase().replace(/\.$/,"");
}
function ipv4Number(s) {
  if(!/^(?:0|[1-9][0-9]{0,2})(?:\.(?:0|[1-9][0-9]{0,2})){3}$/.test(s) ||
     isIP(s)!==4) throw Error("Invalid IPv4");
  return s.split(".").reduce((n,p)=>n*256+Number(p),0)>>>0;
}
function ipv4Text(n) {
  return [(n>>>24)&255,(n>>>16)&255,(n>>>8)&255,n&255].join(".");
}
function parseExpression(expr,maxPerExpression) {
  const cidr=expr.match(/^((?:[0-9]{1,3}\.){3}[0-9]{1,3})\/([0-9]{1,2})$/);
  if(!cidr) return [exact(expr)];
  const ip=ipv4Number(cidr[1]),prefix=Number(cidr[2]);
  if(prefix>32)throw Error("Invalid prefix");
  const size=2**(32-prefix);
  if(size>maxPerExpression)throw Error("Network expansion exceeds bounded review limit");
  // For parity only, include all addresses in the literal CIDR, including
  // first and last. Do NOT infer Nessus exclusion rules or authorized hosts.
  const first=Math.floor(ip/size)*size;
  return Array.from({length:size},(_,i)=>ipv4Text(first+i));
}
export function extractNessusTargetExpressions(editor) {
  // Observed Nessus editor path: settings.basic.inputs[] with
  // id="text_targets". Refuse conflicting/missing descriptors.
  const inputs=editor?.settings?.basic?.inputs;
  if(!Array.isArray(inputs))throw Error("Nessus editor target input missing");
  const rows=inputs.filter(x=>x && (x.id==="text_targets"||x.name==="text_targets"));
  if(rows.length!==1)throw Error("Nessus target field absent/ambiguous");
  // The actual Nessus /editor/scan response on Vuln-NYC1 has
  // id="text_targets", no .value, and the saved targets in .default.
  // Some API variants expose .value. Reject divergent values instead
  // of silently selecting the wrong source.
  const field=rows[0];
  const configured=field.value;
  const savedDefault=field.default;
  if(configured!==undefined && configured!==null &&
     typeof configured!=="string")throw Error("Unexpected Nessus target value type");
  if(savedDefault!==undefined && savedDefault!==null &&
     typeof savedDefault!=="string")throw Error("Unexpected Nessus target default type");
  if(typeof configured==="string" && configured.trim() &&
     typeof savedDefault==="string" && savedDefault.trim() &&
     configured.trim()!==savedDefault.trim())
    throw Error("Conflicting Nessus configured target fields");
  const value=typeof configured==="string" && configured.trim()
    ? configured : savedDefault;
  if(typeof value!=="string" || !value.trim())throw Error("Empty configured target field");
  const expressions=value.split(/[,\r\n]+/).map(x=>x.trim()).filter(Boolean);
  if(expressions.length<1||expressions.length>10000)
    throw Error("Configured target expression count outside bounded review limits");
  return expressions;
}
export function normalizeNessusDefinition(editor,{maxHosts=4096,maxPerExpression=1024}={}) {
  const expressions=extractNessusTargetExpressions(editor);
  const hosts=new Set();
  const problems=[],networks=[];
  for(const expression of expressions){
    try{
      const list=parseExpression(expression,maxPerExpression);
      if(expression.includes("/"))networks.push({expression,count:list.length});
      for(const host of list) {
        if(hosts.has(host)) throw Error("Duplicate or overlapping target in same scan");
        hosts.add(host);
        if(hosts.size>maxHosts)throw Error("Total target count exceeds bounded review limit");
      }
    }catch(err){problems.push({expressionIndex:expressions.indexOf(expression),
      reason:err instanceof Error?err.message:"Invalid target"});}
  }
  return {expressionCount:expressions.length,exactHostCount:hosts.size,
    cidrExpressions:networks.length,cidrIpCount:networks.reduce((n,x)=>n+x.count,0),
    problems,hosts:[...hosts].sort()};
}
export function compareNessusToGreenbonePerScan(input) {
  const {companyId,nessusScanId,nessusOccurrenceId,nessusEditor,
         reviewedExactTargets,greenbonePlannedTargets}=input??{};
  if(typeof companyId!=="string"||!companyId.trim()||
     !Number.isSafeInteger(nessusScanId)||nessusScanId<1||
     typeof nessusOccurrenceId!=="string"||!nessusOccurrenceId.trim())
     throw Error("Missing exact Nessus scan/occurrence/customer identity");
  const source=normalizeNessusDefinition(nessusEditor);
  const results={mode:"per-nessus-scan-target-parity",
    companyId,nessusScanId,nessusOccurrenceId,
    configuredExpressions:source.expressionCount,
    configuredExactHostCount:source.exactHostCount,
    cidrExpressions:source.cidrExpressions,
    sourceProblems:source.problems.length,
    plannedGreenboneCount:0,approvedCount:0,
    missingFromGreenbone:0,extraInGreenbone:0,
    unauthorizedSourceTargets:0,
    status:"blocked",canDispatch:false,
    executedScanParityVerified:false};
  // No approval means no task; no silent fallback to company asset inventory.
  if(source.problems.length||!source.hosts.length||
     !Array.isArray(reviewedExactTargets)||!reviewedExactTargets.length||
     !Array.isArray(greenbonePlannedTargets)) return results;
  let approved,planned;
  try {
    approved=reviewedExactTargets.map(exact);
    planned=greenbonePlannedTargets.map(exact);
    if(new Set(approved).size!==approved.length ||
       new Set(planned).size!==planned.length) return results;
  }catch{return results;}
  const A=new Set(approved),V=new Set(planned),N=new Set(source.hosts);
  results.approvedCount=A.size;
  results.plannedGreenboneCount=V.size;
  results.missingFromGreenbone=[...N].filter(x=>!V.has(x)).length;
  results.extraInGreenbone=[...V].filter(x=>!N.has(x)).length;
  results.unauthorizedSourceTargets=[...N].filter(x=>!A.has(x)).length;
  results.status=results.unauthorizedSourceTargets?"scope-review-required":
    results.missingFromGreenbone||results.extraInGreenbone?"targets-differ":"planned-targets-match";
  // This is NOT a live dispatch implementation.
  return results;
}
