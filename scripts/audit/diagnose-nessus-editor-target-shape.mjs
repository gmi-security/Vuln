#!/usr/bin/env node
// STRICTLY READ-ONLY, one Nessus scan ID. No targets, raw API JSON,
// hostnames, IPs, secrets, scanner URLs or error strings printed.
// Diagnose why a per-definition text_targets parser cannot read
// GET /editor/scan/<id> on the actual GMI Nessus deployment.
// Usage from /opt/vuln:
//   NESSUS_PROBE_SCAN_ID=9 node --env-file=.env.local /tmp/diagnose-nessus-editor-target-shape.mjs
import http from "node:http";
import https from "node:https";
const scanId=Number(process.env.NESSUS_PROBE_SCAN_ID);
if(!Number.isSafeInteger(scanId)||scanId<1||scanId>2_147_483_646)
  throw Error("Provide one numeric existing NESSUS_PROBE_SCAN_ID");
const urlText=process.env.NESSUS_URL,access=process.env.NESSUS_ACCESS_KEY,
  secret=process.env.NESSUS_SECRET_KEY;
if(!urlText||!access||!secret)throw Error("Nessus connection is not configured locally");
const base=new URL(urlText);
if(!["http:","https:"].includes(base.protocol)||base.username||base.password)
  throw Error("Invalid local Nessus URL");
const protocol=base.protocol==="https:"?https:http;
const path=base.pathname.replace(/\/$/,"")+"/editor/scan/"+scanId;
function type(v){return v===undefined?"missing":Array.isArray(v)?"array":v===null?"null":typeof v}
function has(o,k){return Object.prototype.hasOwnProperty.call(o??{},k)}
const out={mode:"READ_ONLY_EDITOR_SHAPE",scanId,requestMethod:"GET",
  httpStatus:null,networkError:false,jsonParsed:false,
  settingsType:"unknown",basicType:"unknown",inputsType:"unknown",
  inputsCount:null,textTargetsCandidateCount:0,candidates:[],
  rootHasTextTargets:false,basicHasTextTargets:false,
  fetchComplete:false};
try {
  const response=await new Promise((resolve,reject)=>{
    const req=protocol.request({hostname:base.hostname,
      port:base.port||undefined,path,method:"GET",timeout:15000,
      rejectUnauthorized:process.env.NESSUS_TLS_INSECURE!=="1",
      headers:{"X-ApiKeys":"accessKey="+access+"; secretKey="+secret,
        Accept:"application/json"}},res=>{
      const chunks=[];let bytes=0,cut=false;
      res.on("data",chunk=>{
        bytes+=chunk.length;
        if(bytes>4_000_000){cut=true;res.destroy();}
        else chunks.push(chunk);
      });
      res.on("end",()=>resolve({status:res.statusCode,body:Buffer.concat(chunks),cut}));
      res.on("error",reject);
    });
    req.on("timeout",()=>req.destroy(new Error("timeout")));
    req.on("error",reject);
    req.end();
  });
  out.httpStatus=response.status;
  out.fetchComplete=!response.cut;
  try{
    const data=JSON.parse(response.body.toString("utf8"));
    out.jsonParsed=true;
    const settings=data?.settings,basic=settings?.basic,inputs=basic?.inputs;
    out.settingsType=type(settings);
    out.basicType=type(basic);
    out.inputsType=type(inputs);
    out.inputsCount=Array.isArray(inputs)?inputs.length:null;
    out.rootHasTextTargets=has(settings,"text_targets");
    out.basicHasTextTargets=has(basic,"text_targets");
    if(Array.isArray(inputs)){
      for(const input of inputs){
        if(!input||typeof input!=="object")continue;
        if(input.id!=="text_targets"&&input.name!=="text_targets")continue;
        out.textTargetsCandidateCount++;
        const val=input.value;
        out.candidates.push({
          idMatches:input.id==="text_targets",nameMatches:input.name==="text_targets",
          valueType:type(val),valueLength:typeof val==="string"?val.length:null,
          defaultType:type(input.default),
          hasOptions:has(input,"options"),
          hasTextTargets:has(input,"text_targets")
        });
      }
    }
  }catch{}
}catch{out.networkError=true}
console.log(JSON.stringify(out,null,2));
console.log("NO SCANS, NO WRITES. Do not paste raw Nessus editor JSON.");
if(out.networkError||out.httpStatus!==200||!out.jsonParsed)process.exitCode=2;
