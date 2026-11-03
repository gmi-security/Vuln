/**
 * Read-only Nessus historical API shape probe.
 * Prints fixed field names, types and equality checks; no raw credentials,
 * customer names, hostnames, addresses, UUIDs, findings or endpoint URLs.
 * Run only for an operator-selected scan in its reviewed Nessus folder.
 */
import https from "node:https";
import http from "node:http";
import { fileURLToPath } from "node:url";
import { resolve } from "node:path";

const obj = value => value && typeof value === "object" && !Array.isArray(value) ? value : null;
const kind = value => value === undefined ? "missing" : value === null ? "null" :
  Array.isArray(value) ? "array" : typeof value;
const field = (data,key) => kind(obj(data)?.[key]);
const isPositive = n => Number.isSafeInteger(n) && n > 0;
const fields = (data,keys) => Object.fromEntries(keys.map(key => [key,field(data,key)]));

/**
 * Pure metadata-only summary. Every output field is explicitly whitelisted,
 * preventing accidental leakage of sensitive Nessus response properties.
 */
export function summarizeNessusHistoryShape({ ordinary, selected, pinned, host, rosterMatched, pinnedHttpStatus, hostHttpStatus }) {
  const summary = obj(ordinary), info = obj(pinned)?.info, run = obj(selected);
  const history = Array.isArray(summary?.history) ? summary.history : null;
  const pinnedRunId = obj(pinned)?.history_id ?? obj(info)?.history_id;
  const pinnedUuid = obj(pinned)?.uuid ?? obj(info)?.uuid;
  const hostInfo = obj(host)?.info;
  return {
    format: "gmi-nessus-history-shape-v1",
    approvedFolderScanMatched: rosterMatched === true,
    latestScan: {
      infoFields: fields(summary?.info,["status","scan_start","scan_end","timestamp","uuid","history_id","incomplete_targets","is_archived"]),
      historyArray: history !== null,
      historyCount: history === null ? null : Math.min(history.length,10000),
    },
    selectedCompletedHistory: {
      available: run !== null,
      fields: fields(run,["history_id","id","uuid","scan_uuid","status","creation_date","last_modification_date","time_start","time_end","incomplete_targets"]),
    },
    pinnedScan: {
      httpStatus: isPositive(pinnedHttpStatus) ? pinnedHttpStatus : null,
      rootFields: fields(pinned,["history_id","uuid","info","hosts","history"]),
      infoFields: fields(info,["history_id","uuid","status","scan_start","scan_end","timestamp","incomplete_targets","is_archived","alt_targets_used"]),
      historyIdMatches: run && isPositive(run.history_id) && pinnedRunId !== undefined
        ? pinnedRunId === run.history_id : null,
      uuidMatches: run && typeof run.uuid === "string" && pinnedUuid !== undefined
        ? pinnedUuid === run.uuid : null,
      hostCount: Array.isArray(obj(pinned)?.hosts) ? Math.min(pinned.hosts.length,10000) : null,
      firstHostIdType: Array.isArray(obj(pinned)?.hosts) && pinned.hosts.length
        ? field(pinned.hosts[0],"host_id") : "missing",
    },
    pinnedHost: {
      httpStatus: isPositive(hostHttpStatus) ? hostHttpStatus : null,
      rootFields: fields(host,["host_id","info","vulnerabilities","hostname"]),
      infoFields: fields(hostInfo,["host-fqdn","host-ip","host_start","host_end","HOST_START","HOST_END"]),
      vulnerabilitiesArray: Array.isArray(obj(host)?.vulnerabilities),
    },
  };
}

function scannerConfig() {
  const url = process.env.NESSUS_URL;
  const accessKey = process.env.NESSUS_ACCESS_KEY;
  const secretKey = process.env.NESSUS_SECRET_KEY;
  if (!url || !accessKey || !secretKey) throw Error("NESSUS_URL and both NESSUS API keys must be configured locally.");
  const base = new URL(url);
  if (!["https:","http:"].includes(base.protocol) || base.username || base.password || base.search || base.hash)
    throw Error("Unsupported scanner URL.");
  return {base,accessKey,secretKey,insecure:process.env.NESSUS_TLS_INSECURE==="1"};
}
async function getScannerJson(config,path) {
  const url = new URL(path,config.base);
  const transport = url.protocol === "https:" ? https : http;
  return new Promise((resolve,reject) => {
    const req = transport.request(url,{
      method:"GET",
      rejectUnauthorized:!config.insecure,
      timeout:15000,
      headers:{
        "X-ApiKeys":"accessKey="+config.accessKey+"; secretKey="+config.secretKey,
        Accept:"application/json",
      },
    },response=>{
      let body="", bytes=0;
      response.on("data",chunk=>{
        bytes+=chunk.length;
        if(bytes>6*1024*1024){ req.destroy(Error("Response exceeded safe metadata-probe limit.")); return; }
        body+=chunk.toString("utf8");
      });
      response.on("end",()=>{
        const status=response.statusCode??0;
        if(status<200 || status>=300 || status===204) return reject(Object.assign(Error("Nessus read unavailable."),{status}));
        try { resolve({status,body:JSON.parse(body)}); }
        catch {reject(Error("Nessus response was not JSON."));}
      });
    });
    req.on("timeout",()=>req.destroy(Error("Nessus metadata probe timed out.")));
    req.on("error",reject);
    req.end();
  });
}
async function safeRead(config,path) {
  try {return await getScannerJson(config,path);}
  catch(error){return {status:isPositive(error?.status)?error.status:null,body:null};}
}

/** No write methods. Operator chooses an exact preapproved scan/folder. */
export async function runNessusHistoricalShapeProbe() {
  const scanId=Number(process.env.NESSUS_PROBE_SCAN_ID), folderId=Number(process.env.NESSUS_PROBE_FOLDER_ID);
  if (!isPositive(scanId) || !isPositive(folderId)) throw Error("Set numeric NESSUS_PROBE_SCAN_ID and NESSUS_PROBE_FOLDER_ID.");
  const config=scannerConfig();
  const rosterResponse=await getScannerJson(config,"/scans?folder_id="+folderId);
  const roster=obj(rosterResponse.body);
  if(!Array.isArray(roster?.scans) || roster.scans.length>1000)
    throw Error("Scan roster unavailable or too large.");
  const matches=roster.scans.filter(scan=>obj(scan)?.id===scanId && obj(scan)?.folder_id===folderId);
  if(matches.length!==1)throw Error("Selected scan is not uniquely present in the chosen folder.");
  const ordinaryResponse=await getScannerJson(config,"/scans/"+scanId);
  const ordinary=ordinaryResponse.body;
  const history=Array.isArray(obj(ordinary)?.history)?ordinary.history:[];
  const selected=[...history].filter(h=>obj(h)?.status==="completed" && isPositive(obj(h)?.history_id))
    .sort((a,b)=>(Number(b.creation_date)||0)-(Number(a.creation_date)||0))[0]??null;
  let pinned=null,host=null,pinnedHttpStatus=null,hostHttpStatus=null;
  if(selected){
    const result=await safeRead(config,"/scans/"+scanId+"?history_id="+selected.history_id);
    pinned=result.body;
    pinnedHttpStatus=result.status;
    const first=Array.isArray(obj(pinned)?.hosts)?pinned.hosts[0]:null;
    const hostId=obj(first)?.host_id;
    if(isPositive(hostId)){
      const hostResult=await safeRead(config,
        "/scans/"+scanId+"/hosts/"+hostId+"?history_id="+selected.history_id);
      host=hostResult.body;
      hostHttpStatus=hostResult.status;
    }
  }
  return summarizeNessusHistoryShape({
    ordinary,selected,pinned,host,rosterMatched:true,pinnedHttpStatus,hostHttpStatus,
  });
}
if(process.argv[1] && resolve(process.argv[1])===fileURLToPath(import.meta.url)){
  runNessusHistoricalShapeProbe().then(result=>{
    process.stdout.write(JSON.stringify(result,null,2)+"\n");
  }).catch(()=>{
    process.stderr.write("Nessus historical metadata probe unavailable; no scans or settings changed. Check local configuration and selected scan/folder.\n");
    process.exitCode=2;
  });
}
