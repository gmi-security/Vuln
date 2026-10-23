"use client";
import {useEffect,useRef,useState} from "react";
import CompactPatchWorklist from "./CompactPatchWorklist";
import {dashboardRequest} from "@/lib/dashboard-browser-client";
import type {PriorityWorklist,PriorityRow} from "@/lib/patch-priority";
type Result=PriorityWorklist&{companyId:string;calculatedAt:string};
export default function PatchPriorityWorklist({companyId,canManage}:{companyId:string;canManage:boolean}){
  const [data,setData]=useState<Result|null>(null);
  const [loading,setLoading]=useState(true),[error,setError]=useState(""),[version,setVersion]=useState(0),[busy,setBusy]=useState<string|null>(null);
  const [message,setMessage]=useState<{id:string;text:string;error:boolean}|null>(null),alive=useRef(true),inFlight=useRef(false);
  useEffect(()=>{alive.current=true;return()=>{alive.current=false;};},[]);
  useEffect(()=>{
    let active=true;
    const controller=new AbortController(),timeout=setTimeout(()=>controller.abort(),45000);setLoading(true);setError("");
    dashboardRequest<Result>(`patch-priority?companyId=${encodeURIComponent(companyId)}`,{signal:controller.signal},45_000)
      .then(result=>{if(result.companyId!==companyId)throw Error("Worklist returned a different customer.");if(!controller.signal.aborted)setData(result);})
      .catch(cause=>{if(active)setError(controller.signal.aborted?"Priority worklist took too long. Try Refresh.":cause instanceof Error?cause.message:"Could not load the worklist.");})
      .finally(()=>{clearTimeout(timeout);if(active)setLoading(false);});
    return()=>{active=false;clearTimeout(timeout);controller.abort();};
  },[companyId,version]);
  async function prepare(row:PriorityRow){
    if(inFlight.current)return;inFlight.current=true;setBusy(row.id);setMessage(null);
    try{const result=await dashboardRequest<{companyId:string;groups:{id:string}[]}>("remediation-ticket",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({companyId,id:row.id})});
      if(result.companyId!==companyId||!result.groups?.length)throw Error("No draft was confirmed. Check Tickets before retrying.");
      if(alive.current){setMessage({id:row.id,text:`${result.groups.length} draft${result.groups.length===1?"":"s"} prepared for review.`,error:false});setVersion(v=>v+1);}}
    catch(cause){if(alive.current)setMessage({id:row.id,text:cause instanceof Error?cause.message:"Could not prepare draft.",error:true});}
    finally{inFlight.current=false;if(alive.current)setBusy(null);}
  }
  const current=data?.companyId===companyId?data:null;
  return <CompactPatchWorklist key={companyId} companyId={companyId} canManage={canManage} data={current} loading={loading} error={error} busy={busy} message={message}
    refresh={()=>setVersion(v=>v+1)} prepare={prepare}/>;
}
