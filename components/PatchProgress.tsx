"use client";
import {useEffect,useState} from 'react';
import {dashboardRequest} from '@/lib/dashboard-browser-client';
import type {ProgressObservation,ProgressSummary} from '@/lib/patch-progress';

type Trend={source:string;observedAt:string;count:number;unit:string};
type Ticket={kind:string;requestId:string;metadata:{ticketId:number;ticketUrl?:string;ticketStatus?:string;closed?:boolean;originalDevices:number;title:string;cves:string[]};
  checkState:string;error?:string;lastAttemptAt:string;checkedAt?:string;summary?:ProgressSummary;newDevices?:Record<string,number|null>;sourceTimes?:Record<string,string|null>};
type Result={state:string;tickets:Ticket[];trends:Trend[];hasMore:boolean;history?:{requestId:string;kind:string;checkedAt:string;summary:ProgressSummary}[]};
const number=(n:number)=>n.toLocaleString();
const date=(s:string|null|undefined)=>s?new Date(s).toLocaleString():'Not available';
const button='rounded-lg border border-zinc-700 px-3 py-1.5 text-sm text-zinc-200 hover:bg-zinc-800 disabled:opacity-40';
const label=(source:string)=>source==='total'?'All imported sources':source==='crowdstrike'?'CrowdStrike':source==='defender'?'Defender':source==='nessus'?'Nessus':source;
function safeLink(value:string|undefined){try{const u=new URL(value||'');return u.protocol==='https:'?u.href:undefined;}catch{return undefined;}}

function TrendChart({points}:{points:Trend[]}){
  const last=points.at(-1)!,previous=points.at(-2),change=previous?last.count-previous.count:null;
  const max=Math.max(1,...points.map(p=>p.count)),start=Date.parse(points[0].observedAt),end=Date.parse(last.observedAt);
  const positions=points.map((p,i)=>({x:end===start?300:30+540*(Date.parse(p.observedAt)-start)/(end-start),y:150-125*p.count/max,p,i}));
  return <div className="rounded-xl border border-zinc-800 bg-zinc-950 p-4">
    <div className="flex flex-wrap items-center justify-between gap-4"><div><p className="text-sm text-zinc-300">{label(last.source)}</p><p className="mt-1 text-3xl font-semibold text-white">{number(last.count)}</p></div>
      <p className={`text-sm ${change===null?'text-zinc-300':change>0?'text-amber-300':change<0?'text-emerald-300':'text-zinc-300'}`}>{change===null?'First recorded count':`${change>0?'↑':change<0?'↓':'→'} ${number(Math.abs(change))} ${change>0?'more':change<0?'fewer':'change'} since previous completed import`}</p></div>
    <svg viewBox="0 0 600 180" role="img" aria-label={`${label(last.source)} open findings: ${points.map(p=>`${new Date(p.observedAt).toLocaleDateString()}: ${number(p.count)}`).join('; ')}`} className="mt-3 h-44 w-full">
      <path d="M30 20V150H570" fill="none" stroke="#52525b"/>
      <text x="30" y="14" fill="#d4d4d8" fontSize="11">{number(max)}</text>
      <polyline points={positions.map(p=>`${p.x},${p.y}`).join(' ')} fill="none" stroke="#f87171" strokeWidth="3"/>
      {positions.map(({x,y,p,i})=><circle key={i} cx={x} cy={y} r="4" fill="#fca5a5"><title>{date(p.observedAt)}: {number(p.count)}</title></circle>)}
      <text x="30" y="174" fill="#d4d4d8" fontSize="11">{new Date(points[0].observedAt).toLocaleDateString()}</text><text x="570" y="174" textAnchor="end" fill="#d4d4d8" fontSize="11">{new Date(last.observedAt).toLocaleDateString()}</text>
    </svg><p className="text-xs text-zinc-300">{last.unit}. Recorded {date(last.observedAt)}.</p>
    {points.length===1&&<p className="mt-2 text-sm text-zinc-300">The next completed import will add a comparison point.</p>}
    <details className="mt-3 text-sm text-zinc-300"><summary className="cursor-pointer">View recorded counts</summary><div className="mt-2 max-h-56 overflow-auto"><table className="w-full text-left"><thead><tr><th>Recorded</th><th className="text-right">Open</th></tr></thead><tbody>{[...points].reverse().map((p,i)=><tr key={i}><td className="py-1">{date(p.observedAt)}</td><td className="text-right">{number(p.count)}</td></tr>)}</tbody></table></div></details>
  </div>;
}

function DeviceDetails({companyId,ticket}:{companyId:string;ticket:Ticket}){
  const [offset,setOffset]=useState(0),[rows,setRows]=useState<ProgressObservation[]|null>(null),[more,setMore]=useState(false),[error,setError]=useState('');
  useEffect(()=>{const controller=new AbortController();setRows(null);setError('');
    dashboardRequest<{rows:ProgressObservation[];hasMore:boolean}>(`patch-progress?companyId=${encodeURIComponent(companyId)}&kind=${ticket.kind}&requestId=${ticket.requestId}&offset=${offset}`,{signal:controller.signal})
      .then(r=>{if(!controller.signal.aborted){setRows(r.rows);setMore(r.hasMore);}}).catch(e=>{if(!controller.signal.aborted)setError(e.message);});return()=>controller.abort();
  },[companyId,ticket.kind,ticket.requestId,offset]);
  if(error)return <p role="alert" className="mt-3 text-amber-300">{error}</p>;
  if(!rows)return <p role="status" className="mt-3 text-zinc-300">Loading saved device evidence…</p>;
  return <div className="mt-4"><div className="max-h-80 overflow-auto rounded-lg border border-zinc-800"><table className="w-full text-left text-sm"><thead className="sticky top-0 bg-zinc-900 text-zinc-200"><tr>{['Device','CVE','Source','Progress','Evidence date','Reason'].map(h=><th key={h} className="p-3">{h}</th>)}</tr></thead><tbody>{rows.map(r=><tr key={r.key} className="border-t border-zinc-800 text-zinc-200"><td className="p-3 break-all">{r.hostname||r.hostId}</td><td className="p-3 whitespace-nowrap">{r.cve}</td><td className="p-3">{label(r.source)}</td><td className={`p-3 ${r.state==='clear'?'text-emerald-300':r.state==='detected'?'text-amber-300':'text-zinc-300'}`}>{r.state==='clear'?(r.source==='crowdstrike'?'Fixed':'No longer detected'):r.state==='detected'?'Still detected':r.source==='defender'?'Waiting for fresh device data':'Not verified'}{r.reappeared&&' · Reappeared'}</td><td className="p-3">{date(r.assessmentAt)}{r.state==='clear'&&r.retained&&<span className="block text-xs text-zinc-300">Earlier verification retained</span>}</td><td className="p-3 min-w-60">{r.reason}</td></tr>)}</tbody></table></div>
    <div className="mt-3 flex items-center gap-3"><button className={button} disabled={!offset} onClick={()=>setOffset(n=>Math.max(0,n-100))}>Previous devices</button><span className="text-sm text-zinc-300">Rows {rows.length?offset+1:0}–{offset+rows.length}</span><button className={button} disabled={!more} onClick={()=>setOffset(n=>n+100)}>Next devices</button></div></div>;
}

export default function PatchProgress({companyId,view}:{companyId:string;view:'overview'|'tickets'}){
  const [data,setData]=useState<Result|null>(null),[error,setError]=useState(''),[retry,setRetry]=useState(0),[offset,setOffset]=useState(0),[expanded,setExpanded]=useState<string|null>(null);
  useEffect(()=>{const controller=new AbortController();setData(null);setError('');setExpanded(null);
    dashboardRequest<Result>(`patch-progress?companyId=${encodeURIComponent(companyId)}&offset=${offset}`,{signal:controller.signal})
      .then(r=>{if(!controller.signal.aborted)setData(r);}).catch(e=>{if(!controller.signal.aborted)setError(e.message);});return()=>controller.abort();
  },[companyId,offset,retry]);
  const title=view==='overview'?'Open vulnerabilities over time':'Patch verification progress';
  return <section aria-label={title} className="rounded-2xl border border-zinc-800 bg-zinc-950/60 p-5">
    <div className="flex items-center justify-between gap-4"><h2 className="text-xl font-semibold text-white">{title}</h2><button className={button} onClick={()=>setRetry(n=>n+1)}>Refresh</button></div>
    <p className="mt-2 text-sm text-zinc-300">{view==='overview'?'Counts from completed imports, saved for the selected customer. A change in scope or newly discovered devices can also change the total.':'Tracks the original devices and CVEs on tickets created from this platform. Ticket closure and scanner verification are separate.'}</p>
    {error?<p role="alert" className="mt-4 text-amber-300">{error}</p>:!data?<p role="status" className="mt-4 text-zinc-300">Loading saved progress…</p>:data.state==='not-installed'?<p className="mt-4 text-zinc-300">Progress tracking is awaiting its database migration.</p>:view==='overview'?<div className="mt-5 space-y-4">
      {!data.trends.length?<p className="text-zinc-300">Waiting for the first completed import count. Failed or incomplete imports are not recorded as zero.</p>:<>{data.trends.some(p=>p.source==='total')&&<TrendChart points={data.trends.filter(p=>p.source==='total')}/>}<details className="text-zinc-200"><summary className="cursor-pointer">Counts by connector</summary><div className="mt-3 grid gap-4 lg:grid-cols-2">{[...new Set(data.trends.map(p=>p.source))].filter(s=>s!=='total').map(source=><TrendChart key={source} points={data.trends.filter(p=>p.source===source)}/>)}</div></details></>}
    </div>:<div className="mt-5 space-y-4">
      <p className="text-sm text-zinc-300">CrowdStrike: disappearance from the next completed matching import is marked Fixed. Defender and Nessus: no longer detected requires later device assessment evidence. Earlier verified Defender fixes retain their evidence date until new detection. Not verified means fresh evidence is still needed.</p>
      {!data.tickets.length&&<p className="text-zinc-300">No ticket progress has been recorded yet. The background worker checks created tickets automatically; drafts are not counted.</p>}
      {data.tickets.map(t=>{const key=t.kind+':'+t.requestId,s=t.summary,link=safeLink(t.metadata.ticketUrl);return <article key={key} className="rounded-xl border border-zinc-800 bg-zinc-950 p-4">
        <div className="flex flex-wrap items-start justify-between gap-4"><div><h3 className="font-semibold text-white">{link?<a href={link} target="_blank" rel="noreferrer" className="underline">ConnectWise #{t.metadata.ticketId}</a>:`ConnectWise #${t.metadata.ticketId}`} · {t.metadata.title}</h3><p className="mt-1 text-sm text-zinc-300">{t.metadata.cves.slice(0,5).join(', ')}{t.metadata.cves.length>5?` +${t.metadata.cves.length-5} more`:''}</p><p className="mt-1 text-sm text-zinc-300">Ticket: {t.metadata.ticketStatus|| (t.metadata.closed?'Closed':'Status unavailable')}</p></div><p className="text-sm text-zinc-300">{number(t.metadata.originalDevices)} original devices</p></div>
        {t.checkState!=='ready'&&<p role="status" className="mt-3 text-amber-300">{t.checkState==='baseline-unavailable'?'Baseline unavailable. ':t.checkState==='failed'?'Latest check incomplete. ':'Comparison pending. '}{t.error||'Previously saved evidence below has not yet been refreshed.'}</p>}
        {s&&<><div className="mt-4 grid gap-3 sm:grid-cols-3">{[['Still detected',s.detected,'text-amber-300'],['Fixed / no longer detected',s.clear,'text-emerald-300'],['Not verified',s.unknown,'text-zinc-200']].map(([name,n,color])=><div key={String(name)} className="rounded-lg bg-zinc-900 p-3"><p className="text-sm text-zinc-300">{name}</p><p className={`mt-1 text-2xl font-semibold ${color}`}>{number(Number(n))}</p></div>)}</div>
          <p className="mt-3 text-sm text-zinc-300">Compared {date(t.checkedAt)}. {s.reappeared>0&&`${number(s.reappeared)} devices have reappeared.`}</p>
          {Object.entries(t.newDevices||{}).map(([source,n])=><p key={source} className="mt-1 text-sm text-zinc-300">{label(source)}: {n===null?'Additional-device count unavailable':`${number(n)} additional devices now report these CVEs`} · outside this ticket’s original device list.</p>)}
          <button className={`${button} mt-3`} aria-expanded={expanded===key} onClick={()=>setExpanded(expanded===key?null:key)}>{expanded===key?'Hide device evidence':'View device evidence'}</button>
          {expanded===key&&<><DeviceDetails companyId={companyId} ticket={t}/><details className="mt-3 text-sm text-zinc-300"><summary className="cursor-pointer">Progress history</summary><div className="max-h-56 overflow-auto"><table className="mt-2 w-full text-left"><thead><tr><th>Compared</th><th>Detected</th><th>Fixed / clear</th><th>Unverified</th></tr></thead><tbody>{data.history?.filter(h=>h.kind===t.kind&&h.requestId===t.requestId).map(h=><tr key={h.checkedAt}><td className="py-1">{date(h.checkedAt)}</td><td>{number(h.summary.detected)}</td><td>{number(h.summary.clear)}</td><td>{number(h.summary.unknown)}</td></tr>)}</tbody></table></div></details></>}
        </>}
      </article>;})}
      <div className="flex gap-3"><button className={button} disabled={!offset} onClick={()=>setOffset(n=>Math.max(0,n-20))}>Previous tickets</button><button className={button} disabled={!data.hasMore} onClick={()=>setOffset(n=>n+20)}>Next tickets</button></div>
    </div>}
  </section>;
}
