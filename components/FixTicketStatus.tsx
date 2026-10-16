"use client";
import Link from "next/link";
import type {FixTicketStatus as Status} from "@/lib/fix-ticket-status";

const labels:Record<Status["state"],string>={none:"No tracked request",draft:"Draft prepared",approved:"Approved - not sent",sending:"Sending ticket",
  uncertain:"Check sending outcome",failed:"Sending failed",open:"Open ticket",partial:"Partially ticketed",closed:"Ticket closed - verify findings",
  related:"Related CVE request",unavailable:"Ticket status unavailable"};
export default function FixTicketStatus({status,companyId}:{status?:Status;companyId:string}) {
  const state=status?.state??"unavailable",href=`/remediation?companyId=${encodeURIComponent(companyId)}&view=tickets`;
  const color=state==="open" ? "border-emerald-800 bg-emerald-950/40 text-emerald-200":
    ["draft","approved","related","sending"].includes(state)?"border-sky-900 bg-sky-950/30 text-sky-200":
    state==="none" ? "border-zinc-700 text-zinc-300":"border-amber-900 bg-amber-950/30 text-amber-200";
  return <div className="mt-3 space-y-2 text-xs" aria-label="Ticket coverage">
    <span className={`inline-block rounded-md border px-2 py-1 font-medium ${color}`}>{labels[state]}</span>
    {status?.coverage && <p className="text-zinc-200">{status.coverage.coveredDevices.toLocaleString()} / {status.coverage.totalDevices.toLocaleString()} devices fully covered by open tickets
      {status.coverage.remainingDevices>0 && <span className="block text-amber-200">{status.coverage.remainingDevices.toLocaleString()} devices still need ticket coverage review.</span>}</p>}
    {state==="open" && !status?.coverage && <p className="text-zinc-300">Current device coverage has not been verified.</p>}
    {state==="related" && <p className="text-zinc-300">This CVE appears in another request. Compare its devices and required fix before creating another.</p>}
    {status?.tickets.map(ticket=><p key={ticket.id} className="text-zinc-200">
      {ticket.ticketId && ticket.url ? <a href={ticket.url} target="_blank" rel="noopener noreferrer" className="underline text-sky-300">ConnectWise #{ticket.ticketId}</a>:
        <Link href={ticket.kind==="single"?"/query-tiles":href} className="underline text-sky-300">{ticket.ticketId?`Ticket #${ticket.ticketId}`:ticket.kind==="single"?"Single-CVE request":ticket.state==="prepared" && ticket.reviewState==="approved"?"Review approved draft":"Review request"}</Link>}
      {ticket.closed ? " - closed":ticket.ticketId ? " - open":ticket.state==="uncertain"?" - sending outcome unknown":ticket.state==="creating"?" - sending":ticket.state==="failed"?" - send failed":" - not sent"}{!ticket.sameFix && " (related CVE)"}
    </p>)}
    {status?.tickets.some(t=>t.kind==="single" && !(t.ticketId && t.url)) && <p className="text-zinc-300">In Query tiles, choose All patch tickets to review single-CVE requests.</p>}
    {!!status?.more && (status.moreSingle ? <p className="text-zinc-300">{status.more} more saved requests. Check Tickets and <Link href="/query-tiles" className="text-sky-300 underline">Query tiles → All patch tickets</Link>.</p>:
      <Link href={href} className="block text-sky-300 underline">View {status.more} more in Tickets</Link>)}
    {state==="unavailable" && <p className="text-zinc-300">Check the Tickets page or refresh before preparing another request.</p>}
  </div>;
}
