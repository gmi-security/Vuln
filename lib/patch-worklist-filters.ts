import type {PriorityRow} from "./patch-priority";
import type {FixTicketStatus} from "./fix-ticket-status";

export type PatchWorklistFilters = {
  search:string; severity:string; signal:"all"|"kev"|"active"|"publicExploit";
  ticket:"all"|FixTicketStatus["state"];
};

// Filter only the bounded result already loaded by the page; preserve its priority order.
export function filterPatchWorklist(rows:PriorityRow[],filters:PatchWorklistFilters) {
  const search=filters.search.trim().toLowerCase();
  return rows.filter(row=>(filters.severity==="all"||row.severity.toUpperCase()===filters.severity.toUpperCase()) &&
    (filters.signal==="all"||row[filters.signal]===true) &&
    (filters.ticket==="all"||(row.ticketStatus?.state??"unavailable")===filters.ticket) &&
    (!search||[...row.cves,...row.products,row.remediation].some(value=>value.toLowerCase().includes(search))));
}
