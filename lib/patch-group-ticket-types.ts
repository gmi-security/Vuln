import type { PatchGroup } from "./patch-request";
import type { FixVerifiedState } from "./patch-ticket-types";
export type PatchGroupTicketSummary = {
  id: string; cves: string[]; remediationId: string; remediationTitle: string; tenantId: string;
  state: "prepared" | "creating" | "uncertain" | "failed" | "created";
  preparedBy: string; createdBy: string | null; preparedAt: string; updatedAt: string;
  hostCount: number; findingCount: number; company: string | null; board: string | null;
  ticketId: number | null; ticketUrl: string | null; ticketStatus: string | null; closed: boolean;
  attachmentState: "not_started" | "uploading" | "pending" | "attached"; error: string | null;
  fixVerifiedAt: string | null; fixVerifiedState: FixVerifiedState; fixStillOpenCount: number | null;
};
export type PatchGroupTicketDetail = { request: PatchGroupTicketSummary; group: PatchGroup };
export function automatedGroupTicketBody(group: Pick<PatchGroup, "ticketBody" | "label">): string {
  return group.ticketBody.replace("PATCH REQUEST — MANUAL CONNECTWISE ENTRY", "PATCH REQUEST")
    .replace(`Attach ${group.label}-patch-request.csv. No ticket has been sent to ConnectWise.`, `Affected assets are in ${group.label}-patch-request.csv.`);
}
export function patchGroupTicketState(row: PatchGroupTicketSummary): string {
  if (row.ticketId) {
    const verified = row.fixVerifiedState === "verified" ? " · fix verified"
      : row.fixVerifiedState === "still_open" ? ` · ${row.fixStillOpenCount} device${row.fixStillOpenCount === 1 ? "" : "s"} still open`
      : row.closed ? " · fix unverified" : "";
    return `${row.closed ? "Closed in ConnectWise" : row.attachmentState === "attached" ? "Ticket linked" : "Ticket linked · CSV pending"}${verified}`;
  }
  return ({ prepared: "Draft prepared", creating: "Creating ticket", uncertain: "Check creation outcome", failed: "Creation rejected", created: "Ticket linked" })[row.state];
}
