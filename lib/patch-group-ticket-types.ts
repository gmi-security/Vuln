import type { PatchGroup } from "./patch-request";
export type PatchGroupTicketSummary = {
  id: string; cves: string[]; remediationId: string; tenantId: string;
  state: "prepared" | "creating" | "uncertain" | "failed" | "created";
  preparedBy: string; createdBy: string | null; preparedAt: string; updatedAt: string;
  hostCount: number; findingCount: number; company: string | null; board: string | null;
  ticketId: number | null; ticketUrl: string | null; ticketStatus: string | null; closed: boolean;
  attachmentState: "not_started" | "uploading" | "pending" | "attached"; error: string | null;
};
export type PatchGroupTicketDetail = { request: PatchGroupTicketSummary; group: PatchGroup };
export function automatedGroupTicketBody(group: Pick<PatchGroup, "ticketBody" | "label">): string {
  return group.ticketBody.replace("PATCH REQUEST — MANUAL CONNECTWISE ENTRY", "PATCH REQUEST")
    .replace(`Attach ${group.label}-patch-request.csv. No ticket has been sent to ConnectWise.`, `Affected assets are in ${group.label}-patch-request.csv.`);
}
export function patchGroupTicketState(row: PatchGroupTicketSummary): string {
  if (row.ticketId) return row.closed ? "Closed in ConnectWise · fix unverified" : row.attachmentState === "attached" ? "Ticket linked" : "Ticket linked · CSV pending";
  return ({ prepared: "Draft prepared", creating: "Creating ticket", uncertain: "Check creation outcome", failed: "Creation rejected", created: "Ticket linked" })[row.state];
}
