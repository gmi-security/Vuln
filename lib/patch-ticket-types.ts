import type { PatchRequest } from "./patch-request";
export type PatchTicketSummary = {
  id: string; cve: string; state: "prepared" | "creating" | "uncertain" | "failed" | "created";
  preparedBy: string; createdBy: string | null; preparedAt: string; updatedAt: string;
  hostCount: number; tenantIds: string[]; company: string | null; board: string | null;
  ticketId: number | null; ticketUrl: string | null; ticketStatus: string | null; closed: boolean;
  attachmentState: "not_started" | "uploading" | "pending" | "attached"; error: string | null;
};
export type PatchTicketDetail = { request: PatchTicketSummary; packet: PatchRequest };
export function automatedTicketBody(packet: Pick<PatchRequest, "body" | "cve">): string {
  return packet.body.replace("PATCH REQUEST — MANUAL CONNECTWISE ENTRY", "PATCH REQUEST")
    .replace(`Attach ${packet.cve}-patch-request.csv. No ticket has been sent to ConnectWise.`, `Affected assets and their recommended remediations are in ${packet.cve}-patch-request.csv.`);
}
export function patchTicketState(row: PatchTicketSummary): string {
  if (row.ticketId) return row.closed ? "Closed in ConnectWise · fix unverified" : row.attachmentState === "attached" ? "Ticket linked" : "Ticket linked · CSV pending";
  return ({ prepared: "Draft prepared", creating: "Creating ticket", uncertain: "Check creation outcome", failed: "Creation rejected", created: "Ticket linked" })[row.state];
}
