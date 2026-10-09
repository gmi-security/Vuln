import type { PoolClient } from "pg";
import type { readCustomerCve } from "../customer-cve-service";
import type { Finding } from "../types";
export type ShadowCveDetail = Awaited<ReturnType<typeof readCustomerCve>> & {
  scope:"published-defender-cohort"; projectionId:string; projectionModelVersion:2;
  sourceRun:string; snapshotSavedAt:string|Date;
  enrichmentState:"available"|"unavailable"|"not-recorded";
};
export function createShadowCustomerCveReader(options:{enabled?:boolean;
  bindings:{companyId:string;source:string;projectionId:string}[];
  resolveCustomer:(id:string)=>Promise<{companyId:string;company:{id:string;name:string;isDemo?:boolean}}>;
}):(clients:{shadowClient:PoolClient;enrichmentClient:PoolClient;ticketClient:PoolClient},request:{companyId:string;cve:string})=>Promise<{
  detail:ShadowCveDetail;preparation:{findings:Finding[];excluded:Set<string>}
}>;
