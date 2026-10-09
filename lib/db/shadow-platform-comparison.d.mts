import type {PoolClient} from "pg";
export type ShadowPlatformRequest={companyId:string;view:"summary"|"findings"|"cves";status:string;limit:number;cursor:string|null};
export function shadowPlatformRequest(raw:Record<string,string>):ShadowPlatformRequest;
export function readShadowPlatformComparison(client:PoolClient,request:ShadowPlatformRequest):Promise<{
  state:"available"|"unpublished";companyId:string;scope:"published-defender-cohort";
  projectionId?:string;publication?:{revision:number;publishedAt:string|Date};
  summary?:Record<string,unknown>;page?:{total:number;rows:Record<string,unknown>[];nextCursor:string|null}|null;
}>;
