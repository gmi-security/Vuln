import type {PoolClient} from "pg";
import {applicationDatabase} from "./persist";
import {DashboardError} from "./elastic-dashboard";
import {shadowCveBindings,readShadowComparisonPool,resolveShadowComparisonCustomer} from "./shadow-cve-preview";
import {shadowPlatformRequest,readShadowPlatformComparison} from "./db/shadow-platform-comparison.mjs";

export async function readShadowPlatformPreview(raw:Record<string,string>){
  if(process.env.VULN_SHADOW_CVE_READS!=="true")throw new DashboardError("Not found",404);
  let request;
  try{request=shadowPlatformRequest(raw);}catch{throw new DashboardError("Invalid comparison request or cursor.",400);}
  const binding=shadowCveBindings(process.env.VULN_SHADOW_CVE_CUSTOMERS).find(b=>b.companyId===request.companyId);
  if(binding?.selection!=="published")throw new DashboardError("No published Defender comparison is configured for this customer.",409);
  const app=applicationDatabase(),url=process.env.VULN_SHADOW_DATABASE_URL;
  if(!app||!url)throw new DashboardError("Comparison storage is unavailable.",503);
  let application:PoolClient|undefined,shadow:PoolClient|undefined;
  try{
    application=await app.connect();
    const {company}=await resolveShadowComparisonCustomer(application,request.companyId);
    // Metadata is complete before connecting to evidence storage. Ticket pools,
    // enrichment and all vendor clients are unnecessary for summary/page reads.
    application.release();application=undefined;
    shadow=await readShadowComparisonPool("shadow",url).connect();
    const data=await readShadowPlatformComparison(shadow,request);
    return {...data,companyName:company.name};
  }catch(error){
    if(error instanceof Error&&"status" in error&&[400,404,409,413,503].includes(Number(error.status)))throw new DashboardError(error.message,Number(error.status));
    throw error;
  }finally{shadow?.release();application?.release();}
}
