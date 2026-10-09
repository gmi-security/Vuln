import type { Pool } from "pg";
import { createSpotlightSummaryStore } from "./spotlight-summary-store";
import { createSpotlightSummaryJobs, summaryCustomers, SummaryLeaseLost } from "./spotlight-summary-jobs";

export function summaryWorkerSettings(env:Record<string,string|undefined>) {
  if(env.VULN_SPOTLIGHT_SUMMARY_WORKER_ENABLED!=='true') return {enabled:false as const};
  const customers=summaryCustomers((env.VULN_SPOTLIGHT_SUMMARY_CUSTOMERS??'').split(',').map(v=>v.trim()));
  if(!env.DATABASE_URL) throw new Error("DATABASE_URL is required for the enabled summary worker.");
  return {enabled:true as const,customers};
}

/** Polling belongs only in the dedicated CLI. Importing this module starts nothing. */
export function createSpotlightSummaryWorker(db:Pool) {
  const jobs=createSpotlightSummaryJobs(db),store=createSpotlightSummaryStore(db);
  async function tick(customers:readonly string[],signal?:AbortSignal) {
    summaryCustomers(customers);
    if(signal?.aborted) return {state:'stopped' as const};
    const enqueued=await jobs.discover(customers);
    const job=await jobs.claim(customers);
    if(!job) return {state:'idle' as const,enqueued};
    let heartbeatAt=0,scanned=0;
    try {
      const result=await store.build(job.companyId,'dedicated-summary-worker',{
        expectedRunId:job.runId,signal,
        checkpoint:async progress=>{
          scanned=progress;
          if(Date.now()-heartbeatAt>=15000) {await jobs.heartbeat(job,progress);heartbeatAt=Date.now();}
        },
        beforePublish:async client=>{await jobs.heartbeat(job,scanned,client);},
      });
      const outcome=result.state==='built'||result.state==='reused' ? 'succeeded' : result.state==='busy' ? 'busy' : 'superseded';
      const acknowledged=await jobs.finish(job,outcome);
      return {state:acknowledged ? outcome : 'lease-lost',companyId:job.companyId,runId:job.runId};
    } catch(error) {
      if(error instanceof SummaryLeaseLost) return {state:'lease-lost' as const,companyId:job.companyId,runId:job.runId};
      const acknowledged=await jobs.finish(job,signal?.aborted?'worker-stopped':'build-failed');
      return {state:acknowledged?'retry-or-failed':'lease-lost',companyId:job.companyId,runId:job.runId};
    }
  }
  return {assertReady:jobs.assertReady,tick,status:jobs.list};
}
