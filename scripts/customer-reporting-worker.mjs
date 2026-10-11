// Opt-in dedicated process. The disabled path loads neither pg nor credentials.
import {createRequire} from 'node:module';
import {setTimeout as delay} from 'node:timers/promises';
import {reportingWorkerSettings,createCustomerReportingWorker} from '../lib/db/customer-reporting-worker.mjs';
const log=(event,details={})=>console.log(JSON.stringify({worker:'customer-reporting',event,...details}));
async function main(){
 const settings=reportingWorkerSettings(process.env);
 if(!settings.enabled){log('disabled');return;}
 const args=process.argv.slice(2),retry=args[0]==='--retry-failed';
 if(retry){
  if(args.length!==3||!settings.customers.includes(args[1])||!/^\d+$/.test(args[2])||Number(args[2])<1||!Number.isSafeInteger(Number(args[2])))throw Error('invalid-retry-scope');
 }else if(args.length>1||(args.length===1&&args[0]!=='--once'))throw Error('invalid-arguments');
 const require=createRequire(import.meta.url),{Pool}=require('pg');
 const {createReportingSectionsAccumulator}=require('../.worker-build/customer-reporting/lib/reporting-sections-accumulator.js');
 const options={connectionTimeoutMillis:5000,statement_timeout:15000,application_name:'vuln-customer-reporting-worker'};
 const source=new Pool({...options,connectionString:settings.sourceUrl,max:2}),target=new Pool({...options,connectionString:settings.targetUrl,max:4});
 const controller=new AbortController(),stop=()=>controller.abort();
 const connectionLost=()=>{log('connection-lost');process.exitCode=1;stop();};
 source.on('error',connectionLost);target.on('error',connectionLost);process.on('SIGTERM',stop);process.on('SIGINT',stop);
 let lock,owned=false;
 try{
  const worker=createCustomerReportingWorker(source,target,createReportingSectionsAccumulator,{mode:settings.mode});await worker.assertReady();
  lock=await target.connect();lock.on('error',connectionLost);
  owned=(await lock.query('SELECT pg_try_advisory_lock(804259,1) owned')).rows[0].owned;
  if(!owned){log('already-running');if(retry)process.exitCode=1;return;}
  if(retry){log('requeued',await worker.retryFailed(args[1],Number(args[2])));return;}
  log('started',{customers:settings.customers.length});
  while(!controller.signal.aborted){
   try{
    const result=await worker.tick(settings.customers,controller.signal);log('tick',result);
    if(process.argv.includes('--once')&&(result.unavailable>0||['retry-or-superseded','lease-lost'].includes(result.state)))process.exitCode=1;
   }
   catch{log('tick-failed');if(process.argv.includes('--once'))process.exitCode=1;}
   if(process.argv.includes('--once')||controller.signal.aborted)break;
   await delay(60000,undefined,{signal:controller.signal}).catch(error=>{if(error.name!=='AbortError')throw error;});
  }
 }finally{
  if(owned)await lock.query('SELECT pg_advisory_unlock(804259,1)').catch(()=>{});
  lock?.release();await Promise.all([source.end(),target.end()]);
  process.off('SIGTERM',stop);process.off('SIGINT',stop);log('stopped',{peakRssMiB:Math.ceil(process.resourceUsage().maxRSS/1024)});
 }
}
main().catch(()=>{log('startup-or-shutdown-failed');process.exitCode=1;});
