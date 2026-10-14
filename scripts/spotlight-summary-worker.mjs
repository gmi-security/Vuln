// Dedicated process only. Never imported by Next or started by the web application.
import {createRequire} from 'node:module';
import {setTimeout as delay} from 'node:timers/promises';

const log=(event,details={})=>console.log(JSON.stringify({worker:'spotlight-summary',event,...details}));
async function main() {
  // The disabled path does not read configuration files, load pg or connect to a database.
  if(process.env.VULN_SPOTLIGHT_SUMMARY_WORKER_ENABLED!=='true') {log('disabled');return;}
  if(process.argv.slice(2).some(arg=>!['--once','--load-env'].includes(arg))) throw new Error('invalid-arguments');
  const require=createRequire(import.meta.url);
  const loadEnv=process.argv.includes('--load-env');
  if(loadEnv) {
    process.env.NODE_ENV='production';
    require('@next/env').loadEnvConfig(process.cwd(),false,{info(){},error(){}});
  }
  const {summaryWorkerSettings,createSpotlightSummaryWorker}=require('../.worker-build/spotlight-summary/lib/spotlight-summary-worker.js');
  const settings=summaryWorkerSettings(process.env);
  const {Pool}=require('pg');
  const db=new Pool({connectionString:process.env.DATABASE_URL,
    // Explicit app-environment mode uses the same managed-Postgres TLS settings as lib/persist.ts.
    ...(loadEnv?{ssl:{rejectUnauthorized:false}}:{}),max:4,connectionTimeoutMillis:5000,
    statement_timeout:15000,application_name:'vuln-spotlight-summary-worker'});
  const controller=new AbortController();
  const stop=()=>controller.abort();
  const connectionLost=()=>{log('connection-lost');process.exitCode=1;stop();};
  db.on('error',connectionLost);
  process.on('SIGTERM',stop);process.on('SIGINT',stop);
  let lock,owned=false;
  try {
    lock=await db.connect();lock.on('error',connectionLost);
    owned=(await lock.query('SELECT pg_try_advisory_lock(804245,1) AS owned')).rows[0].owned;
    if(!owned) {log('already-running');return;}
    const worker=createSpotlightSummaryWorker(db);
    await worker.assertReady();
    log('started',{customers:settings.customers});
    while(!controller.signal.aborted) {
      try {log('tick',await worker.tick(settings.customers,controller.signal));}
      catch {log('tick-failed');if(process.argv.includes('--once')) process.exitCode=1;}
      if(process.argv.includes('--once')||controller.signal.aborted)break;
      // Bounded polling; never a page request or an overlapping timer callback.
      await delay(60000,undefined,{signal:controller.signal}).catch(error=>{if(error.name!=='AbortError')throw error;});
    }
  } finally {
    if(owned)await lock.query('SELECT pg_advisory_unlock(804245,1)').catch(()=>{});
    lock?.release();await db.end();
    process.off('SIGTERM',stop);process.off('SIGINT',stop);
    log('stopped');
  }
}
main().catch(()=>{log('startup-or-shutdown-failed');process.exitCode=1;});
