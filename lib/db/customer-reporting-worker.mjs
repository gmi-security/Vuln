import {randomUUID} from 'node:crypto';
import {inspectCustomerReportingInput,buildCustomerReportingSections} from './customer-reporting-sections.mjs';
const requireValue=(ok,message)=>{if(!ok)throw Error(message);};
export function reportingWorkerSettings(env){
 if(env.VULN_REPORTING_WORKER_ENABLED!=='true')return {enabled:false};
 const customers=(env.VULN_REPORTING_WORKER_CUSTOMERS??'').split(',').map(v=>v.trim());
 requireValue(customers.length>0&&customers.length<=50&&new Set(customers).size===customers.length&&
  customers.every(id=>/^[A-Za-z0-9][A-Za-z0-9_-]{0,99}$/.test(id)),'Explicit reporting worker customers required');
 requireValue(env.VULN_REPORTING_SOURCE_URL&&env.VULN_REPORTING_DATABASE_URL,'Explicit reporting source and target storage required');
 return {enabled:true,customers,sourceUrl:env.VULN_REPORTING_SOURCE_URL,targetUrl:env.VULN_REPORTING_DATABASE_URL};
}
const clearLease='claimed_revision=NULL,lease_token=NULL,lease_until=NULL';
const leaseLost=()=>Object.assign(Error('Reporting job lease lost'),{code:'report-lease-lost'});

// Polling belongs only in the dedicated CLI. No timers or imports in page code.
export function createCustomerReportingWorker(sourcePool,targetPool,createAccumulator){
 async function assertReady(){
  const client=await targetPool.connect();
  try{
   const {rows:[g]}=await client.query("SELECT current_database() db,current_setting('data_directory') dir,current_setting('listen_addresses') listen,to_regclass('customer_reporting_jobs') jobs,to_regclass('customer_reporting_sections') reports");
   requireValue(/^vuln2_reporting_test_[a-f0-9]+$/.test(g.db)&&g.dir.startsWith('/home/codex/vuln-recovery/')&&!g.listen&&g.jobs&&g.reports,
    'Private reporting target and explicit migrations required');
  }finally{client.release();}
 }
 async function discover(companyId){
  await assertReady();
  const source=await sourcePool.connect();let input;
  try{input=await inspectCustomerReportingInput(source,companyId);}finally{source.release();}
  // Fingerprint changes cover committed findings, workflow, scans, assets and
  // history. Refresh before TTL even when the source is unchanged. No rebuild
  // is ever enqueued by a page read.
  const {rows}=await targetPool.query(`INSERT INTO customer_reporting_jobs(company_id,requested_revision,requested_fingerprint,state)
   VALUES($1,1,$2,'queued') ON CONFLICT(company_id) DO UPDATE SET
    requested_revision=customer_reporting_jobs.requested_revision+1,requested_fingerprint=EXCLUDED.requested_fingerprint,
    state=CASE WHEN customer_reporting_jobs.state='running' THEN 'running' ELSE 'queued' END,
    attempts=CASE WHEN customer_reporting_jobs.state='running' THEN customer_reporting_jobs.attempts ELSE 0 END,
    available_at=CASE WHEN customer_reporting_jobs.state IN ('queued','running') THEN customer_reporting_jobs.available_at ELSE now() END,
    requested_at=CASE WHEN customer_reporting_jobs.state IN ('queued','running') THEN customer_reporting_jobs.requested_at ELSE now() END,
    updated_at=now(),last_error_code=NULL
   WHERE customer_reporting_jobs.requested_fingerprint<>EXCLUDED.requested_fingerprint OR
    (customer_reporting_jobs.state='succeeded' AND NOT EXISTS(SELECT 1 FROM customer_reporting_sections r WHERE r.company_id=$1
      AND r.source_fingerprint=$2 AND r.expires_at>now()+interval '5 minutes')) RETURNING company_id`,[companyId,input.fingerprint]);
  return rows.length;
 }
 async function claim(customers){
  await assertReady();
  const client=await targetPool.connect();
  try{
   await client.query('BEGIN');
   await client.query("SET LOCAL statement_timeout='5s';SET LOCAL lock_timeout='2s'");
   await client.query(`UPDATE customer_reporting_jobs SET
    state=CASE WHEN requested_revision<>claimed_revision THEN 'queued' WHEN attempts<3 THEN 'retry' ELSE 'failed' END,
    attempts=CASE WHEN requested_revision<>claimed_revision THEN 0 ELSE attempts END,
    last_error_code='lease-expired',available_at=now(),updated_at=now(),${clearLease}
    WHERE company_id=ANY($1::text[]) AND state='running' AND lease_until<=now()`,[customers]);
   const {rows:[job]}=await client.query(`WITH next AS (SELECT company_id FROM customer_reporting_jobs
    WHERE company_id=ANY($1::text[]) AND state IN ('queued','retry') AND attempts<3 AND available_at<=now()
    ORDER BY available_at,requested_at,company_id FOR UPDATE SKIP LOCKED LIMIT 1)
    UPDATE customer_reporting_jobs j SET state='running',attempts=attempts+1,claimed_revision=requested_revision,
    lease_token=$2,lease_until=now()+interval '120 seconds',updated_at=now() FROM next WHERE j.company_id=next.company_id
    RETURNING j.company_id AS "companyId",j.claimed_revision AS revision,j.requested_fingerprint AS fingerprint,j.lease_token AS token`,[customers,randomUUID()]);
   await client.query('COMMIT');return job??null;
  }catch(error){await client.query('ROLLBACK').catch(()=>{});throw error;}finally{client.release();}
 }
 async function heartbeat(job){
  await assertReady();
  const result=await targetPool.query(`UPDATE customer_reporting_jobs SET lease_until=now()+interval '120 seconds',updated_at=now()
   WHERE company_id=$1 AND state='running' AND claimed_revision=$2 AND requested_revision=$2 AND lease_token=$3 AND lease_until>now()`,
   [job.companyId,job.revision,job.token]);
  if(result.rowCount!==1)throw leaseLost();
 }
 async function complete(job,client){
  await assertReady();
  // Commit job success in the SAME transaction as the new saved report. A
  // revoked/expired lease or newer request rolls back that whole publication.
  const result=await client.query(`UPDATE customer_reporting_jobs SET state='succeeded',succeeded_at=now(),updated_at=now(),last_error_code=NULL,${clearLease}
   WHERE company_id=$1 AND state='running' AND requested_revision=$2 AND claimed_revision=$2 AND lease_token=$3 AND lease_until>now()`,
   [job.companyId,job.revision,job.token]);
  if(result.rowCount!==1)throw leaseLost();
 }
 async function failed(job,code){
  await assertReady();
  requireValue(['build-failed','worker-stopped','source-changed'].includes(code),'Invalid reporting job error');
  const {rowCount}=await targetPool.query(`UPDATE customer_reporting_jobs SET
   state=CASE WHEN requested_revision<>$2 THEN 'queued' WHEN attempts<3 THEN 'retry' ELSE 'failed' END,
   attempts=CASE WHEN requested_revision<>$2 THEN 0 ELSE attempts END,
   available_at=CASE WHEN requested_revision<>$2 THEN now() ELSE now()+interval '1 minute'*attempts END,
   last_error_code=$4,updated_at=now(),${clearLease}
   WHERE company_id=$1 AND state='running' AND claimed_revision=$2 AND lease_token=$3`,[job.companyId,job.revision,job.token,code]);
  return rowCount===1;
 }
 async function retryFailed(companyId,expectedRevision){
  await assertReady();requireValue(typeof companyId==='string'&&Number.isInteger(expectedRevision)&&expectedRevision>0,
   'Explicit failed reporting revision required');
  const {rows:[row]}=await targetPool.query(`UPDATE customer_reporting_jobs SET requested_revision=requested_revision+1,state='queued',
   attempts=0,available_at=now(),requested_at=now(),updated_at=now(),last_error_code=NULL
   WHERE company_id=$1 AND state='failed' AND requested_revision=$2 RETURNING requested_revision AS revision`,[companyId,expectedRevision]);
  requireValue(row,'Failed reporting job changed; inspect its current revision before retrying');return row;
 }
 async function run(job,signal){
  let source,target,lastBeat=0;
  try{
   const checkpoint=async()=>{
    if(signal?.aborted)throw Object.assign(Error('Worker stopping'),{code:'worker-stopped'});
    if(Date.now()-lastBeat>=15000){await heartbeat(job);lastBeat=Date.now();}
   };
   await checkpoint();source=await sourcePool.connect();target=await targetPool.connect();
   const result=await buildCustomerReportingSections(source,target,job.companyId,createAccumulator,{
    expectedFingerprint:job.fingerprint,checkpoint,
    beforeCommit:async client=>{await checkpoint();await complete(job,client);},
   });
   return {state:'succeeded',companyId:job.companyId,records:result.records,buildMs:result.buildMs};
  }catch(error){
   const code=signal?.aborted?'worker-stopped':error.code==='report-source-changed'?'source-changed':'build-failed';
   const acknowledged=await failed(job,code);
   return {state:acknowledged?'retry-or-superseded':'lease-lost',companyId:job.companyId};
  }finally{source?.release();target?.release();}
 }
 async function tick(customers,signal){
  // Reuse the exact allowlist parser before any operation, including direct tests.
  reportingWorkerSettings({VULN_REPORTING_WORKER_ENABLED:'true',VULN_REPORTING_WORKER_CUSTOMERS:customers.join(','),
   VULN_REPORTING_SOURCE_URL:'checked-pool',VULN_REPORTING_DATABASE_URL:'checked-pool'});
  if(signal?.aborted)return {state:'stopped'};
  await assertReady();let enqueued=0,unavailable=0;
  for(const companyId of customers){
   if(signal?.aborted)return {state:'stopped'};
   try{enqueued+=await discover(companyId);}catch{unavailable++;}
  }
  if(signal?.aborted)return {state:'stopped'};
  const job=await claim(customers);
  return job?{...await run(job,signal),enqueued,unavailable}:{state:'idle',enqueued,unavailable};
 }
 return {assertReady,discover,claim,heartbeat,complete,failed,retryFailed,run,tick};
}
