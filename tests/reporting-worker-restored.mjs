import assert from 'node:assert/strict';
import {readFile,realpath} from 'node:fs/promises';
import {randomUUID} from 'node:crypto';
import {execFile} from 'node:child_process';
import {promisify} from 'node:util';
import pg from 'pg';
import {readCustomerReportingSections} from '../lib/db/customer-reporting-sections.mjs';
const socket=await realpath(process.argv[2]||'.');assert.ok(socket.startsWith('/home/codex/vuln-recovery/')&&socket.endsWith('/socket'));
const config={host:socket,port:55483,user:'codex',connectionTimeoutMillis:5000,statement_timeout:15000};
const name=`vuln2_reporting_test_${randomUUID().replaceAll('-','')}`,admin=new pg.Client({...config,database:'postgres'});
const url=database=>{const u=new URL(`postgresql://codex@localhost/${database}`);u.searchParams.set('host',socket);u.searchParams.set('port','55483');return u.href;};
let source,target,created=false;
try{
 await admin.connect();const g=(await admin.query("SELECT current_setting('data_directory') dir,current_setting('listen_addresses') listen")).rows[0];
 assert.ok(g.dir.startsWith('/home/codex/vuln-recovery/')&&!g.listen);await admin.query(`CREATE DATABASE ${name}`);created=true;
 source=new pg.Client({...config,database:'recovery_application'});target=new pg.Client({...config,database:name});await source.connect();await target.connect();
 for(const file of ['customer-reporting-sections','customer-reporting-jobs'])await target.query(await readFile(`docs/sql/${file}.sql`,'utf8'));
 await target.query(`CREATE TABLE heartbeat_evidence(company_id text PRIMARY KEY,n int);
  CREATE FUNCTION record_heartbeat_fixture() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN
   INSERT INTO heartbeat_evidence VALUES(NEW.company_id,1) ON CONFLICT(company_id) DO UPDATE SET n=heartbeat_evidence.n+1;RETURN NEW;END;$$;
  CREATE TRIGGER record_heartbeat_fixture AFTER UPDATE ON customer_reporting_jobs FOR EACH ROW
   WHEN(OLD.state='running' AND NEW.state='running' AND NEW.lease_until>OLD.lease_until) EXECUTE FUNCTION record_heartbeat_fixture()`);
 const scope=['CO-230784','CO-147284'];
 for(let i=0;i<2;i++){
  const result=await promisify(execFile)(process.execPath,['--max-old-space-size=512','scripts/customer-reporting-worker.mjs','--once'],{
   env:{PATH:process.env.PATH,VULN_REPORTING_WORKER_ENABLED:'true',VULN_REPORTING_WORKER_CUSTOMERS:scope.join(','),
    VULN_REPORTING_SOURCE_URL:url('recovery_application'),VULN_REPORTING_DATABASE_URL:url(name)},timeout:300000,maxBuffer:1024*1024});
  const events=result.stdout.trim().split('\n').map(line=>JSON.parse(line)),tick=events.find(e=>e.event==='tick'),stopped=events.find(e=>e.event==='stopped');
  assert.equal(tick.state,'succeeded');const data=await readCustomerReportingSections(source,target,tick.companyId);
  const index=scope.indexOf(tick.companyId);assert.ok(index>=0);assert.equal(data.state,'available');
  assert.equal(data.records,[288878,80302][index]);assert.equal(data.model.metrics.vulnerabilities.open,[215891,80000][index]);
  const {rows:[heartbeats]}=await target.query('SELECT n FROM heartbeat_evidence WHERE company_id=$1',[tick.companyId]);
  assert.ok(heartbeats.n>=(tick.buildMs>16000?2:1));
  console.log(JSON.stringify({cohort:['Defender customer','Mixed-scanner customer'][index],records:data.records,
   buildMs:tick.buildMs,heartbeats:heartbeats.n,peakWorkerRssMiB:stopped.peakRssMiB}));
 }
 assert.equal((await target.query("SELECT count(*)::int n FROM customer_reporting_jobs WHERE state='succeeded'")).rows[0].n,2);
 console.log('PASS actual bounded-memory worker builds both restored customers with renewed leases');
}finally{await source?.end();await target?.end();if(created)await admin.query(`DROP DATABASE ${name} WITH (FORCE)`);await admin.end();}
