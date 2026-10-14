// Run only during the reviewed maintenance window with application and worker
// writers stopped. No dotenv loader: the operator supplies the existing env.
import pg from 'pg';
import {applicationDatabaseSsl} from '../lib/db/connection-target.mjs';
import {readPlatformAuthority} from '../lib/db/platform-authority.mjs';
import {transitionPlatformStore} from '../lib/db/platform-store.mjs';
import {createReportingInputDigests,publishReportingInputRevisions} from '../lib/db/customer-reporting-revisions.mjs';
const args=process.argv.slice(2),status=args.length===1&&args[0]==='--status';
if(!status&&!(args.length===6&&['--to-sql','--to-legacy'].includes(args[0])&&args[1]==='--writers-stopped'&&args[2]==='--expect-epoch'&&args[4]==='--expect-revision'&&/^\d+$/.test(args[3])&&/^\d+$/.test(args[5])))
 throw Error('Use --status, or --to-sql/--to-legacy --writers-stopped --expect-epoch N --expect-revision N. Review the recovery runbook first.');
const connectionString=process.env.DATABASE_URL;if(!connectionString)throw Error('DATABASE_URL required');
const client=new pg.Client({connectionString,ssl:applicationDatabaseSsl(connectionString),application_name:'vuln2-platform-maintenance',connectionTimeoutMillis:15000});
let open=false;
try{
 await client.connect();await client.query(status?'BEGIN READ ONLY':'BEGIN');open=true;
 await client.query("SET LOCAL statement_timeout='60s';SET LOCAL lock_timeout='5s';SET LOCAL idle_in_transaction_session_timeout='90s';SET LOCAL search_path=public");
 const authority=await readPlatformAuthority(client);
 if(!authority)throw Error('Explicit platform authority migrations must be installed first');
 if(status){console.log(JSON.stringify({authority}));await client.query('COMMIT');open=false;}
 else{
  if(authority.epoch!==args[3]||authority.revision!==args[5])throw Error('Authority changed since review; no transition performed');
  const reporting=createReportingInputDigests(),started=Date.now();
  const result=await transitionPlatformStore(client,args[0]==='--to-sql'?'sql':'legacy',authority,{actor:'maintenance-cli',reporting,
   checkpoint:()=>{if(Date.now()-started>20*60000)throw Error('Maintenance transition exceeded 20 minutes');}});
  await publishReportingInputRevisions(client,reporting.finish());
  await client.query('COMMIT');open=false;
  console.log(JSON.stringify({result,elapsedMs:Date.now()-started}));
 }
}finally{if(open)await client.query('ROLLBACK').catch(()=>{});await client.end();}
