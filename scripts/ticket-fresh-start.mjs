// No provider imports or requests. Inspect is read-only; apply is maintenance-only.
import pg from 'pg';
import nextEnv from '@next/env';
import {readFile} from 'node:fs/promises';
import {resolve} from 'node:path';
import {applicationDatabaseSsl} from '../lib/db/connection-target.mjs';
import {inspectTicketFreshStart,applyTicketFreshStart} from '../lib/db/ticket-fresh-start.mjs';
const usage='Use --inspect --env-file PATH, or --apply --writers-stopped --expected-plan SHA256 --env-file PATH';
async function main(){
 const args=process.argv.slice(2),inspect=args[0]==='--inspect';
 if(inspect?args.length!==3||args[1]!=='--env-file':args.length!==6||args[0]!=='--apply'||args[1]!=='--writers-stopped'||args[2]!=='--expected-plan'||args[4]!=='--env-file')throw Error(usage);
 if(process.env.DATABASE_URL||process.env.ELASTIC_VULN_DATABASE_URL)throw Error('Unset inherited database URLs before using an explicit env-file');
 const path=resolve(args.at(-1));nextEnv.processEnv([{path,contents:await readFile(path,'utf8'),env:{}}],undefined,{info(){},error(){}},true);
 const url=process.env.ELASTIC_VULN_DATABASE_URL||process.env.DATABASE_URL;if(!url)throw Error('Ticket database configuration required');
 const client=new pg.Client({connectionString:url,ssl:applicationDatabaseSsl(url),connectionTimeoutMillis:5000,statement_timeout:60000,
  options:inspect?'-c default_transaction_read_only=on':undefined,application_name:'vuln-ticket-fresh-start'});
 try{await client.connect();if(inspect){await client.query('BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY');const plan=await inspectTicketFreshStart(client);await client.query('COMMIT');
  console.log(JSON.stringify({identity:plan.identity,planHash:plan.planHash,tables:plan.tables.map(({name,count,owner})=>({name,count,owner})),configurationHash:plan.configurationHash,changes:0}));
 }else console.log(JSON.stringify(await applyTicketFreshStart(client,{writersStopped:true,expectedPlanHash:args[3]})));
 }finally{await client.end();}
}
main().catch(error=>{console.error(JSON.stringify({error:error.message,code:error.code??'ticket-fresh-start'}));process.exitCode=1;});
