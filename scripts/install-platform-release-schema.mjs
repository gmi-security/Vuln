// Operator-only command. --plan has no database connection or environment load.
import pg from 'pg';
import nextEnv from '@next/env';
import {readFile} from 'node:fs/promises';
import {resolve} from 'node:path';
import {applicationDatabaseSsl} from '../lib/db/connection-target.mjs';
import {loadPlatformReleaseMigrations,applyPlatformReleaseMigrations} from '../lib/db/platform-release-migrations.mjs';
import {loadMigrations,runMigrations} from '../lib/db/migration-runner.mjs';
async function main(){
 const args=process.argv.slice(2),migrations=await loadPlatformReleaseMigrations();
 if(args.length===1&&args[0]==='--plan'){
  console.log(JSON.stringify({applicationSchema:migrations.map(({name,checksum})=>({name,checksum})),
   coreSchema:(await loadMigrations(new URL('../db/migrations/',import.meta.url))).map(({name,checksum})=>({name,checksum})),
   changesData:false,activatesConnections:false,changesAuthority:false},null,2));return;
 }
 if(args[0]!=='--apply'||args[1]!=='--writers-stopped'||(args.length!==2&&!(args.length===4&&args[2]==='--env-file'&&args[3])))
  throw Error('Use --plan, or --apply --writers-stopped [--env-file PATH] after release review');
 if(args[3]){const path=resolve(args[3]);nextEnv.processEnv([{path,contents:await readFile(path,'utf8'),env:{}}],undefined,{info(){},error(){}},true);}
 if(!process.env.DATABASE_URL)throw Error('Application database configuration required');
 const pool=new pg.Pool({connectionString:process.env.DATABASE_URL,ssl:applicationDatabaseSsl(process.env.DATABASE_URL),
  max:1,connectionTimeoutMillis:5000,statement_timeout:60000,application_name:'vuln-platform-release-schema'});
 pool.on('error',()=>{});
 try{
  const client=await pool.connect();let applied;
  try{applied=await applyPlatformReleaseMigrations(client,migrations);}finally{client.release();}
  const core=await runMigrations(pool,await loadMigrations(new URL('../db/migrations/',import.meta.url)));
  console.log(JSON.stringify({applied,core,authority:'unchanged',approvalsCreated:0}));
 }finally{await pool.end();}
}
main().catch(error=>{console.error(JSON.stringify({error:'Release schema installation failed; keep maintenance active. No authority transition was requested.',code:error.code??'release-schema'}));process.exitCode=1;});
