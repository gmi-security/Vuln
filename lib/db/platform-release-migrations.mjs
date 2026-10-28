// Explicit release manifest. Shadow experiments are deliberately not installed.
import {readFile} from 'node:fs/promises';
import {createHash} from 'node:crypto';
export const platformReleaseSql = Object.freeze([
 'customer-connector-drafts','customer-connector-bindings','customer-source-selections',
 'customer-inventory-routes','customer-inventory-routes-v2','customer-spotlight-routes',
 'customer-scanner-routes','customer-scanner-osint-routes','customer-scanner-active-routes',
 'customer-query-routes','customer-query-routes-v2','customer-appsec-routes',
 'spotlight-source-summaries','spotlight-summary-jobs',
 'customer-reporting-inputs','customer-reporting-buckets','customer-reporting-sections',
 'customer-reporting-jobs','customer-reporting-executive','patch-progress',
]);
const hash = text => createHash('sha256').update(text).digest('hex');
export async function loadPlatformReleaseMigrations(){
 return Promise.all(platformReleaseSql.map(async name=>{
  // Normalize checkout line endings so a Windows review matches Linux deploy.
  const sql=(await readFile(new URL(`../../docs/sql/${name}.sql`,import.meta.url),'utf8')).replaceAll('\r\n','\n');
  const begins=sql.match(/^BEGIN;\s*$/gm)??[],commits=sql.match(/^COMMIT;\s*$/gm)??[];
  if(begins.length!==commits.length||begins.length>1||/\bCONCURRENTLY\b/.test(sql))throw Error(`Unsupported transaction in ${name}`);
  return {name,checksum:hash(sql),sql:sql.replace(/^BEGIN;\s*$/gm,'').replace(/^COMMIT;\s*$/gm,'')};
 }));
}
export async function applyPlatformReleaseMigrations(client,migrations){
 // One owned transaction: a failed migration leaves no partial schema/ledger.
 let open=false;
 try{
  await client.query("BEGIN; SET LOCAL statement_timeout='60s'; SET LOCAL lock_timeout='5s'; SET LOCAL search_path=public");open=true;
  await client.query('SELECT pg_advisory_xact_lock(20261011,1)');
  await client.query(`CREATE TABLE IF NOT EXISTS platform_release_migrations(
   name text PRIMARY KEY,checksum text NOT NULL CHECK(checksum ~ '^[a-f0-9]{64}$'),applied_at timestamptz NOT NULL DEFAULT clock_timestamp())`);
  const prior=new Map((await client.query('SELECT name,checksum FROM platform_release_migrations')).rows.map(r=>[r.name,r.checksum]));
  if(migrations.length!==platformReleaseSql.length||migrations.some((m,i)=>m.name!==platformReleaseSql[i]))throw Error('Release manifest order mismatch');
  for(const [name,checksum]of prior){if(!migrations.some(m=>m.name===name&&m.checksum===checksum))throw Error(`Applied release schema differs: ${name}`);}
  const applied=[];
  for(const m of migrations){if(prior.has(m.name))continue;await client.query(m.sql);await client.query('INSERT INTO platform_release_migrations(name,checksum) VALUES($1,$2)',[m.name,m.checksum]);applied.push(m.name);}
  await client.query('COMMIT');open=false;return applied;
 }finally{if(open)await client.query('ROLLBACK').catch(()=>{});}
}
