// Actual operator workflow against a disposable database on the private cluster.
// Never uses production configuration, starts the application or contacts vendors.
import assert from 'node:assert/strict';
import { readFile, writeFile, realpath, mkdtemp, stat } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { randomUUID } from 'node:crypto';
import pg from 'pg';
import { runRegistry } from '../scripts/customer-connector-registry.mjs';
import { loadConnectorPreview } from '../scripts/connector-preview-loader.mjs';
import { readApplicationConnectorMetadata, readDashboardConnectorMetadata } from '../lib/db/connector-metadata.mjs';

const socket=await realpath(process.argv[2] || '.');
assert.ok(socket.startsWith('/home/codex/vuln-recovery/') && socket.endsWith('/socket'),'Private cluster required');
const options={host:socket,port:55483,user:'codex',connectionTimeoutMillis:5000,statement_timeout:15000};
const admin=new pg.Client({...options,database:'postgres'}),name=`vuln2_registry_cli_${randomUUID().replaceAll('-','')}`;
let db,created=false,checks=0;
const ok=message=>{checks++;console.log('PASS '+message);};
const directory=await mkdtemp(join(tmpdir(),'vuln-registry-command-'));
try {
  await admin.connect();
  const state=(await admin.query("SELECT current_setting('data_directory') data,current_setting('listen_addresses') listen")).rows[0];
  assert.ok(state.data.startsWith('/home/codex/vuln-recovery/') && !state.listen);
  await admin.query(`CREATE DATABASE ${name}`);created=true;
  db=new pg.Client({...options,database:name});await db.connect();
  const url=new URL(`postgresql://codex@localhost/${name}`);url.searchParams.set('host',socket);url.searchParams.set('port','55483');
  const env={DATABASE_URL:url.href,SPIDERFOOT_URL:'https://never-contacted.invalid'};
  const run=args=>runRegistry(args,env);
  const build=await loadConnectorPreview();
  const collect=async()=>build({...await readApplicationConnectorMetadata(db),...await readDashboardConnectorMetadata(db)},env);
  const emptyFingerprint=(await collect()).fingerprint;
  await assert.rejects(()=>run(['import','--fingerprint',emptyFingerprint]),e=>e.code==='42P01');
  assert.equal((await db.query("SELECT count(*)::int n FROM pg_tables WHERE schemaname='public'")).rows[0].n,0);
  await db.query(await readFile('docs/sql/customer-connector-drafts.sql','utf8'));
  await db.query('CREATE TABLE vuln_store(key text PRIMARY KEY,data jsonb); CREATE TABLE defender_connections(company_id text PRIMARY KEY,tenant_id text,revision int,secret text)');
  await db.query("INSERT INTO vuln_store VALUES('meta',$1)",[JSON.stringify({companies:[['CO-A',{id:'CO-A',name:'Alpha'}],['CO-B',{id:'CO-B',name:'Beta'}]]})]);
  await db.query("INSERT INTO defender_connections VALUES('CO-A','tenant-a',1,'DO_NOT_COPY'),('CO-B','tenant-b',1,'DO_NOT_COPY')");
  const preview=await collect();
  const first=await run(['import','--fingerprint',preview.fingerprint]);assert.equal(first.created,3);assert.equal(first.enabledBindings,0);
  assert.equal((await run(['import','--fingerprint',preview.fingerprint])).unchanged,true);
  ok('actual command requires explicit migration and imports current metadata idempotently');

  const output=join(directory,'customer-a.json');
  const exported=await run(['export','--company','CO-A','--output',output]);assert.equal(exported.drafts,2);
  const text=await readFile(output,'utf8');assert.doesNotMatch(text,/DO_NOT_COPY|tenant-b|CO-B/);
  assert.equal((await stat(output)).mode & 0o777,0o600);
  await assert.rejects(()=>run(['export','--company','CO-A','--output',output]),e=>e.code==='EEXIST');
  await assert.rejects(()=>run(['export','--company','CO-MISSING','--output',join(directory,'missing.json')]),/non-demo/);
  const input=JSON.parse(text).drafts.find(d=>d.provider==='defender').reviewRequest;
  input.decision='reviewed';input.note='Synthetic tenant verification.';input.proposal.authority='findings-primary';
  const inputPath=join(directory,'review.json');await writeFile(inputPath,JSON.stringify(input),{mode:0o600});
  const sourceBefore=(await db.query('SELECT jsonb_agg(to_jsonb(d) ORDER BY company_id) data FROM defender_connections d')).rows[0].data;
  const auditCount=async()=>Number((await db.query('SELECT count(*) n FROM customer_connector_audit')).rows[0].n);
  ok('private export contains selected customer plus unassigned sources, never another customer or credentials');

  await db.query("UPDATE defender_connections SET revision=2 WHERE company_id='CO-A'");
  const before=await auditCount();
  await assert.rejects(()=>run(['review','--input',inputPath]),/Source metadata changed/);assert.equal(await auditCount(),before);
  await run(['import','--fingerprint',(await collect()).fingerprint]);
  const refreshedPath=join(directory,'refreshed.json');await run(['export','--company','CO-A','--output',refreshedPath]);
  const refreshed=JSON.parse(await readFile(refreshedPath,'utf8')).drafts.find(d=>d.provider==='defender').reviewRequest;
  Object.assign(refreshed,{decision:'reviewed',note:'Synthetic current tenant verified.'});refreshed.proposal.authority='findings-primary';
  await writeFile(inputPath,JSON.stringify(refreshed));
  const reviewed=await run(['review','--input',inputPath]);assert.equal(reviewed.reviewState,'reviewed');assert.equal(reviewed.enabledBindings,0);
  const saved=(await db.query('SELECT reviewed_by,enabled FROM customer_connector_drafts WHERE id=$1',[input.id])).rows[0];
  assert.match(saved.reviewed_by,/^operator:/);assert.equal(saved.enabled,false);
  await assert.rejects(()=>run(['review','--input',inputPath]),/Draft changed/);
  ok('review rechecks source changes before saving; operator identity is derived and stale retries are rejected');

  const after=(await db.query('SELECT jsonb_agg(to_jsonb(d) ORDER BY company_id) data FROM defender_connections d')).rows[0].data;
  sourceBefore[0].revision=2;assert.deepEqual(after,sourceBefore);
  assert.equal((await db.query('SELECT count(*)::int n FROM customer_connector_drafts WHERE enabled')).rows[0].n,0);
  assert.doesNotMatch(JSON.stringify((await db.query('SELECT * FROM customer_connector_audit')).rows),/DO_NOT_COPY/);
  ok('commands leave source records and credentials intact; all bindings remain inactive');
  console.log(JSON.stringify({checks,passed:true,productionWrites:false,externalCalls:false}));
} finally {
  await db?.end();if(created)await admin.query(`DROP DATABASE ${name}`);await admin.end();
}
