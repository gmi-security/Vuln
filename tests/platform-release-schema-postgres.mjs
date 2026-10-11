// Release installer rehearsal on a new database in the private socket cluster.
import assert from 'node:assert/strict';
import {realpath} from 'node:fs/promises';
import {randomUUID} from 'node:crypto';
import pg from 'pg';
import {loadPlatformReleaseMigrations,applyPlatformReleaseMigrations} from '../lib/db/platform-release-migrations.mjs';
import {loadMigrations,runMigrations} from '../lib/db/migration-runner.mjs';
const socket=await realpath(process.argv[2]||'.');assert.ok(socket.startsWith('/home/codex/vuln-recovery/')&&socket.endsWith('/socket'));
const config={host:socket,port:55483,user:'codex',connectionTimeoutMillis:5000},name='vuln2_release_test_'+randomUUID().replaceAll('-','');
const admin=new pg.Client({...config,database:'postgres'});let db,pool,created=false;
try{
 await admin.connect();const g=(await admin.query("SELECT current_setting('data_directory') dir,current_setting('listen_addresses') listen")).rows[0];assert.ok(g.dir.startsWith('/home/codex/vuln-recovery/')&&!g.listen);
 await admin.query(`CREATE DATABASE ${name}`);created=true;db=new pg.Client({...config,database:name});await db.connect();pool=new pg.Pool({...config,database:name,max:1});
 await db.query("CREATE TABLE vuln_store(key text PRIMARY KEY,data jsonb,updated_at timestamptz DEFAULT now());INSERT INTO vuln_store VALUES('fixture','{\"keep\":true}',now())");
 await db.query('CREATE TABLE spotlight_import_runs(id uuid PRIMARY KEY)');
 const migrations=await loadPlatformReleaseMigrations();
 await db.query('CREATE TABLE customer_connector_drafts(existing text)');
 await assert.rejects(applyPlatformReleaseMigrations(db,migrations),/already exists/);
 assert.equal((await db.query("SELECT to_regclass('platform_release_migrations') name")).rows[0].name,null);
 await db.query('DROP TABLE customer_connector_drafts');
 const failed=migrations.map(m=>({...m}));failed.at(-1).sql+='\n SELECT 1/0;';
 await assert.rejects(applyPlatformReleaseMigrations(db,failed),/division by zero/);
 assert.equal((await db.query("SELECT to_regclass('customer_connector_drafts') name")).rows[0].name,null);
 assert.equal((await db.query('SELECT data FROM vuln_store')).rows[0].data.keep,true);
 console.log('PASS conflicting existing schema and late install failure leave the original database intact');
 assert.equal((await applyPlatformReleaseMigrations(db,migrations)).length,19);
 assert.deepEqual(await applyPlatformReleaseMigrations(db,migrations),[]);
 const changed=migrations.map(m=>({...m}));changed[0].checksum='0'.repeat(64);
 await assert.rejects(applyPlatformReleaseMigrations(db,changed),/differs/);
 console.log('PASS ordered release schema installs once and rejects changed applied checksums');
 const core=await loadMigrations(new URL('../db/migrations/',import.meta.url));
 assert.equal((await runMigrations(pool,core)).length,2);assert.deepEqual(await runMigrations(pool,core),[]);
 const authority=(await db.query('SELECT mode,enforced FROM app_store_authority')).rows[0];assert.deepEqual(authority,{mode:'legacy',enforced:false});
 assert.equal((await db.query('SELECT count(*)::int n FROM customer_connector_bindings')).rows[0].n,0);
 assert.equal((await db.query('SELECT data FROM vuln_store')).rows[0].data.keep,true);
 console.log('PASS core schema installs without changing authority, source data or approving any connector');
}finally{await pool?.end();await db?.end();if(created)await admin.query(`DROP DATABASE ${name} WITH(FORCE)`);await admin.end();}
