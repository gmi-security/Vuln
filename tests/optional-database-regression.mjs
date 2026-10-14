// Runs the otherwise-skipped integration suites in disposable databases on the
// private recovery cluster. Real providers are replaced by each suite's mocks.
import assert from 'node:assert/strict';
import {realpath} from 'node:fs/promises';
import {randomUUID} from 'node:crypto';
import {spawn} from 'node:child_process';
import pg from 'pg';
const socket=await realpath(process.argv[2]||'.');assert.ok(socket.startsWith('/home/codex/vuln-recovery/')&&socket.endsWith('/socket'));
const config={host:socket,port:55483,user:'codex',database:'postgres',connectionTimeoutMillis:5000};
const admin=new pg.Client(config),created=[];
const defender='vuln2_optional_'+randomUUID().replaceAll('-','');
const url=name=>{const u=new URL('postgresql://codex@localhost/'+name);u.searchParams.set('host',socket);u.searchParams.set('port','55483');return u.href;};
try{
 await admin.connect();const g=(await admin.query("SELECT current_setting('data_directory') dir,current_setting('listen_addresses') listen")).rows[0];assert.ok(g.dir.startsWith('/home/codex/vuln-recovery/')&&!g.listen);
 for(const name of [defender,'elastic_test','patch_ticket_test']){
  assert.equal((await admin.query('SELECT 1 FROM pg_database WHERE datname=$1',[name])).rowCount,0,'Refusing an existing test database');
  await admin.query(`CREATE DATABASE ${name}`);created.push(name);
 }
 const child=spawn(process.execPath,['--experimental-vm-modules','--test','--test-concurrency=1',
  'tests/connectwise-patch-tickets.test.mjs','tests/defender-risk.test.mjs','tests/defender.test.mjs','tests/elastic-dashboard.test.mjs','tests/persist-snapshot.test.mjs'],{
  env:{PATH:process.env.PATH,DEFENDER_TEST_DATABASE_URL:url(defender),ELASTIC_TEST_DATABASE_URL:url('elastic_test'),PATCH_TICKET_TEST_DATABASE_URL:url('patch_ticket_test')},stdio:'inherit'});
 const code=await new Promise((resolve,reject)=>{child.once('error',reject);child.once('close',resolve);});assert.equal(code,0,'Optional database regression failed');
}finally{for(const name of created.reverse())await admin.query(`DROP DATABASE ${name} WITH(FORCE)`);await admin.end();}
