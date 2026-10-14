// Runs existing dashboard/ticket suites only in new databases on the private recovery cluster.
import assert from 'node:assert/strict';import {realpath} from 'node:fs/promises';import pg from 'pg';import {spawn} from 'node:child_process';
const socket=await realpath(process.argv[2]||'.');assert.ok(socket.startsWith('/home/codex/vuln-recovery/')&&socket.endsWith('/socket'));
const config={host:socket,port:55483,user:'codex',database:'postgres',connectionTimeoutMillis:5000};const db=new pg.Client(config);let created=[];
try{
 await db.connect();const s=(await db.query("SELECT current_setting('data_directory') data,current_setting('listen_addresses') listen")).rows[0];assert.ok(s.data.startsWith('/home/codex/vuln-recovery/')&&!s.listen);
 for(const [name,key,test] of [['elastic_test','ELASTIC_TEST_DATABASE_URL','elastic-dashboard'],['patch_ticket_test','PATCH_TICKET_TEST_DATABASE_URL','connectwise-patch-tickets']]){
  assert.equal((await db.query('SELECT 1 FROM pg_database WHERE datname=$1',[name])).rowCount,0,'Never reuse an existing test DB');
  await db.query(`CREATE DATABASE ${name}`);created.push(name);
  const url=new URL(`postgresql://codex@localhost/${name}`);url.searchParams.set('host',socket);url.searchParams.set('port','55483');
  const env={PATH:process.env.PATH,HOME:process.env.HOME,NODE_NO_WARNINGS:'1',[key]:url.href};
  const exit=await new Promise((resolve,reject)=>{const child=spawn(process.execPath,['--experimental-vm-modules','--test',`tests/${test}.test.mjs`],{env,stdio:'inherit'});child.on('error',reject);child.on('exit',resolve);});assert.equal(exit,0);
 }
}finally{for(const name of created)await db.query(`DROP DATABASE ${name} WITH (FORCE)`);await db.end();}
