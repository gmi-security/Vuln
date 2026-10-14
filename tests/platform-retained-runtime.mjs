// Actual persistence implementation, isolated retained database only. The Pool
// constructor is supplied a Unix socket, so no production URL/env is loaded.
import assert from 'node:assert/strict';
import {readFile,realpath} from 'node:fs/promises';
import {SourceTextModule,SyntheticModule} from 'node:vm';
import * as crypto from 'node:crypto';
import ts from 'typescript';
import pg from 'pg';
import * as authority from '../lib/db/platform-authority.mjs';
import * as storage from '../lib/db/platform-store.mjs';
import * as reader from '../lib/db/platform-reader.mjs';
import {platformBucket} from '../lib/db/platform-records.mjs';
import * as reporting from '../lib/db/customer-reporting-revisions.mjs';
const socket=await realpath(process.argv[2]||'.'),database=process.argv[3];
assert.ok(socket.startsWith('/home/codex/vuln-recovery/')&&socket.endsWith('/socket'));
assert.match(database,/^vuln2_reporting_test_[a-f0-9]+$/);
const pool=new pg.Pool({host:socket,port:55483,user:'codex',database,max:2,connectionTimeoutMillis:5000});
process.env.DATABASE_URL='postgresql://localhost/fixture';process.env.VULN_PLATFORM_STORE='sql';
try{
 const guard=(await pool.query("SELECT current_setting('data_directory') dir,current_setting('listen_addresses') listen")).rows[0];assert.ok(guard.dir.startsWith('/home/codex/vuln-recovery/')&&!guard.listen);
 const module=new SourceTextModule(ts.transpileModule(await readFile('lib/persist.ts','utf8'),{compilerOptions:{target:ts.ScriptTarget.ES2022,module:ts.ModuleKind.ESNext}}).outputText);
 await module.link(name=>{
  const values=name==='pg'?{Pool:class{constructor(){return pool;}}}:name.endsWith('platform-authority.mjs')?authority:name.endsWith('platform-store.mjs')?storage:name.endsWith('platform-reader.mjs')?reader:name.endsWith('customer-reporting-revisions.mjs')?reporting:crypto;
  return new SyntheticModule(Object.keys(values),function(){for(const k of Object.keys(values))this.setExport(k,values[k]);});
 });await module.evaluate();const persist=module.namespace,times={};
 let started=Date.now();const data=await persist.loadSnapshot();times.loadMs=Date.now()-started;
 const counts=Object.fromEntries(['companies','folders','scans','findings','assets'].map(k=>[k,data[k].length]));
 const initial=await authority.readPlatformAuthority(pool);started=Date.now();await persist.saveSnapshot(data,{changes:{}});times.unchangedSaveMs=Date.now()-started;
 assert.deepEqual(await authority.readPlatformAuthority(pool),initial);
 // Small analyst edit, then revert it, using the same real write path. The
 // later independent full reverse checksum compares the restored source.
 const finding=data.findings[0][1],had=Object.hasOwn(finding,'analystMigrationFixture'),old=finding.analystMigrationFixture;
 finding.analystMigrationFixture='private-verification-only';started=Date.now();await persist.saveSnapshot(data,{changes:{findings:[finding.id]}});times.singleEditMs=Date.now()-started;
 assert.equal((await pool.query('SELECT payload->>\'analystMigrationFixture\' value FROM app_findings WHERE id=$1',[finding.id])).rows[0].value,'private-verification-only');
 const commit=(await pool.query('SELECT counts FROM app_store_commits ORDER BY epoch DESC,revision DESC LIMIT 1')).rows[0].counts;
 assert.deepEqual(commit,{inserted:0,updated:1,deleted:0,metadata:0,changedKeys:[`findings:${String(platformBucket(finding.id,64)).padStart(2,'0')}`]});
 if(had)finding.analystMigrationFixture=old;else delete finding.analystMigrationFixture;
 started=Date.now();await persist.saveSnapshot(data,{changes:{findings:[finding.id]}});times.revertMs=Date.now()-started;
 assert.ok(times.singleEditMs<5000&&times.revertMs<5000,'An ordinary edit must not rescan the full dataset');
 console.log(JSON.stringify({phase:'retained-runtime',counts,...times,peakRssMiB:Math.round(process.resourceUsage().maxRSS/1024),singleEditRows:commit}));
}finally{await pool.end();}
