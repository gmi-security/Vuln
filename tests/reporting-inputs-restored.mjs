// Read-only cost/compatibility check of the per-customer input digests on the
// complete retained application snapshot. Never installs tables in the restore.
import assert from 'node:assert/strict';
import {realpath} from 'node:fs/promises';
import {performance,monitorEventLoopDelay} from 'node:perf_hooks';
import pg from 'pg';
import {createHash} from 'node:crypto';
import {createReportingInputDigests,reportingKeys} from '../lib/db/customer-reporting-revisions.mjs';
const socket=await realpath(process.argv[2]||'.');assert.ok(socket.startsWith('/home/codex/vuln-recovery/')&&socket.endsWith('/socket'));
const db=new pg.Client({host:socket,port:55483,user:'codex',database:'recovery_application',connectionTimeoutMillis:5000,statement_timeout:15000});
const cache=new Map(),delay=monitorEventLoopDelay({resolution:10});let first;
try{
 await db.connect();const g=(await db.query("SELECT current_setting('data_directory') dir,current_setting('listen_addresses') listen")).rows[0];
 assert.ok(g.dir.startsWith('/home/codex/vuln-recovery/')&&!g.listen);
 await db.query('BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY');
 for(const phase of ['first-publication','unchanged-buckets']){
  const digest=createReportingInputDigests(cache);let hashingMs=0,checksumMs=0,bytes=0,largest=0;const start=performance.now();delay.reset();delay.enable();
  for(const key of reportingKeys){
   const {rows:[row]}=await db.query('SELECT data::text AS json FROM vuln_store WHERE key=$1',[key]);assert.ok(row);
   const size=Buffer.byteLength(row.json);bytes+=size;largest=Math.max(largest,size);
   const checksumStart=performance.now(),checksum=createHash('sha1').update(row.json).digest('hex');checksumMs+=performance.now()-checksumStart;
   const hashStart=performance.now();await digest.bucket(key,row.json,checksum);hashingMs+=performance.now()-hashStart;
  }
  const inputs=digest.finish();digest.committed();delay.disable();
  if(first)assert.deepEqual(inputs,first);else first=inputs;
  assert.ok(inputs.some(row=>row.companyId==='CO-230784'));assert.ok(inputs.some(row=>row.companyId==='CO-147284'));
  console.log(JSON.stringify({phase,customers:inputs.length,bytes,largestBucketBytes:largest,hashingMs:Math.round(hashingMs),checksumMs:Math.round(checksumMs),totalMs:Math.round(performance.now()-start),
   maxEventLoopDelayMs:Math.round(delay.max/1e6),peakRssMiB:Math.ceil(process.resourceUsage().maxRSS/1024)}));
 }
 await db.query('COMMIT');
}finally{delay.disable();await db.end();}
