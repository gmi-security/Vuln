// Read-only observation of the private restore, not a live capacity benchmark.
import assert from 'node:assert/strict';
import {realpath} from 'node:fs/promises';
import pg from 'pg';
import {readDefenderRefreshSource} from '../lib/db/defender-refresh-source.mjs';
import {privateShadowDatabase} from '../lib/db/defender-platform-shadow.mjs';
const socket=await realpath(process.argv[2]||'.');assert.ok(socket.startsWith('/home/codex/vuln-recovery/')&&socket.endsWith('/socket'));
const client=new pg.Client({host:socket,port:55483,user:'codex',database:'recovery_application',connectionTimeoutMillis:5000,statement_timeout:15000,query_timeout:20000});
try{
  await client.connect();await privateShadowDatabase(client,'source');await client.query('SET default_transaction_read_only=on');
  const companyId='CO-230784',start=performance.now(),source=await readDefenderRefreshSource(client,companyId);
  const {rows:[expected]}=await client.query('SELECT count(DISTINCT (device_id,cve))::int pairs FROM defender_records WHERE run_id=$1',[source.snapshot.runId]);
  assert.equal(source.snapshot.findings.length,expected.pairs);
  console.log(JSON.stringify({scope:'private restored completed Defender import',pairs:source.snapshot.findings.length,devices:source.snapshot.devices.length,elapsedMs:Math.round(performance.now()-start),peakRssKiB:process.resourceUsage().maxRSS,sourceWrites:0,candidateWrites:0}));
}finally{await client.end();}
