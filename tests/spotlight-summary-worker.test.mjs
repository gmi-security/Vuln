import assert from 'node:assert/strict';
import test from 'node:test';
import {createRequire} from 'node:module';
import {spawnSync} from 'node:child_process';
const require=createRequire(import.meta.url);
const {summaryWorkerSettings,createSpotlightSummaryWorker}=require('../.worker-build/spotlight-summary/lib/spotlight-summary-worker.js');
test('disabled worker needs no credentials and creates no connections',()=>{
  assert.deepEqual(summaryWorkerSettings({}),{enabled:false});
  assert.deepEqual(summaryWorkerSettings({VULN_SPOTLIGHT_SUMMARY_WORKER_ENABLED:'TRUE',DATABASE_URL:'invalid'}),{enabled:false});
  const child=spawnSync(process.execPath,['scripts/spotlight-summary-worker.mjs'],{encoding:'utf8',env:{...process.env,VULN_SPOTLIGHT_SUMMARY_WORKER_ENABLED:'false',DATABASE_URL:'invalid'}});
  assert.equal(child.status,0);assert.match(child.stdout,/disabled/);assert.doesNotMatch(child.stdout,/started/);
});
test('enabled worker requires explicit valid customers and database configuration',()=>{
  const base={VULN_SPOTLIGHT_SUMMARY_WORKER_ENABLED:'true',DATABASE_URL:'postgres://not-used'};
  for(const ids of [undefined,'','*','CO-A,','CO-A,../B'])assert.throws(()=>summaryWorkerSettings({...base,VULN_SPOTLIGHT_SUMMARY_CUSTOMERS:ids}));
  assert.throws(()=>summaryWorkerSettings({...base,DATABASE_URL:undefined,VULN_SPOTLIGHT_SUMMARY_CUSTOMERS:'CO-A'}));
  assert.deepEqual(summaryWorkerSettings({...base,VULN_SPOTLIGHT_SUMMARY_CUSTOMERS:' CO-B,CO-A,CO-B '}),{enabled:true,customers:['CO-A','CO-B']});
});
test('module construction and an aborted tick perform no database work',async()=>{
  const worker=createSpotlightSummaryWorker({query:()=>assert.fail('query'),connect:()=>assert.fail('connect')});
  const controller=new AbortController();controller.abort();
  assert.deepEqual(await worker.tick(['CO-A'],controller.signal),{state:'stopped'});
});
