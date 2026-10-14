import assert from 'node:assert/strict';
import test from 'node:test';
import {execFile} from 'node:child_process';
import {promisify} from 'node:util';
import {reportingWorkerSettings} from '../lib/db/customer-reporting-worker.mjs';
test('reporting worker is disabled by default without requiring database configuration',()=>{
 assert.deepEqual(reportingWorkerSettings({}),{enabled:false});
 assert.deepEqual(reportingWorkerSettings({VULN_REPORTING_WORKER_ENABLED:'false',VULN_REPORTING_WORKER_CUSTOMERS:'*'}),{enabled:false});
});
test('enabled worker requires explicit bounded customer and database configuration',()=>{
 const base={VULN_REPORTING_WORKER_ENABLED:'true',VULN_REPORTING_SOURCE_URL:'private-source',VULN_REPORTING_DATABASE_URL:'private-target'};
 for(const value of ['',',','A,A','*','A/OTHER',Array.from({length:51},(_,i)=>`CO-${i}`).join(',')])
  assert.throws(()=>reportingWorkerSettings({...base,VULN_REPORTING_WORKER_CUSTOMERS:value}),/customers required/);
 assert.throws(()=>reportingWorkerSettings({...base,VULN_REPORTING_SOURCE_URL:'',VULN_REPORTING_WORKER_CUSTOMERS:'A'}),/storage required/);
 assert.deepEqual(reportingWorkerSettings({...base,VULN_REPORTING_WORKER_CUSTOMERS:' A , CO-2 '}).customers,['A','CO-2']);
});
test('actual disabled CLI exits without connecting or exposing supplied storage strings',async()=>{
 const result=await promisify(execFile)(process.execPath,['scripts/customer-reporting-worker.mjs'],{env:{...process.env,
  VULN_REPORTING_WORKER_ENABLED:'false',VULN_REPORTING_SOURCE_URL:'SECRET-MUST-NOT-LEAK',VULN_REPORTING_DATABASE_URL:'SECRET-MUST-NOT-LEAK'},timeout:10000,windowsHide:true});
 assert.match(result.stdout,/"event":"disabled"/);assert.doesNotMatch(result.stdout+result.stderr,/SECRET-MUST-NOT-LEAK/);
});
