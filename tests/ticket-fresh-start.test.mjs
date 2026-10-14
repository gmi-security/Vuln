import assert from 'node:assert/strict';
import test from 'node:test';
import {spawnSync} from 'node:child_process';
import {fileURLToPath} from 'node:url';
import {applyTicketFreshStart} from '../lib/db/ticket-fresh-start.mjs';

test('explicit env-file refuses inherited database URLs before opening the file or connecting', () => {
 for(const key of ['DATABASE_URL','ELASTIC_VULN_DATABASE_URL']){
  const result=spawnSync(process.execPath,['--',fileURLToPath(new URL('../scripts/ticket-fresh-start.mjs',import.meta.url)), '--inspect','--env-file','does-not-exist'],
   {encoding:'utf8',env:{...process.env,[key]:'postgresql://fixture:must-not-print@127.0.0.1:1/wrong_database'}});
  assert.equal(result.status,1);assert.match(result.stderr,/Unset inherited database URLs/);
  assert.ok(!result.stderr.includes('must-not-print'));
 }
});
test('fresh start refuses missing maintenance assertion or invalid observed plan before SQL', async () => {
 const db={query(){throw Error('SQL must not run');}};
 await assert.rejects(applyTicketFreshStart(db,{expectedPlanHash:'a'.repeat(64)}),/writers must be stopped/);
 await assert.rejects(applyTicketFreshStart(db,{writersStopped:true,expectedPlanHash:'not-a-plan'}),/observed plan/);
});
