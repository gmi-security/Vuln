// Read-only historical restore, new disposable derived target, no app process.
import assert from 'node:assert/strict';
import {originalSections} from './reporting-restored-reference.mjs';
import {readFile,realpath} from 'node:fs/promises';
import {randomUUID} from 'node:crypto';
import pg from 'pg';
import {loadReportingSections} from '../scripts/reporting-sections-loader.mjs';
import {buildCustomerReportingSections,readCustomerReportingSections} from '../lib/db/customer-reporting-sections.mjs';
globalThis.fetch=()=>{throw Error('Network calls prohibited');};
const socket=await realpath(process.argv[2]||'.');assert.ok(socket.startsWith('/home/codex/vuln-recovery/')&&socket.endsWith('/socket'));
const config={host:socket,port:55483,user:'codex',connectionTimeoutMillis:5000,statement_timeout:15000};
const name=`vuln2_reporting_test_${randomUUID().replaceAll('-','')}`,admin=new pg.Client({...config,database:'postgres'});
let source,target,created=false;
const {create,reference}=await loadReportingSections();

try{
 await admin.connect();const g=(await admin.query("SELECT current_setting('data_directory') dir,current_setting('listen_addresses') listen")).rows[0];
 assert.ok(g.dir.startsWith('/home/codex/vuln-recovery/')&&!g.listen);await admin.query(`CREATE DATABASE ${name}`);created=true;
 source=new pg.Client({...config,database:'recovery_application'});target=new pg.Client({...config,database:name});
 await source.connect();await target.connect();await target.query(await readFile('docs/sql/customer-reporting-sections.sql','utf8'));
 for(const [cohort,id] of [['Defender customer','CO-230784'],['Mixed-scanner customer','CO-147284']]){
  console.log('Starting '+cohort);
  const build=await buildCustomerReportingSections(source,target,id,create);
  let saved;const times=[];for(let i=0;i<5;i++){const start=performance.now();saved=await readCustomerReportingSections(source,target,id);times.push(Math.round((performance.now()-start)*10)/10);}
  assert.equal(saved.state,'available');const expected=await originalSections(source,reference,id,saved.capturedAt);
  // JSON transport omits optional undefined keys. Null values remain material.
  assert.deepEqual(saved.model,JSON.parse(JSON.stringify(expected.model)));assert.equal(saved.records,expected.records);
  console.log(JSON.stringify({cohort,records:build.records,open:saved.model.metrics.vulnerabilities.open,
   findingsSources:expected.contributors,scans:saved.model.scanTotal,assets:saved.model.assets.inventoryCount,
   history:saved.model.history.length,bytes:build.bytes,buildMs:build.buildMs,readMs:times}));
 }
 console.log(JSON.stringify({peakRssMiB:Math.round(process.resourceUsage().maxRSS/1024)}));
 console.log('PASS complete restored reporting sections parity for both customers');
}finally{await source?.end();await target?.end();if(created)await admin.query(`DROP DATABASE ${name} WITH (FORCE)`);await admin.end();}
