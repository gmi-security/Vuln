import assert from 'node:assert/strict';
import test from 'node:test';
import { loadSpotlightSourceReader } from '../scripts/source-read-model-loader.mjs';
const create=await loadSpotlightSourceReader();
const request={companyId:'CO-A',now:new Date('2026-10-10'),staleAfterMs:86400000};
function fixture(overrides={}) {
  const data={installed:true, saved:{run_id:'run-a',owned_run:'run-a',status:'completed',finished_at:'2026-10-09',checkpoint_version:3,
    expected_count:'0',hydrated_count:'0',latest_status:'completed',latest_started_at:'2026-10-08',latest_finished_at:'2026-10-09'},
    integrity:{records:'0',misplaced:'0'},...overrides};
  const calls=[];let released=false;
  const read=create({connect:async()=>({release(){released=true;},query:async(sql,values)=>{
    calls.push({sql,values});
    if(data.fail&&sql.includes(data.fail)) throw Object.assign(new Error('statement timeout'),{code:'57014'});
    if(sql.includes('to_regclass')) return{rows:[{ready:data.installed}]};
    if(sql.includes('LEFT JOIN LATERAL'))return{rows:[data.saved]};
    if(sql.includes('AS misplaced'))return{rows:[data.integrity]};
    if(sql.includes('WITH open_rows'))return{rows:[{invalid:'0',instances:'0',devices:'0',unknown_suppression:'0',suppressed:'0',non_cve:'0',unique_cves:'0',device_cves:'0',
      instance_severity:{},cve_severity:{},page:[]}]};
    return{rows:[]};
  }})});
  return{data,calls,read:extra=>read({...request,...extra}),released:()=>released};
}
test('unknown inventory/revisions stay null and completed empty source is a real zero',async()=>{
  const f=fixture(),r=await f.read();
  assert.equal(r.state,'available');assert.equal(r.summary.sourceInstances,0);
  assert.equal(r.summary.inventoryDevices,null);assert.equal(r.generation.revisionMatches,null);
  assert.equal(r.definition.instanceUnit,'spotlight-finding');assert.equal(r.definition.severityBasis,'source-cvss');
  assert.equal(r.latestAttempt.status,'succeeded');assert.equal(r.generation.countVerification,'import-count-reconciled');
  assert.equal(f.calls[0].sql,'BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY');
  assert.ok(f.calls.some(c=>c.sql==="SET LOCAL statement_timeout='15s'"));
  assert.deepEqual(f.calls.find(c=>c.sql.includes('WITH open_rows')).values,['run-a','CO-A',50,0]);
  assert.equal(f.calls.at(-1).sql,'COMMIT');assert.ok(f.released());
});
test('invalid scope/page fails before connecting',async()=>{
  const f=fixture();for(const bad of [{companyId:''},{companyId:'%'},{companyId:'CO-A OR true'},{limit:101},{offset:-1}])await assert.rejects(()=>f.read(bad));
  assert.equal(f.calls.length,0);
});
test('missing and incomplete generations cannot return partial or zero totals',async()=>{
  const f=fixture({installed:false});assert.equal((await f.read()).state,'not-installed');
  const missing=fixture();missing.data.saved.run_id=null;assert.equal((await missing.read()).state,'no-completed-import');
  for(const change of [{owned_run:null},{status:'running'},{finished_at:null},{expected_count:null},{expected_count:'1'}]){
    const bad=fixture();Object.assign(bad.data.saved,change);assert.equal((await bad.read()).state,'inconsistent');
  }
  const misplaced=fixture({integrity:{records:'1',misplaced:'1'}});assert.equal((await misplaced.read()).summary,null);
});
test('failure propagates with rollback/release; no successful cache or stale generation is fabricated',async()=>{
  const f=fixture({fail:'WITH open_rows'});await assert.rejects(f.read,error=>error.code==='57014');
  assert.equal(f.calls.at(-1).sql,'ROLLBACK');assert.ok(f.released());
});
test('failed latest and unsupported legacy count proof remain explicit',async()=>{
  const f=fixture();Object.assign(f.data.saved,{checkpoint_version:1,latest_status:'failed'});
  const r=await f.read({now:new Date('2026-10-11')});assert.equal(r.state,'available');
  assert.equal(r.generation.countVerification,'completion-marker-only');assert.equal(r.latestAttempt.status,'failed');
  assert.equal(r.generation.freshness,'stale');
});
