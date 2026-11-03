// node --test tests/external-scan-claims.test.mjs
import assert from 'node:assert/strict';
import test from 'node:test';
import { readFile } from 'node:fs/promises';
import { reserveExternalScanClaim, inspectExternalScanSlot } from '../lib/db/external-scan-claims.mjs';

const claim = (c='a') => ({dedupKey:c.repeat(64),companyId:'CO-A',target:'host.example',nessusScanId:55,occurrenceAt:'2026-11-05T03:00:00Z'});
function database() {
  const state={ slot:null, claims:new Set(), locked:false, statements:[] };
  return {state,pool:{
    async connect() {
      let txn=null,holdsLock=false;
      return {
        async query(sql,args=[]) {
          state.statements.push(sql);
          if(sql==='BEGIN'){txn={slot:state.slot,claims:new Set(state.claims)};return {rows:[]};}
          if(sql.startsWith('SET LOCAL'))return {rows:[]};
          if(sql.includes('FOR UPDATE NOWAIT')) {
            if(state.locked){const e=new Error('busy');e.code='55P03';throw e;}
            state.locked=true;holdsLock=true;return {rows:[{claim_key:txn.slot}]};
          }
          if(sql.includes('INSERT INTO public.external_scan_dispatch_claims')){
            if(txn.claims.has(args[0]))return {rows:[]};
            txn.claims.add(args[0]);return {rows:[{claim_key:args[0]}]};
          }
          if(sql.includes('UPDATE public.external_scan_dispatch_slot')){
            if(txn.slot!==null)return {rows:[]};
            txn.slot=args[0];return {rows:[{claim_key:args[0]}]};
          }
          if(sql==='COMMIT'){
            state.slot=txn.slot;state.claims=txn.claims;txn=null;
            if(holdsLock)state.locked=false;holdsLock=false;return {rows:[]};
          }
          if(sql==='ROLLBACK'){
            txn=null;if(holdsLock)state.locked=false;holdsLock=false;return {rows:[]};
          }
          throw Error('Unexpected query: '+sql);
        },
        release(){assert.equal(txn,null,'unfinished transaction');},
      };
    },
    async query(sql){
      assert.match(sql,/LEFT JOIN public.external_scan_dispatch_claims/);
      return {rows:[{claim_key:state.slot}]};
    }
  }};
}
test('one reservation persists and blocks a different occurrence',async()=>{
  const db=database();
  assert.deepEqual(await reserveExternalScanClaim(db.pool,claim()),{state:'reserved',claimKey:'a'.repeat(64)});
  assert.equal((await inspectExternalScanSlot(db.pool)).claim_key,'a'.repeat(64));
  assert.deepEqual(await reserveExternalScanClaim(db.pool,claim('b')),{state:'busy'});
  assert.equal(db.state.claims.size,1);
});
test('historical deduplication survives an independently reconciled slot',async()=>{
  const db=database();await reserveExternalScanClaim(db.pool,claim());
  db.state.slot=null; // simulated separately reviewed operator resolution
  assert.deepEqual(await reserveExternalScanClaim(db.pool,claim()),{state:'duplicate'});
});
test('concurrent session holding the lock fails closed',async()=>{
  const db=database();db.state.locked=true;
  assert.deepEqual(await reserveExternalScanClaim(db.pool,claim()),{state:'busy'});
  assert.equal(db.state.claims.size,0);
});
test('invalid keys, hostnames, and CIDRs reject before database work',async()=>{
  const db=database();
  for(const patch of [{dedupKey:'bad'},{target:'10.0.0.0/24'},{target:'*.example'},
    {target:'BADHOST.EXAMPLE'},{target:'bad::notip'},{companyId:'CO A'},
    {nessusScanId:0},{occurrenceAt:'today'}]){
    await assert.rejects(()=>reserveExternalScanClaim(db.pool,{...claim(),...patch}));
  }
  assert.equal(db.state.statements.length,0);
});
test('unexpected PostgreSQL error rolls back and leaves no claim',async()=>{
  const db=database(),normal=db.pool;
  const failing={connect:async()=>{const c=await normal.connect();const query=c.query;
    c.query=async(sql,args)=>sql.includes('UPDATE public.external_scan_dispatch_slot')?{rows:[]}:query(sql,args);
    return c;}};
  await assert.rejects(()=>reserveExternalScanClaim(failing,claim()),/reservation failed/);
  assert.equal(db.state.slot,null);assert.equal(db.state.claims.size,0);
});
test('schema is a singleton with durable deduplication and no automatic release',async()=>{
  const schema=await readFile(new URL('../docs/sql/external-scan-dispatch-claims.sql',import.meta.url),'utf8');
  assert.match(schema,/PRIMARY KEY CHECK \(slot_id = 1\)/);
  assert.match(schema,/UNIQUE \(company_id, target, nessus_scan_id, nessus_occurrence_at\)/);
  assert.doesNotMatch(schema,/DROP TABLE|TRUNCATE/i);
  const moduleSource=await readFile(new URL('../lib/db/external-scan-claims.mjs',import.meta.url),'utf8');
  assert.doesNotMatch(moduleSource,/\b(startScan|vulnersBridgeStartScan|setInterval|DELETE FROM|expires_at)\b/i);
});
