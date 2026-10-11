import assert from 'node:assert/strict';
import test from 'node:test';
import {createReportingInputDigests,reportingKeys,reportingDigest} from '../lib/db/customer-reporting-revisions.mjs';

const baseline=()=>Object.fromEntries(reportingKeys.map(key=>[key,key==='meta'?{}:key==='companies:00'?
 [['A',{id:'A',name:'Customer A'}],['B',{id:'B',name:'Customer B'}]]:[]]));
async function collect(data,cache){const d=createReportingInputDigests(cache);for(const key of reportingKeys)await d.bucket(key,JSON.stringify(data[key]));return {rows:d.finish(),commit:()=>d.committed()};}
test('customer bucket maps omit unrelated buckets and capture first/last records and owner changes',async()=>{
 const data=baseline();data['findings:00']=[['f',{id:'f',companyId:'A',status:'Open'}]];
 const initial=(await collect(data)).rows;assert.deepEqual(initial[0].buckets.map(p=>p[0]),['companies:00','findings:00']);
 assert.deepEqual(initial[1].buckets.map(p=>p[0]),['companies:00']);
 for(const row of initial)assert.equal(reportingDigest(row.buckets),row.hash);
 data['findings:00'][0][1].companyId='B';const moved=(await collect(data)).rows;
 assert.deepEqual(moved[0].buckets.map(p=>p[0]),['companies:00']);assert.deepEqual(moved[1].buckets.map(p=>p[0]),['companies:00','findings:00']);
 data['findings:00']=[];assert.deepEqual((await collect(data)).rows.map(r=>r.buckets.map(p=>p[0])),[['companies:00'],['companies:00']]);
});
test('only committed bucket cache is reused; source-only fields and another customer do not alter the report digest',async()=>{
 const cache=new Map(),data=baseline();data['findings:01']=[['f',{id:'f',companyId:'A',status:'Open'}]];
 const first=await collect(data,cache);assert.equal(cache.size,0);first.commit();const committed=cache.get('findings:01');
 data['findings:01'][0][1].status='Resolved';const uncommitted=await collect(data,cache);assert.notEqual(uncommitted.rows[0].hash,first.rows[0].hash);
 assert.equal(cache.get('findings:01'),committed);data['findings:01'][0][1].status='Open';
 data['findings:01'][0][1].rawSourceField='irrelevant';data.meta.counter=50;data['findings:02']=[['g',{id:'g',companyId:'B',status:'Open'}]];
 assert.deepEqual((await collect(data,cache)).rows[0],first.rows[0]);
});
test('incomplete, duplicate and orphaned input cannot produce a customer bucket map',async()=>{
 const d=createReportingInputDigests();await d.bucket('meta','{}');assert.throws(()=>d.finish(),/Incomplete/);
 await assert.rejects(()=>d.bucket('meta','{}'),/Duplicate/);
 const data=baseline();data['findings:00']=[['orphan',{id:'orphan',companyId:'MISSING'}]];
 await assert.rejects(()=>collect(data),/no saved customer/);
});
