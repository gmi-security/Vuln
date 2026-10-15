import assert from 'node:assert/strict';
import test from 'node:test';
import * as revisions from '../lib/db/customer-reporting-revisions.mjs';
import * as store from '../lib/db/platform-store.mjs';

const baseline=()=>Object.fromEntries(revisions.reportingKeys.map(k=>[k,k==='meta'?{}:k==='companies:00'?
 [['A',{id:'A',name:'A'}],['B',{id:'B',name:'B'}],['C',{id:'C',name:'C'}]]:[]]));
async function digest(data){const d=revisions.createReportingInputDigests();for(const [k,v]of Object.entries(data))await d.bucket(k,JSON.stringify(v));return d.finish();}

for(const action of ['update','move','delete','source-only'])test(`targeted reporting ${action} equals full digest and never reads an unrelated customer`,async()=>{
 const before=baseline();before['findings:00']=[['f',{id:'f',companyId:'A',status:'Open'}],['g',{id:'g',companyId:'C',status:'Open'}]];
 const current=await digest(before),after=structuredClone(before);
 if(action==='update')after['findings:00'][0][1].status='Resolved';
 if(action==='move')after['findings:00'][0][1].companyId='B';
 if(action==='delete')after['findings:00'].shift();
 if(action==='source-only')after['findings:00'][0][1].vendorRaw='changed';
 const readOwners=[],published=[];
 const client={async query(sql,p=[]){
  if(sql.startsWith('SELECT company_id,format_version'))return {rows:current.map(r=>({company_id:r.companyId,format_version:3,bucket_map:r.buckets,content_hash:r.hash}))};
  if(sql==='SELECT id FROM app_companies ORDER BY id')return {rows:['A','B','C'].map(id=>({id}))};
  if(sql.startsWith('SELECT id,store_order,')){
   const rows=after['findings:00'].map(([id,record],i)=>({id,record,store_order:(i+1)*1024})).filter(r=>r.store_order>p[1]&&(!sql.includes('company_id=ANY')||p[3].includes(r.record.companyId)));
   readOwners.push(...rows.map(r=>r.record.companyId));return {rows};
  }
  if(sql.includes('pg_try_advisory'))return {rows:[{acquired:true}]};
  if(sql.startsWith('INSERT INTO public.customer_reporting_inputs'))published.push({companyId:p[0],hash:p[3],buckets:JSON.parse(p[4])});
  if(sql.includes('to_regclass'))return {rows:[{relation:'app_store_authority'}]};
  if(sql.includes('FROM public.app_store_authority'))return {rows:[{mode:'sql',enforced:true,epoch:'2',revision:'6'}]};
  if(sql.includes('current_database()'))return {rows:[{db:'test',relation:'123'}]};
  return {rows:[]};
 }};
 await revisions.publishSqlReportingChanges(client,['findings:00'],{'findings:00':action==='move'?['A','B']:['A']});
 assert.deepEqual(published,await digest(after));
 assert.ok(!readOwners.includes('C'),'unaffected customer must not be read even when it shares the changed bucket');
});

test('reporting scopes collect both previous and frozen new owners, including deleted rows',async()=>{
 assert.equal(typeof revisions.collectSqlReportingTargets,'function');
 const plan={writes:new Map([['findings',[{id:'moved',company_id:'B',store_bucket:0}]]]),deletes:new Map([['findings',['deleted']]]),changedKeys:['findings:00','findings:01']};
 const client={async query(sql,params){
  assert.match(sql,/SELECT id,company_id,store_bucket/);assert.deepEqual(new Set(params[0]),new Set(['moved','deleted']));
  return {rows:[{id:'moved',company_id:'A',store_bucket:0},{id:'deleted',company_id:'C',store_bucket:1}]};
 }};
 const targets=await revisions.collectSqlReportingTargets(client,plan);
 assert.deepEqual(targets,{'findings:00':['A','B'],'findings:01':['C']});
 plan.changedKeys.push('companies:00');
 assert.equal(await revisions.collectSqlReportingTargets({query(){throw Error('should use full fallback')}},plan),undefined);
});
