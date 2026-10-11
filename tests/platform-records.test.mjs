import test from 'node:test';
import assert from 'node:assert/strict';
import {platformRecord,platformRecordOrders,platformJson,platformHash} from '../lib/db/platform-records.mjs';
import {samePlatformAuthority} from '../lib/db/platform-authority.mjs';
test('record projection preserves source extensions and fractional risk without changing payload',()=>{
 const payload={id:'F-1',companyId:'CO-1',connector:'defender',realRisk:44.5,lastSeen:'not a date',future:{z:1,a:['x',null]}};
 const row=platformRecord('findings',['F-1',payload],1024);
 assert.deepEqual(row.payload,payload);assert.equal(row.real_risk,44.5);assert.equal(row.last_seen,null);
 payload.future.z=2;assert.equal(row.payload.future.z,1);
 assert.equal(row.record_hash,platformHash(platformJson(row.payload)));
 assert.throws(()=>platformRecord('findings',['wrong',payload],1024),/identity/);
 assert.throws(()=>platformRecord('unknown',['F-1',payload],1024),/collection/);
});
test('order diff keeps deletions and middle insertions from rewriting unchanged records',()=>{
 const prior=new Map([['a',{order:1024}],['b',{order:2048}],['c',{order:3072}]]);
 assert.deepEqual(platformRecordOrders([['a'],['c']],prior),[1024,3072]);
 assert.deepEqual(platformRecordOrders([['a'],['new'],['b'],['c']],prior),[1024,1536,2048,3072]);
 assert.deepEqual(platformRecordOrders([['c'],['a']],prior),[1024,2048]);
 assert.throws(()=>platformRecordOrders([['a'],['a']],prior),/Duplicate/);
});
test('authority includes mode, epoch, revision and enforcement',()=>{
 const token={mode:'sql',epoch:'2',revision:'3',enforced:true};
 assert.equal(samePlatformAuthority(token,{...token}),true);
 for(const change of [{mode:'legacy'},{epoch:'3'},{revision:'4'},{enforced:false}])assert.equal(samePlatformAuthority(token,{...token,...change}),false);
 assert.equal(samePlatformAuthority(null,null),true);assert.equal(samePlatformAuthority(null,token),false);
});
