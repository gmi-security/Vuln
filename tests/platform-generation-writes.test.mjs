import test from 'node:test';
import assert from 'node:assert/strict';
import {platformRecord,upsertPlatformRecords} from '../lib/db/platform-records.mjs';

const generation='11111111-1111-4111-8111-111111111111';
test('finding writes address the selected physical generation without changing the public read view',async()=>{
 const calls=[],client={query:async(sql,params)=>{calls.push({sql,params});return {rows:[]};}};
 const record=platformRecord('findings',['F-1',{id:'F-1',companyId:'CO-1',status:'Open'}],1024);
 await upsertPlatformRecords(client,'findings',[record],{generation});
 assert.match(calls[0].sql,/INSERT INTO app_finding_versions/);
 assert.match(calls[0].sql,/ON CONFLICT\s*\(generation,id\)/);
 assert.equal(calls[0].params[1],generation);
 assert.deepEqual(JSON.parse(calls[0].params[0]),[record]);
});
test('non-finding writes and pre-migration findings retain their existing target',async()=>{
 const calls=[],client={query:async(sql)=>{calls.push(sql);return {rows:[]};}};
 await upsertPlatformRecords(client,'assets',[platformRecord('assets',['A-1',{id:'A-1',companyId:'CO-1'}],1024)],{generation});
 await upsertPlatformRecords(client,'findings',[platformRecord('findings',['F-1',{id:'F-1',companyId:'CO-1'}],1024)]);
 assert.match(calls[0],/INSERT INTO app_assets/);assert.match(calls[1],/INSERT INTO app_findings/);
});
test('an invalid generation fails before issuing SQL',async()=>{
 let calls=0;const client={query:async()=>{calls++;return {rows:[]};}};
 await assert.rejects(upsertPlatformRecords(client,'findings',[platformRecord('findings',['F-1',{id:'F-1'}],1)],{generation:'invalid'}),/generation/i);
 assert.equal(calls,0);
});
