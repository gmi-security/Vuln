import test from 'node:test';
import assert from 'node:assert/strict';
import {platformRecord, preparePlatformRecordBatch, upsertPlatformRecords} from '../lib/db/platform-records.mjs';
import {observePublicationQueries} from '../lib/db/publication-metrics.mjs';
const generation='11111111-1111-4111-8111-111111111111';
const row=(id,padding='')=>platformRecord('findings',[id,{id,evidence:padding}],1);

test('prepared publication batch encodes at most 500 rows and is detached before SQL starts', async()=>{
  const rows=Array.from({length:501},(_,i)=>row(`F-${i}`));
  const batch=preparePlatformRecordBatch('findings',rows,{generation});
  assert.equal(batch.rowCount,500);assert.equal(batch.encodedBytes,Buffer.byteLength(batch.params[0]));
  rows[0].payload.evidence='later mutation';
  assert.equal(JSON.parse(batch.params[0])[0].payload.evidence,'');
  assert.ok(Object.isFrozen(batch));assert.ok(Object.isFrozen(batch.params));
  assert.equal(preparePlatformRecordBatch('findings',rows,{generation,offset:500}).rowCount,1);
  // The transaction receives only strings; it cannot serialize caller payloads.
  rows[0].payload.toJSON=()=>{throw Error('serialization inside transaction');};
  const calls=[];await ({query:async(...args)=>calls.push(args)}).query(batch.sql,batch.params);
  assert.equal(calls.length,1);
});

test('publication byte target bounds variable-size batches, while one valid large record advances',()=>{
  const rows=Array.from({length:6},(_,i)=>row(`L-${i}`,'x'.repeat(1024*1024)));
  const batch=preparePlatformRecordBatch('findings',rows,{generation});
  assert.equal(batch.rowCount,3);assert.ok(batch.encodedBytes<=4*1024*1024);
  const large=row('large','x'.repeat(16*1024*1024-100));
  const singleton=preparePlatformRecordBatch('findings',[large,rows[0]],{generation});
  assert.equal(singleton.rowCount,1);assert.ok(singleton.encodedBytes>4*1024*1024);
  assert.throws(()=>row('too-large','x'.repeat(16*1024*1024)),/16 MiB/);
});

test('encoding preserves column validation and ordinary upsert behavior',async()=>{
  assert.throws(()=>preparePlatformRecordBatch('findings',[{...row('a'),injected:'x'}],{generation}),/column/);
  assert.throws(()=>preparePlatformRecordBatch('findings',[row('a')],{generation:'invalid'}),/generation/);
  assert.throws(()=>preparePlatformRecordBatch('findings',[row('a')],{offset:-1}),/offset/);
  const calls=[];await upsertPlatformRecords({query:async(...args)=>calls.push(args)},'findings',[row('a')]);
  assert.match(calls[0][0],/^INSERT INTO app_findings/);assert.equal(JSON.parse(calls[0][1][0])[0].id,'a');
});

test('transaction diagnostics distinguish query time from idle gaps without exposing SQL or payloads',async()=>{
  let clock=0;const logs=[];
  const db=observePublicationQueries({processID:42,query:async()=>{clock+=20;return {rows:[]};}},
    {now:()=>clock,emit:value=>logs.push(value)});
  db.phase('writing',{offset:500,bytes:1234});
  await db.query('BEGIN');clock+=2300;
  await db.query('INSERT confidential SQL',['secret payload']);
  await db.query('COMMIT');db.close();
  assert.ok(logs.some(x=>x.maxIdleGapMs===2300&&x.backendPid===42));
  assert.ok(logs.some(x=>x.maxQueryMs===20));
  assert.doesNotMatch(JSON.stringify(logs),/secret|confidential/);
});
