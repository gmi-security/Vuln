import test from 'node:test';
import assert from 'node:assert/strict';

const path = '../lib/committed-cache.mjs';
const { createCommittedCache } = await import(path).catch(() => ({}));
const defer = () => { let resolve, reject; const promise = new Promise((a,b)=>{resolve=a;reject=b;}); return {promise,resolve,reject}; };

test('committed cache serves previous complete generation during a single in-flight refresh', async () => {
  const pending=defer(); let calls=0;
  const cache=createCommittedCache({load:async()=> ++calls===1 ? {revision:1} : pending.promise, build:async snapshot=>({revision:snapshot.revision})});
  await cache.refresh(); const old=cache.current(); const job=cache.refresh();
  assert.equal(cache.current(),old); assert.equal(cache.refresh(),job); assert.equal(calls,2);
  pending.resolve({revision:2}); await job; assert.equal(cache.current().view.revision,2); assert.equal(old.view.revision,1);
});
test('failed load or failed preparation keeps prior committed view and a retry can recover', async()=>{
  let phase=0; const cache=createCommittedCache({load:async()=>{if(phase===1)throw Error('offline');return {revision:phase};}, build:async s=>{if(phase===2)throw Error('bad generation');return s;}});
  await cache.refresh(); const old=cache.current();
  for(phase of [1,2]) {await assert.rejects(cache.refresh());assert.equal(cache.current(),old);assert.ok(cache.status().refreshError);}
  phase=3;await cache.refresh();assert.equal(cache.current().view.revision,3);assert.equal(cache.status().refreshError,null);
});
test('initial cache has no seeded fallback and unchanged SQL snapshot skips rebuilding',async()=>{
  const snapshot={revision:1};let builds=0;
  const cache=createCommittedCache({load:async()=>snapshot,build:async s=>{builds++;return s;}});
  assert.equal(cache.current(),null);await cache.refresh();const first=cache.current();await cache.refresh();assert.equal(cache.current(),first);assert.equal(builds,1);
});
