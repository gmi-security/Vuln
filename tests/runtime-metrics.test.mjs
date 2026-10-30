import test from 'node:test';
import assert from 'node:assert/strict';
import {startRuntimeMetrics} from '../lib/runtime-metrics.mjs';
test('runtime samples contain only process measurements and stop cleanly',t=>{
  t.mock.timers.enable({apis:['setInterval']});const samples=[];
  const stop=startRuntimeMetrics({role:'worker',emit:sample=>samples.push(sample)});
  t.mock.timers.tick(10000);assert.equal(samples.length,1);
  assert.equal(samples[0].role,'worker');assert.ok(samples[0].heapUsedBytes>0);
  assert.ok(samples[0].rssBytes>0);assert.ok(Number.isFinite(samples[0].eventLoopMaxMs));
  stop();t.mock.timers.tick(10000);assert.equal(samples.length,1);
});
