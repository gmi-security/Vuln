import test from 'node:test';
import assert from 'node:assert/strict';
import {createPersistenceHealth,persistenceNotice} from '../lib/persistence-health.mjs';

test('a timed-out worker probe supersedes cached progress, then recovery shows the current phase',()=>{
  const health={persistence:{dbReachable:true},persistenceState:'retrying',worker:{available:true}};
  assert.equal(persistenceNotice(health),'retrying');
  health.worker.available=false;assert.equal(persistenceNotice(health),'unavailable');
  health.worker.available=true;health.persistenceState='healthy';assert.equal(persistenceNotice(health),'healthy');
});

test('pending publication and backoff stay unsaved until a durable commit',()=>{
  let now=1000;const health=createPersistenceHealth({now:()=>now});
  assert.equal(health.snapshot().persistenceState,'healthy');
  health.dirty();health.publishing('writing');
  assert.equal(health.snapshot().pendingSince,new Date(now).toISOString());
  health.retry({code:'25P03',delayMs:5000});
  assert.equal(health.snapshot().persistenceState,'retrying');
  assert.equal(health.snapshot().lastCommittedRevision,null);
  assert.equal(health.snapshot().firstError.code,'25P03');
  now+=5000;health.publishing('writing');health.committed('18000',false);
  assert.equal(health.snapshot().persistenceState,'healthy');
  assert.equal(health.snapshot().lastCommittedRevision,'18000');
  assert.equal(health.snapshot().pendingSince,null);
  assert.equal(health.snapshot().firstError,null);
});

test('later mutations remain pending after the frozen capture commits',()=>{
  const health=createPersistenceHealth();health.dirty();health.publishing('writing');health.dirty();health.committed('12',true);
  assert.equal(health.snapshot().persistenceState,'publishing');assert.ok(health.snapshot().pendingSince);
});

test('only stalled pending work alerts; checkpoints reset the durable progress clock',()=>{
  let now=1000;const alerts=[],health=createPersistenceHealth({now:()=>now,emit:event=>alerts.push(event)});
  now+=600000;health.snapshot();assert.equal(alerts.length,0);
  health.dirty();now+=290000;health.progress();now+=290000;health.snapshot();assert.equal(alerts.length,0);
  now+=10001;assert.equal(health.snapshot().stalled,true);assert.equal(alerts.length,1);
  health.snapshot();assert.equal(alerts.length,1);
  health.committed('1',false);assert.equal(health.snapshot().stalled,false);
});

test('blocked errors are sanitized and do not claim recovery from a successful ping',()=>{
  const health=createPersistenceHealth();health.dirty();health.publishing('commit');
  health.failed(Object.assign(new Error('password and tenant data'),{code:'08006'}),true);
  const status=health.snapshot();assert.equal(status.persistenceState,'blocked');assert.equal(status.firstError.phase,'commit');
  assert.doesNotMatch(JSON.stringify(status),/password|tenant/);
});
