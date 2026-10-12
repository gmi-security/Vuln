import test from 'node:test';
import assert from 'node:assert/strict';
import {createRehearsalGate,captureLegacyCustomer} from './defender-handoff-rehearsal.mjs';
test('rehearsal gate refuses active writers and expired holders cannot release a later hold',async()=>{
  const gate=createRehearsalGate();let release;
  const writing=gate.run(()=>new Promise(resolve=>{release=resolve;}));
  assert.throws(()=>gate.hold(),/finish/);release();await writing;
  const first=gate.hold();assert.equal(first.valid(),true);await assert.rejects(()=>gate.run(()=>{}),/paused/);
  first.release();assert.equal(first.valid(),false);const second=gate.hold();first.release();
  assert.equal(first.valid(),false);assert.equal(second.valid(),true);await assert.rejects(()=>gate.run(()=>{}),/paused/);
  second.release();await assert.rejects(()=>gate.run(()=>{throw Error('writer failed');}),/writer failed/);
  const recovered=gate.hold();assert.equal(recovered.valid(),true);recovered.release();
});
test('captured customer data is detached, scoped, complete for the candidate inputs and sorted',()=>{
  const id='CO-TEST',other='CO-OTHER',f={id:'f1',companyId:id,status:'Open',assignee:null};
  const s={companies:new Map([[id,{id,name:'Fixture'}],[other,{id:other,name:'Other'}]]),findings:new Map([['f1',f],['f2',{id:'f2',companyId:other}]]),
    assets:new Map(),compensatingControls:new Map(),meta:{defenderGenerations:{[id]:'run'}}};
  const saved=captureLegacyCustomer(s,id);f.status='Resolved';
  assert.equal(saved.findings.length,1);assert.equal(saved.findings[0].status,'Open');assert.equal(saved.runId,'run');
  assert.throws(()=>captureLegacyCustomer(s,'CO-MISSING'),/missing/);
  s.findings.set('duplicate',{...f});assert.throws(()=>captureLegacyCustomer(s,id),/identity/);
});
